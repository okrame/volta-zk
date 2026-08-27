#!/usr/bin/env python3
"""Executable C7 R0.7 analytic/readiness screen; every result is credit:false."""

from __future__ import annotations

import argparse
import json
import math
from fractions import Fraction


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
            "absolute_setup_wall_cap_seconds": None,
            "absolute_refresh_wall_cap_seconds": None,
            "absolute_time_caps_must_be_preregistered_before_measurement": True,
            "all_absolute_caps_selected": False,
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
    extension_field_size = GOLDILOCKS_MODULUS**2
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
            "formula": "T/|Fp2|",
            **probability(interactive),
            "explicit_challenge_bytes_per_draw": AUTHENTICATED_FP2_SYMBOL_BYTES,
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
            "formula": "Q_FS*T/|Fp2|",
            "Q_FS": FIAT_SHAMIR_AMPLIFIED_QUERY_SCREEN,
            **probability(fs_direct),
            "selected": False,
            "credit": False,
        },
        "fiat_shamir_two_challenge_amplified": {
            "formula": "Q_FS*T^2/|Fp2|^2",
            "Q_FS": FIAT_SHAMIR_AMPLIFIED_QUERY_SCREEN,
            **probability(fs_pair),
            "explicit_challenge_bytes": 0,
            "extra_response_handle_path_settlement_bytes": None,
            "extra_field_and_hash_work": None,
            "extra_packed_source_passes": None,
            "requirements": [
                "one paired RO invocation on one frozen prefix and grinding nonce",
                "paired output expands with domain separation into two independent challenges",
                "canonical rejection sampling into Fp2",
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
        "status": "R07_OWNER_1_30_QUERY_AXIS_CANDIDATE_BACKEND_UNADMITTED",
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
            "Q_PRF_masks_and_salts": None,
            "historical_Q_leaf_is_not_an_active_substitute": True,
            "all_three_derived_across_K_model": False,
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
                "sum_domain Adv_PCG + sum_attempt(eps_terminal_codec+eps_timing) + "
                "sum_all_rotation_attempts eps_RotateSameW_priv + "
                "eps_branch_derived_closure + eps_state_codec_carry"
            ),
            "eps_RV_formula": (
                "eps_OnlineMDVViewRefine + zeta_RS_adapt + Adv_PRF + "
                "Adv_BLAKE3_RootPathHide"
            ),
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
            "terminal baseline Fp2 with one shared Delta; PCS algebraic "
            "amplifier/field is unselected, and Lean does not prove its bridge"
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
    small_total = int(small["certificate"]["total"]["bytes"])
    large_total = int(large["certificate"]["total"]["bytes"])
    certificate_growth = large_total / small_total
    return {
        "schema": "volta-c7-stateful-alfc-r07-screen-v11",
        "design": "C7 stateful authenticated linear-functional commitment",
        "screening_only": True,
        "credit": False,
        "authorization": {
            "r07_carrier_and_pareto_checkpoint_authorized": True,
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
        },
        "privacy_policy": {
            "active": 2,
            "last_tested": 3,
            "active_status": (
                "policy2_owner1_30_query_axis_candidate_backend_unadmitted"
            ),
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
            "policy_2_root_wide_query_horizon_schema_registered": True,
            "policy_2_root_wide_query_horizon_instantiated": False,
            "policy_2_exact_numeric_caps_derived": False,
            "numeric_caps_deferred_until_complete_pareto": True,
            "selected_theorem_carrier": (
                "RS_t_query_ZK_plus_strict_unique_decoding_WHIR_or_Ligerito"
            ),
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
            "setup_exploratory_absolute_time_and_refresh_caps_selected": False,
            "logical_leaf_geometry_selected": True,
            "anti_x4d_setup_gate_pass": False,
            "active_public_leaf_function_implemented": False,
            "historical_policy3_poseidon2_leaf_implemented": True,
            "concrete_leaf_commitment_selected": False,
            "public_blake3_leaf_tree_function_selected": True,
            "leaf_commitment_adaptive_hiding_proved": False,
            "policy3_private_leaf_checker_required": False,
            "only_budgeted_masked_query_payloads_codec_proved": False,
            "terminal_evaluation_remains_authenticated": True,
            "malicious_dv_connection_privacy_theorem_complete": False,
            "policy2_model_lifetime_privacy_78bit_proved": False,
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
            "algebraic_security_amplifier_selected": False,
            "algebraic_security_closure_path_selected": True,
            "fp3_direct_three_limb_fallback_selected": True,
            "first_compiler_envelope_selected": (
                "rate1-k0-4-owner1_30-Fp2-query-axis-flat-g141-one-root"
            ),
            "strict_ud_algebraic_110bit_per_response_derived": False,
            "strict_ud_model_lifetime_soundness_78bit_derived": False,
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
            "owner_1_30_complete_four_axis_query_gate_pass": False,
            "joint_sampler_visible_Fp_sharing_selected": False,
            "different_code_switch_selected": False,
            "one_pass_batch_open_blocks_proved": False,
            "cpu_batch_open_blocks_reference_pass": False,
            "simt_bit_exact_equivalence_pass": False,
            "query_schedule_compiled": False,
            "query_counter_schema": {
                "aggregate": list(POLICY2_AGGREGATE_CENSUS_CLASSES),
                "per_plane": list(POLICY2_QUERY_CLASSES),
                "attempt_counter": "A_attempt",
                "logical_pcs_samples_q_open_by_plane_root_round": None,
                "zk_alphabet_query_atoms_by_plane_root_round": None,
            },
            "exact_query_counts_by_root_and_round": {
                str(GPT2["name"]): None,
                str(GEMMA_ENVELOPE["name"]): None,
            },
            "adversarial_leaf_oracle_query_bound": LEAF_ORACLE_QUERY_SCREEN,
            "adversarial_leaf_oracle_query_bound_kind": (
                "owner_selected_analytic_screen_not_a_concrete_theorem_cap"
            ),
            "adversarial_fiat_shamir_query_bound": (
                SELECTED_FIAT_SHAMIR_QUERY_BOUND
            ),
            "serialized_query_and_challenge_bytes_by_model": {
                str(GPT2["name"]): None,
                str(GEMMA_ENVELOPE["name"]): None,
            },
            "query_bytes_reconciled_into_certificate_total": False,
            "compiled_tier_a_certificate_gate_pass": False,
        },
        "batch_open_blocks_admission": {
            "state": (
                "R07_OWNER_1_30_QUERY_AXIS_CANDIDATE_CPU_BACKEND_UNADMITTED"
            ),
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
            "state": "C7_R07_OWNER_1_30_QUERY_AXIS_CANDIDATE_NOT_READY",
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
                "absolute_setup_wall_caps_seconds": {
                    str(GPT2["name"]): None,
                    str(GEMMA_ENVELOPE["name"]): None,
                },
                "absolute_refresh_wall_caps_seconds": {
                    str(GPT2["name"]): None,
                    str(GEMMA_ENVELOPE["name"]): None,
                },
                "time_caps_must_be_preregistered_before_measurement": True,
                "all_absolute_caps_selected": False,
                "complete_compiled_gate_pass": False,
            },
            "no_tolerance_transfer": True,
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
    assert report["schema"] == "volta-c7-stateful-alfc-r07-screen-v11"
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
    assert small_setup["absolute_setup_wall_cap_seconds"] is None
    assert small_setup["absolute_refresh_wall_cap_seconds"] is None
    assert not small_setup["all_absolute_caps_selected"]
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
    assert all(
        value is None
        for value in relaxations["setup"][
            "absolute_setup_wall_caps_seconds"
        ].values()
    )
    assert all(
        value is None
        for value in relaxations["setup"][
            "absolute_refresh_wall_caps_seconds"
        ].values()
    )
    assert not relaxations["setup"]["all_absolute_caps_selected"]
    assert not relaxations["setup"]["complete_compiled_gate_pass"]
    assert relaxations["no_tolerance_transfer"]
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
    assert policy["active_status"] == (
        "policy2_owner1_30_query_axis_candidate_backend_unadmitted"
    )
    assert policy["policy_3_candidate_exhaustion_documented"]
    assert len(policy["terminal_catalog"]) == 10
    assert policy["policy_2_status"] == "active_design_only"
    assert policy["policy_2_activation_authorized"]
    assert policy["policy_2_root_wide_query_horizon_schema_registered"]
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
    assert not gates[
        "setup_exploratory_absolute_time_and_refresh_caps_selected"
    ]
    assert gates["logical_leaf_geometry_selected"]
    assert not gates["anti_x4d_setup_gate_pass"]
    assert not gates["active_public_leaf_function_implemented"]
    assert gates["historical_policy3_poseidon2_leaf_implemented"]
    assert not gates["leaf_commitment_adaptive_hiding_proved"]
    assert not gates["concrete_leaf_commitment_selected"]
    assert not gates["policy3_private_leaf_checker_required"]
    assert not gates["only_budgeted_masked_query_payloads_codec_proved"]
    assert gates["terminal_evaluation_remains_authenticated"]
    assert not gates["malicious_dv_connection_privacy_theorem_complete"]
    assert not gates["policy2_model_lifetime_privacy_78bit_proved"]
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
    assert not gates["algebraic_security_amplifier_selected"]
    assert gates["algebraic_security_closure_path_selected"]
    assert gates["fp3_direct_three_limb_fallback_selected"]
    assert gates["first_compiler_envelope_selected"] == (
        "rate1-k0-4-owner1_30-Fp2-query-axis-flat-g141-one-root"
    )
    assert not gates["strict_ud_algebraic_110bit_per_response_derived"]
    assert not gates["strict_ud_model_lifetime_soundness_78bit_derived"]
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
    assert not gates["owner_1_30_complete_four_axis_query_gate_pass"]
    assert not gates["joint_sampler_visible_Fp_sharing_selected"]
    assert not gates["different_code_switch_selected"]
    assert not gates["one_pass_batch_open_blocks_proved"]
    assert not gates["cpu_batch_open_blocks_reference_pass"]
    assert not gates["simt_bit_exact_equivalence_pass"]
    assert not gates["query_schedule_compiled"]
    assert gates["query_counter_schema"]["aggregate"] == list(
        POLICY2_AGGREGATE_CENSUS_CLASSES
    )
    assert gates["query_counter_schema"]["per_plane"] == list(
        POLICY2_QUERY_CLASSES
    )
    assert gates["query_counter_schema"][
        "logical_pcs_samples_q_open_by_plane_root_round"
    ] is None
    assert gates["adversarial_leaf_oracle_query_bound"] == 1 << 64
    assert gates["adversarial_leaf_oracle_query_bound_kind"] == (
        "owner_selected_analytic_screen_not_a_concrete_theorem_cap"
    )
    assert gates["adversarial_fiat_shamir_query_bound"] == 0
    assert all(
        value is None
        for value in gates["exact_query_counts_by_root_and_round"].values()
    )
    assert all(
        value is None
        for value in gates["serialized_query_and_challenge_bytes_by_model"].values()
    )
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
    assert 118.9 < challenge_comparison["interactive_selected"]["effective_bits"] < 119.1
    assert 54.9 < challenge_comparison["fiat_shamir_direct_control"]["effective_bits"] < 55.1
    assert 173.9 < challenge_comparison["fiat_shamir_two_challenge_amplified"]["effective_bits"] < 174.1
    assert not challenge_comparison["fiat_shamir_two_challenge_amplified"][
        "proof_size_gate_passed"
    ]
    batch_open = report["batch_open_blocks_admission"]
    assert batch_open["logical_leaf_symbols"] == 141
    assert batch_open["generator_incidence_obstruction"][
        "nonzero_incidence_lower_bound"
    ] == "nnz(G) >= k*d"
    assert batch_open["cpu_reference_contract"]["reference_implemented"]
    assert "opened leaf salts and canonical query/leaf indices" in batch_open[
        "cpu_reference_contract"
    ]["required_output"]
    assert batch_open["cpu_reference_contract"]["packed_source_passes"] == 1
    assert not batch_open["c7_cpu_reference_pass"]
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
        "R07_OWNER_1_30_QUERY_AXIS_CANDIDATE_BACKEND_UNADMITTED"
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
        "C7_R07_OWNER_1_30_QUERY_AXIS_CANDIDATE_NOT_READY"
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
