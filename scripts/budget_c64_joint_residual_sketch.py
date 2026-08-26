#!/usr/bin/env python3
"""Exact non-credit capacity screen for the selected C6.4 joint layout."""

from __future__ import annotations

import json
import sys
from decimal import Decimal
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import budget_c62_whir_fiat_shamir as c62
import budget_c63_authenticated_sketch as c63
import budget_c6_wrapper as c6

FP_BYTES = 8
FP2_BYTES = 2 * FP_BYTES
JOINT_COLUMNS = 16
JOINT_ROW_BYTES = JOINT_COLUMNS * FP_BYTES
INPUT_LOG2 = 23
SKETCH_LOG2 = 20
INPUT_ROWS = 1 << INPUT_LOG2
SKETCH_ROWS = 1 << SKETCH_LOG2
COLUMN_DEGREE = 16
CHECK_DEGREE = 128
SYSTEMATIC_QUERIES = 4_420
C6RSC3_LEAF_TABLES = 8
C6RSC3_AUXILIARY_TABLES = 16
C6RSC3_REPETITIONS = 2
C64_TERMINAL_LINK_BYTES = 1_816
C64_TERMINAL_LINK_ROUNDS = 27
C64_TERMINAL_LINK_FULL_CORRELATIONS_PER_TAPE = 54
C64_TERMINAL_BATCH_ERROR_NUMERATOR = 47
C64_TERMINAL_SUMCHECK_ERROR_NUMERATOR = 2 * C64_TERMINAL_LINK_ROUNDS
C64_TERMINAL_ZEROOPEN_ERROR_NUMERATOR = 2
C64_TERMINAL_ERROR_NUMERATOR = (
    C64_TERMINAL_BATCH_ERROR_NUMERATOR
    + C64_TERMINAL_SUMCHECK_ERROR_NUMERATOR
    + C64_TERMINAL_ZEROOPEN_ERROR_NUMERATOR
)
C64_DISTANCE_BITS = 186
SOUNDNESS_LIMIT_BITS = Decimal("78.00")

# Historical C6.3 values are used only as a byte-delta baseline.  They confer
# no C6.4 credit.
C63_COMPLETE_CERTIFICATE_BYTES = 28_710_631
C63_EIGHT_WHIR_BODY_BYTES = 9_039_328
C63_FOUR_TRANSITION_OPENING_BYTES = 1_194_532
C63_CORRECTION_ARTIFACT_MAX_BYTES = 2_042_062

# Exact output of the executable Rust structural screen.
C64_EIGHT_WHIR_BODY_BYTES = 9_322_048
C64_FOUR_TRANSITION_OPENING_BYTES = 1_257_332
C64_SYSTEMATIC_OPENING_FRAMING_BYTES = 14  # magic + version + frontier count
CERTIFICATE_DIAGNOSTIC_BYTES = 30_000_000
CERTIFICATE_LIMIT_BYTES = 35_000_000

RESPONSES = (
    ("genesis_0_150", 150 * (6 << 9), 5_119_131, 399_140, 399_076),
    ("continuation_150_200", 200 * (6 << 9), 1_992_912, 365_180, 365_116),
)


def maximum_binary_multiproof_siblings(depth: int, queries: int) -> int:
    if not 0 < queries <= 1 << depth:
        raise ValueError("invalid Merkle query geometry")
    return sum(min(queries, 1 << level) for level in range(1, depth)) + 2 - queries


def byte_screen() -> dict[str, int | bool]:
    siblings = maximum_binary_multiproof_siblings(INPUT_LOG2, SYSTEMATIC_QUERIES)
    opening = (
        SYSTEMATIC_QUERIES * JOINT_ROW_BYTES
        + siblings * 32
        + C64_SYSTEMATIC_OPENING_FRAMING_BYTES
    )
    projected = (
        C63_COMPLETE_CERTIFICATE_BYTES
        - C63_EIGHT_WHIR_BODY_BYTES
        - C63_FOUR_TRANSITION_OPENING_BYTES
        - C63_CORRECTION_ARTIFACT_MAX_BYTES
        + C64_EIGHT_WHIR_BODY_BYTES
        + C64_FOUR_TRANSITION_OPENING_BYTES
        + opening
        + C64_TERMINAL_LINK_BYTES
    )
    return {
        "systematic_queries": SYSTEMATIC_QUERIES,
        "maximum_sibling_digests": siblings,
        "systematic_opening_max_bytes": opening,
        "eight_whir_body_bytes": C64_EIGHT_WHIR_BODY_BYTES,
        "four_transition_opening_bytes": C64_FOUR_TRANSITION_OPENING_BYTES,
        "projected_complete_certificate_bytes": projected,
        "diagnostic_headroom_bytes": CERTIFICATE_DIAGNOSTIC_BYTES - projected,
        "hard_limit_headroom_bytes": CERTIFICATE_LIMIT_BYTES - projected,
        "diagnostic_30mb_pass": projected <= CERTIFICATE_DIAGNOSTIC_BYTES,
        "hard_limit_35mb_pass": projected <= CERTIFICATE_LIMIT_BYTES,
        "credit": False,
    }


def response_screen(
    name: str,
    cache_rows: int,
    leaf_rows: int,
    closure_rows: int,
    auxiliary_fp2_entries: int,
) -> dict[str, int | str]:
    residual_rows = max(leaf_rows, closure_rows)
    packed_end_cells = (
        (cache_rows + residual_rows) * JOINT_COLUMNS + 2 * auxiliary_fp2_entries
    )
    capacity_cells = INPUT_ROWS * JOINT_COLUMNS
    if packed_end_cells > capacity_cells:
        raise ValueError(f"{name} exceeds D23")
    physical_cache_values = cache_rows * JOINT_COLUMNS
    physical_private_values = (
        leaf_rows * 14 + closure_rows * 2 + auxiliary_fp2_entries * 2
    )
    physical_values = physical_cache_values + physical_private_values
    return {
        "name": name,
        "cache_rows": cache_rows,
        "leaf_rows": leaf_rows,
        "closure_rows": closure_rows,
        "auxiliary_fp2_entries": auxiliary_fp2_entries,
        "residual_rows": residual_rows,
        "packed_end_cells": packed_end_cells,
        "packed_headroom_cells": capacity_cells - packed_end_cells,
        "physical_cache_bytes": physical_cache_values * FP_BYTES,
        "physical_private_residual_bytes": physical_private_values * FP_BYTES,
        "physical_total_bytes": physical_values * FP_BYTES,
        "virtual_zero_bytes_not_materialized": (capacity_cells - physical_values) * FP_BYTES,
    }


def d23_distance_screen() -> dict[str, int | str | bool]:
    """Exact rational reuse of the C6.3 finite-distance certificate at D23."""
    n = 1 << INPUT_LOG2
    maximum_weight = 49 * n // 1_000
    assert c63._exp_taylor_lower(Fraction(347, 500), 4) > 2
    assert c63._exp_taylor_lower(Fraction(917, 1_000), 5) > Fraction(5, 2)
    assert c63._exp_taylor_upper(Fraction(603, 200), 7) < Fraction(n, maximum_weight)
    assert Fraction(5, 4) ** 128 < 1 << 43
    assert c63.GOLDILOCKS_MODULUS > 1 << 63
    assert Fraction(7, 5) ** 128 / c63.GOLDILOCKS_MODULUS < Fraction(7, 25)
    alpha = Fraction(maximum_weight, n)
    upper_endpoint_n_phi = (
        -15 * maximum_weight * Fraction(3_015, 1_000)
        - 15 * (n - maximum_weight) * (alpha + alpha * alpha / 2)
        + 64 * maximum_weight * Fraction(694, 1_000)
        + 16 * maximum_weight * Fraction(917, 1_000)
        + Fraction(n, 8) * Fraction(7, 25)
    )
    assert upper_endpoint_n_phi < -15_000
    assert maximum_weight < 1 << 19
    assert 16 * n + 1 < 1 << 28
    assert C64_DISTANCE_BITS == 234 - 1 - 28 - 19
    return {
        "input_rows": n,
        "maximum_bad_weight": maximum_weight,
        "lower_endpoint_n_phi_upper": "-234*ln(2)+1/2",
        "upper_endpoint_n_phi_nat_upper": "<-15000",
        "failure_probability_upper": "<2^-186",
        "bits_lower": C64_DISTANCE_BITS,
        "exact_rational_checks_complete": True,
        "credit": False,
    }


def soundness_screen() -> dict[str, object]:
    inherited = c63.c63_soundness_screen()["known_terms_under_inherited_qro"]
    inherited_error = Fraction(int(inherited["numerator"]), int(inherited["denominator"]))
    terminal_error = Fraction(C64_TERMINAL_ERROR_NUMERATOR, c6.FP2_CARDINALITY)
    complete_error = (
        inherited_error
        - Fraction(1, 2**188)
        + Fraction(1, 2**C64_DISTANCE_BITS)
        + c62.C62_MAX_RANDOM_ORACLE_QUERIES * terminal_error
    )
    bits = c6.soundness_bits(complete_error)
    return {
        "terminal_batch_error_numerator_over_fp2": C64_TERMINAL_BATCH_ERROR_NUMERATOR,
        "terminal_sumcheck_error_numerator_over_fp2": C64_TERMINAL_SUMCHECK_ERROR_NUMERATOR,
        "terminal_zeroopen_error_numerator_over_fp2": C64_TERMINAL_ZEROOPEN_ERROR_NUMERATOR,
        "terminal_union_error_numerator_over_fp2": C64_TERMINAL_ERROR_NUMERATOR,
        "random_oracle_query_bound": c62.C62_MAX_RANDOM_ORACLE_QUERIES,
        "complete_error_numerator": str(complete_error.numerator),
        "complete_error_denominator": str(complete_error.denominator),
        "complete_soundness_bits": str(bits),
        "gate_bits": str(SOUNDNESS_LIMIT_BITS),
        "gate_pass": bits >= SOUNDNESS_LIMIT_BITS,
        "credit": False,
    }


def build_screen() -> dict[str, object]:
    socket_count = INPUT_ROWS * COLUMN_DEGREE
    if socket_count != SKETCH_ROWS * CHECK_DEGREE:
        raise ValueError("C6.4 sparse geometry is inconsistent")
    responses = [response_screen(*response) for response in RESPONSES]
    return {
        "schema": 2,
        "milestone": "C6.4-R2",
        "credit": False,
        "geometry": {
            "input_log2": INPUT_LOG2,
            "input_rows": INPUT_ROWS,
            "sketch_log2": SKETCH_LOG2,
            "sketch_rows": SKETCH_ROWS,
            "columns": JOINT_COLUMNS,
            "row_bytes": JOINT_ROW_BYTES,
            "column_degree": COLUMN_DEGREE,
            "check_degree": CHECK_DEGREE,
            "socket_count": socket_count,
            "dense_joint_bytes_forbidden": INPUT_ROWS * JOINT_ROW_BYTES,
            "one_sparse_sketch_bytes": SKETCH_ROWS * JOINT_ROW_BYTES,
            "sparse_setup_permutation_bytes": socket_count * 4,
            "sparse_setup_coefficient_bytes": socket_count * FP_BYTES,
            "sparse_setup_total_bytes": socket_count * (4 + FP_BYTES),
        },
        "responses": responses,
        "structural_byte_screen": byte_screen(),
        "finite_distance_screen": d23_distance_screen(),
        "soundness_screen": soundness_screen(),
        "terminal_link_screen": {
            "leaf_tables_per_repetition": C6RSC3_LEAF_TABLES,
            "auxiliary_tables_per_repetition": C6RSC3_AUXILIARY_TABLES,
            "tables_per_repetition": C6RSC3_LEAF_TABLES + C6RSC3_AUXILIARY_TABLES,
            "private_tables_per_repetition": 24,
            "terminal_claims_total": (
                C6RSC3_REPETITIONS * (C6RSC3_LEAF_TABLES + C6RSC3_AUXILIARY_TABLES)
            ),
            "padded_tables_materialized": 0,
            "sumcheck_rounds": C64_TERMINAL_LINK_ROUNDS,
            "framed_bytes": C64_TERMINAL_LINK_BYTES,
            "full_correlations_per_tape": C64_TERMINAL_LINK_FULL_CORRELATIONS_PER_TAPE,
            "credit": False,
        },
        "setup_profile_ids": [0, 150],
        "setup_profile_count": 2,
        "open_gates": [
            "production_streaming_and_privacy_codec",
            "complete_certificate_bytes",
            "finite_real_pcg_census",
            "two_profile_reload_lifecycle",
            "measured_simt_time",
        ],
    }


def self_check(screen: dict[str, object]) -> None:
    geometry = screen["geometry"]
    responses = screen["responses"]
    byte_budget = screen["structural_byte_screen"]
    terminal = screen["terminal_link_screen"]
    distance = screen["finite_distance_screen"]
    soundness = screen["soundness_screen"]
    assert isinstance(geometry, dict)
    assert isinstance(responses, list)
    assert isinstance(byte_budget, dict)
    assert isinstance(terminal, dict)
    assert isinstance(distance, dict)
    assert isinstance(soundness, dict)
    assert geometry["dense_joint_bytes_forbidden"] == 1_073_741_824
    assert geometry["one_sparse_sketch_bytes"] == 134_217_728
    assert geometry["sparse_setup_total_bytes"] == 1_610_612_736
    assert responses[0]["packed_end_cells"] == 90_077_048
    assert responses[0]["packed_headroom_cells"] == 44_140_680
    assert responses[0]["physical_total_bytes"] == 645_096_528
    assert responses[1]["packed_end_cells"] == 42_447_224
    assert responses[1]["packed_headroom_cells"] == 91_770_504
    assert responses[1]["physical_total_bytes"] == 313_534_080
    assert screen["setup_profile_ids"] == [0, 150]
    assert screen["setup_profile_count"] == 2
    assert byte_budget["maximum_sibling_digests"] == 47_972
    assert byte_budget["systematic_opening_max_bytes"] == 2_100_878
    assert byte_budget["projected_complete_certificate_bytes"] == 29_116_783
    assert byte_budget["diagnostic_headroom_bytes"] == 883_217
    assert byte_budget["hard_limit_headroom_bytes"] == 5_883_217
    assert byte_budget["diagnostic_30mb_pass"] is True
    assert byte_budget["hard_limit_35mb_pass"] is True
    assert byte_budget["credit"] is False
    assert terminal["tables_per_repetition"] == 24
    assert terminal["private_tables_per_repetition"] == 24
    assert terminal["terminal_claims_total"] == 48
    assert terminal["padded_tables_materialized"] == 0
    assert terminal["sumcheck_rounds"] == 27
    assert terminal["framed_bytes"] == 1_816
    assert terminal["full_correlations_per_tape"] == 54
    assert terminal["credit"] is False
    assert distance["maximum_bad_weight"] == 411_041
    assert distance["bits_lower"] == 186
    assert distance["exact_rational_checks_complete"] is True
    assert soundness["terminal_union_error_numerator_over_fp2"] == 103
    assert str(soundness["complete_soundness_bits"]).startswith("78.0190232026")
    assert soundness["gate_pass"] is True
    assert screen["credit"] is False


def main() -> None:
    screen = build_screen()
    self_check(screen)
    print(json.dumps(screen, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
