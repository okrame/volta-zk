#!/usr/bin/env python3
"""Exact non-credit screen for the corrected C6.4 projected residual PCS."""

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
C64_PROJECTED_RESIDUAL_BODY_BYTES = 6_861_312
C64_CORRECTION_LINK_BYTES = 1_624
C64_CORRECTION_LINK_ROUNDS = 24
C64_PROJECTED_RESIDUAL_SECURITY_BITS = 107
C64_PROJECTED_RESIDUAL_CORES = 6
C64_PROJECTED_RESIDUAL_FULL_CORRELATIONS_PER_TAPE = 6 + 2 * C64_CORRECTION_LINK_ROUNDS
C64_PRODUCTION_SUFFIX_FULL_CORRELATIONS_PER_TAPE = 661
C64_TERMINAL_BATCH_ERROR_NUMERATOR = 2 * (5 + 1 + 15) + 1
C64_CORRECTION_BATCH_ERROR_NUMERATOR = 1
C64_TERMINAL_SUMCHECK_ERROR_NUMERATOR = 2 * C64_CORRECTION_LINK_ROUNDS
C64_TERMINAL_NONZERO_ERROR_NUMERATOR = 1
C64_TERMINAL_ZEROOPEN_ERROR_NUMERATOR = 6
C64_TERMINAL_ERROR_NUMERATOR = (
    C64_TERMINAL_BATCH_ERROR_NUMERATOR
    + C64_CORRECTION_BATCH_ERROR_NUMERATOR
    + C64_TERMINAL_SUMCHECK_ERROR_NUMERATOR
    + C64_TERMINAL_NONZERO_ERROR_NUMERATOR
    + C64_TERMINAL_ZEROOPEN_ERROR_NUMERATOR
)
C64_DISTANCE_BITS = 188
SOUNDNESS_LIMIT_BITS = Decimal("78.00")

# Historical C6.3 values are used only as a byte-delta baseline.  They confer
# no C6.4 credit.
C63_COMPLETE_CERTIFICATE_BYTES = 28_710_631
C63_REDUCED_OUTPUT_LINK_BYTES = 2_672_044
C63_EIGHT_WHIR_BODY_BYTES = 9_039_328
C63_FOUR_TRANSITION_OPENING_BYTES = 1_194_532
C63_CORRECTION_ARTIFACT_MAX_BYTES = 2_042_062

# Exact output of the executable Rust structural screen.
C64_CODEC_RESERVE_BYTES = 4_096
C63_CERTIFICATE_FRAMING_BYTES = 793
C64_CERTIFICATE_FRAMING_BYTES = 761
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
    # Replace the old wrapper/output-link frame with the six residual bodies.
    # The reserve includes the 1,624-byte correction link, mask corrections
    # and strict framing.
    projected = (
        C63_COMPLETE_CERTIFICATE_BYTES
        - C63_REDUCED_OUTPUT_LINK_BYTES
        + C64_PROJECTED_RESIDUAL_BODY_BYTES
        + C64_CODEC_RESERVE_BYTES
        + C64_CERTIFICATE_FRAMING_BYTES
        - C63_CERTIFICATE_FRAMING_BYTES
    )
    return {
        "retained_c63_certificate_ceiling_bytes": C63_COMPLETE_CERTIFICATE_BYTES,
        "removed_c63_output_link_bytes": C63_REDUCED_OUTPUT_LINK_BYTES,
        "six_projected_residual_body_bytes": C64_PROJECTED_RESIDUAL_BODY_BYTES,
        "new_codec_reserve_bytes": C64_CODEC_RESERVE_BYTES,
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
        "physical_cache_bytes": physical_cache_values * FP_BYTES,
        "physical_private_residual_bytes": physical_private_values * FP_BYTES,
        "physical_total_bytes": physical_values * FP_BYTES,
        "projected_leaf_rows": 1 << 23,
        "projected_auxiliary_rows": 1 << 15,
        "resident_projected_fp2_bytes": (3 * (1 << 23) + (1 << 15)) * FP2_BYTES,
        "dense_residual_wrapper_bytes": 0,
    }


def d23_distance_screen() -> dict[str, int | str | bool]:
    """The corrected design keeps C6.3's already-certified D22 sparse code."""
    return {
        "input_rows": 1 << 22,
        "failure_probability_upper": "<2^-188",
        "bits_lower": C64_DISTANCE_BITS,
        "exact_rational_checks_complete": True,
        "new_sparse_matrix": False,
        "credit": False,
    }


def soundness_screen() -> dict[str, object]:
    inherited = c63.c63_soundness_screen()["known_terms_under_inherited_qro"]
    inherited_error = Fraction(int(inherited["numerator"]), int(inherited["denominator"]))
    terminal_error = Fraction(C64_TERMINAL_ERROR_NUMERATOR, c6.FP2_CARDINALITY)
    complete_error = (
        inherited_error
        + c62.C62_MAX_RANDOM_ORACLE_QUERIES
        * (
            Fraction(C64_PROJECTED_RESIDUAL_CORES, 1 << C64_PROJECTED_RESIDUAL_SECURITY_BITS)
            + terminal_error
        )
    )
    bits = c6.soundness_bits(complete_error)
    return {
        "terminal_batch_error_numerator_over_fp2": C64_TERMINAL_BATCH_ERROR_NUMERATOR,
        "correction_batch_error_numerator_over_fp2": C64_CORRECTION_BATCH_ERROR_NUMERATOR,
        "terminal_sumcheck_error_numerator_over_fp2": C64_TERMINAL_SUMCHECK_ERROR_NUMERATOR,
        "terminal_nonzero_error_numerator_over_fp2": C64_TERMINAL_NONZERO_ERROR_NUMERATOR,
        "terminal_zeroopen_error_numerator_over_fp2": C64_TERMINAL_ZEROOPEN_ERROR_NUMERATOR,
        "terminal_union_error_numerator_over_fp2": C64_TERMINAL_ERROR_NUMERATOR,
        "projected_residual_core_count": C64_PROJECTED_RESIDUAL_CORES,
        "projected_residual_security_bits_per_core": C64_PROJECTED_RESIDUAL_SECURITY_BITS,
        "random_oracle_query_bound": c62.C62_MAX_RANDOM_ORACLE_QUERIES,
        "complete_error_numerator": str(complete_error.numerator),
        "complete_error_denominator": str(complete_error.denominator),
        "complete_soundness_bits": str(bits),
        "gate_bits": str(SOUNDNESS_LIMIT_BITS),
        "gate_pass": bits >= SOUNDNESS_LIMIT_BITS,
        "credit": False,
    }


def build_screen() -> dict[str, object]:
    responses = [response_screen(*response) for response in RESPONSES]
    return {
        "schema": 3,
        "milestone": "C6.4-R5",
        "credit": False,
        "geometry": {
            "projected_leaf_log2": 23,
            "projected_correction_log2": 24,
            "projected_auxiliary_log2": 15,
            "leaf_columns_before_projection": C6RSC3_LEAF_TABLES,
            "auxiliary_columns_before_projection": C6RSC3_AUXILIARY_TABLES,
            "dense_joint_bytes_forbidden": INPUT_ROWS * JOINT_ROW_BYTES,
            "new_sparse_setup_bytes": 0,
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
            "projected_polynomials": 3,
            "base_field_whir_bodies": 6,
            "sumcheck_rounds": C64_CORRECTION_LINK_ROUNDS,
            "correction_link_framed_bytes": C64_CORRECTION_LINK_BYTES,
            "framed_bytes": C64_PROJECTED_RESIDUAL_BODY_BYTES,
            "full_correlations_per_tape": C64_PROJECTED_RESIDUAL_FULL_CORRELATIONS_PER_TAPE,
            "complete_suffix_full_correlations_per_tape": C64_PRODUCTION_SUFFIX_FULL_CORRELATIONS_PER_TAPE,
            "credit": False,
        },
        "setup_profile_ids": [0, 150],
        "setup_profile_count": 2,
        "open_gates": [
            "pod_cuda_compile_and_projection_differential",
            "measured_complete_certificate_bytes",
            "measured_finite_real_pcg_two_response_run",
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
    assert geometry["new_sparse_setup_bytes"] == 0
    assert responses[0]["physical_total_bytes"] == 645_096_528
    assert responses[0]["physical_private_residual_bytes"] == 586_114_128
    assert responses[1]["physical_total_bytes"] == 313_534_080
    assert responses[1]["physical_private_residual_bytes"] == 234_890_880
    assert responses[0]["resident_projected_fp2_bytes"] == 403_177_472
    assert responses[1]["dense_residual_wrapper_bytes"] == 0
    assert screen["setup_profile_ids"] == [0, 150]
    assert screen["setup_profile_count"] == 2
    assert byte_budget["projected_complete_certificate_bytes"] == 32_903_963
    assert byte_budget["diagnostic_headroom_bytes"] == -2_903_963
    assert byte_budget["hard_limit_headroom_bytes"] == 2_096_037
    assert byte_budget["diagnostic_30mb_pass"] is False
    assert byte_budget["hard_limit_35mb_pass"] is True
    assert byte_budget["credit"] is False
    assert terminal["tables_per_repetition"] == 24
    assert terminal["private_tables_per_repetition"] == 24
    assert terminal["terminal_claims_total"] == 48
    assert terminal["padded_tables_materialized"] == 0
    assert terminal["projected_polynomials"] == 3
    assert terminal["base_field_whir_bodies"] == 6
    assert terminal["sumcheck_rounds"] == 24
    assert terminal["correction_link_framed_bytes"] == 1_624
    assert terminal["framed_bytes"] == 6_861_312
    assert terminal["full_correlations_per_tape"] == 54
    assert terminal["complete_suffix_full_correlations_per_tape"] == 661
    assert terminal["credit"] is False
    assert distance["bits_lower"] == 188
    assert distance["new_sparse_matrix"] is False
    assert distance["exact_rational_checks_complete"] is True
    assert soundness["terminal_union_error_numerator_over_fp2"] == 99
    assert soundness["projected_residual_security_bits_per_core"] == 107
    assert str(soundness["complete_soundness_bits"]).startswith("78.001993")
    assert soundness["gate_pass"] is True
    assert screen["credit"] is False


def main() -> None:
    screen = build_screen()
    self_check(screen)
    print(json.dumps(screen, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
