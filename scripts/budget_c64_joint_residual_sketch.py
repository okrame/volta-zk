#!/usr/bin/env python3
"""Exact non-credit capacity screen for the selected C6.4 joint layout."""

from __future__ import annotations

import json

FP_BYTES = 8
FP2_BYTES = 2 * FP_BYTES
JOINT_COLUMNS = 16
JOINT_ROW_BYTES = JOINT_COLUMNS * FP_BYTES
RESIDUAL_PUBLIC_COLUMNS = 2 * 2  # two Fp2 corrections, two Fp limbs each
RESIDUAL_PUBLIC_ROW_BYTES = RESIDUAL_PUBLIC_COLUMNS * FP_BYTES
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
PUBLIC_CORRECTION_TABLES = 2

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
CERTIFICATE_TARGET_BYTES = 28_000_000
CERTIFICATE_LIMIT_BYTES = 30_000_000

RESPONSES = (
    ("genesis_0_150", 150 * (6 << 9), 5_119_131),
    ("continuation_150_200", 200 * (6 << 9), 1_992_912),
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
    )
    return {
        "systematic_queries": SYSTEMATIC_QUERIES,
        "maximum_sibling_digests": siblings,
        "systematic_opening_max_bytes": opening,
        "eight_whir_body_bytes": C64_EIGHT_WHIR_BODY_BYTES,
        "four_transition_opening_bytes": C64_FOUR_TRANSITION_OPENING_BYTES,
        "projected_complete_certificate_bytes": projected,
        "target_headroom_bytes": CERTIFICATE_TARGET_BYTES - projected,
        "hard_limit_headroom_bytes": CERTIFICATE_LIMIT_BYTES - projected,
        "target_28mb_pass": projected <= CERTIFICATE_TARGET_BYTES,
        "hard_limit_30mb_pass": projected <= CERTIFICATE_LIMIT_BYTES,
        "credit": False,
    }


def response_screen(name: str, cache_rows: int, residual_rows: int) -> dict[str, int | str]:
    live_rows = cache_rows + residual_rows
    if live_rows > INPUT_ROWS:
        raise ValueError(f"{name} exceeds D23")
    return {
        "name": name,
        "cache_rows": cache_rows,
        "residual_rows": residual_rows,
        "live_rows": live_rows,
        "d23_headroom_rows": INPUT_ROWS - live_rows,
        "physical_public_bytes": (
            cache_rows * JOINT_ROW_BYTES
            + residual_rows * RESIDUAL_PUBLIC_ROW_BYTES
        ),
        "virtual_zero_bytes_not_materialized": (
            INPUT_ROWS * JOINT_ROW_BYTES
            - cache_rows * JOINT_ROW_BYTES
            - residual_rows * RESIDUAL_PUBLIC_ROW_BYTES
        ),
    }


def build_screen() -> dict[str, object]:
    socket_count = INPUT_ROWS * COLUMN_DEGREE
    if socket_count != SKETCH_ROWS * CHECK_DEGREE:
        raise ValueError("C6.4 sparse geometry is inconsistent")
    responses = [response_screen(*response) for response in RESPONSES]
    return {
        "schema": 1,
        "milestone": "C6.4-R1",
        "credit": False,
        "geometry": {
            "input_log2": INPUT_LOG2,
            "input_rows": INPUT_ROWS,
            "sketch_log2": SKETCH_LOG2,
            "sketch_rows": SKETCH_ROWS,
            "columns": JOINT_COLUMNS,
            "row_bytes": JOINT_ROW_BYTES,
            "residual_public_columns": RESIDUAL_PUBLIC_COLUMNS,
            "residual_public_row_bytes": RESIDUAL_PUBLIC_ROW_BYTES,
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
        "terminal_link_screen": {
            "leaf_tables_per_repetition": C6RSC3_LEAF_TABLES,
            "auxiliary_tables_per_repetition": C6RSC3_AUXILIARY_TABLES,
            "tables_per_repetition": C6RSC3_LEAF_TABLES + C6RSC3_AUXILIARY_TABLES,
            "public_correction_tables_per_repetition": PUBLIC_CORRECTION_TABLES,
            "private_compact_tables_per_repetition": (
                C6RSC3_LEAF_TABLES + C6RSC3_AUXILIARY_TABLES - PUBLIC_CORRECTION_TABLES
            ),
            "terminal_claims_total": (
                C6RSC3_REPETITIONS * (C6RSC3_LEAF_TABLES + C6RSC3_AUXILIARY_TABLES)
            ),
            "padded_tables_materialized": 0,
            "credit": False,
        },
        "setup_profile_ids": [0, 150],
        "setup_profile_count": 2,
        "open_gates": [
            "privacy_and_source_binding",
            "c6rsc3_terminal_link",
            "d23_d20_whir_structural_bytes",
            "complete_certificate_bytes",
            "soundness",
            "finite_real_pcg_census",
            "measured_simt_time",
        ],
    }


def self_check(screen: dict[str, object]) -> None:
    geometry = screen["geometry"]
    responses = screen["responses"]
    byte_budget = screen["structural_byte_screen"]
    terminal = screen["terminal_link_screen"]
    assert isinstance(geometry, dict)
    assert isinstance(responses, list)
    assert isinstance(byte_budget, dict)
    assert isinstance(terminal, dict)
    assert geometry["dense_joint_bytes_forbidden"] == 1_073_741_824
    assert geometry["one_sparse_sketch_bytes"] == 134_217_728
    assert geometry["sparse_setup_total_bytes"] == 1_610_612_736
    assert responses[0]["live_rows"] == 5_579_931
    assert responses[0]["d23_headroom_rows"] == 2_808_677
    assert responses[0]["physical_public_bytes"] == 222_794_592
    assert responses[1]["live_rows"] == 2_607_312
    assert responses[1]["d23_headroom_rows"] == 5_781_296
    assert responses[1]["physical_public_bytes"] == 142_416_384
    assert screen["setup_profile_ids"] == [0, 150]
    assert screen["setup_profile_count"] == 2
    assert byte_budget["maximum_sibling_digests"] == 47_972
    assert byte_budget["systematic_opening_max_bytes"] == 2_100_878
    assert byte_budget["projected_complete_certificate_bytes"] == 29_114_967
    assert byte_budget["target_headroom_bytes"] == -1_114_967
    assert byte_budget["hard_limit_headroom_bytes"] == 885_033
    assert byte_budget["target_28mb_pass"] is False
    assert byte_budget["hard_limit_30mb_pass"] is True
    assert byte_budget["credit"] is False
    assert terminal["tables_per_repetition"] == 24
    assert terminal["public_correction_tables_per_repetition"] == 2
    assert terminal["private_compact_tables_per_repetition"] == 22
    assert terminal["terminal_claims_total"] == 48
    assert terminal["padded_tables_materialized"] == 0
    assert terminal["credit"] is False
    assert screen["credit"] is False


def main() -> None:
    screen = build_screen()
    self_check(screen)
    print(json.dumps(screen, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
