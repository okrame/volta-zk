#!/usr/bin/env python3
"""Executable C7 R0.3 analytic/readiness screen; every result is credit:false."""

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
MERKLE_SYMBOLS_PER_LEAF = 64
DIGEST_ONLY_LEAF_CANDIDATES = (64, 128, 129, 141, 256)
HASH_BYTES = 32
AUTHENTICATED_FP_SYMBOL_BYTES = 8
AUTHENTICATED_FP2_SYMBOL_BYTES = 16
LEAF_SALT_BITS = 256
LEAF_ORACLE_QUERY_SCREEN = 1 << 64

SETUP_TARGET_NUMERATOR = 2
SETUP_TARGET_DENOMINATOR = 1
SETUP_HARD_NUMERATOR = 21
SETUP_HARD_DENOMINATOR = 10
QUERY_TOLERANCE_NUMERATOR = 105
QUERY_TOLERANCE_DENOMINATOR = 100

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


def ceil_div(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


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


def setup_and_refresh(model: dict[str, object], bandwidth_bytes_per_second: float) -> dict[str, object]:
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
    leaves = ceil_div(oracle_symbols, MERKLE_SYMBOLS_PER_LEAF)
    merkle_nodes = 2 * leaves - 1
    merkle = merkle_nodes * HASH_BYTES
    digest_only_screen = packed + merkle
    persistent_oracle = oracle + merkle
    setup_disk = packed + persistent_oracle + p1 + p2 + multiplier
    setup_target = packed * SETUP_TARGET_NUMERATOR // SETUP_TARGET_DENOMINATOR
    setup_hard = packed * SETUP_HARD_NUMERATOR // SETUP_HARD_DENOMINATOR
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
            "amplification_over_packed_i16": candidate_total / packed,
            "private_payload_bytes_per_unique_leaf": {
                "Fp": symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES,
                "Fp2": symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES,
            },
            "within_2x_target": candidate_total <= setup_target,
            "within_2_1x_hard_ceiling": candidate_total <= setup_hard,
            "classification": (
                "within_target_floor_only"
                if candidate_total <= setup_target
                else "within_registered_tolerance_floor_only"
                if candidate_total <= setup_hard
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
            "symbols_per_leaf": MERKLE_SYMBOLS_PER_LEAF,
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
            "hard_multiplier_with_tolerance": "21/10",
            "tolerance_percent_of_target": 5,
            "target_bytes": setup_target,
            "hard_ceiling_bytes": setup_hard,
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
        "selected_artifact_volume_sum": byte_result(
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


def model_report(
    model: dict[str, object], chunk_bytes: int, bandwidth: float
) -> dict[str, object]:
    components = certificate_components(model)
    total = sum(int(component["bytes"]) for component in components.values())
    weight_target = int(components["B_weight_ALFC"]["bytes"])
    weight_hard = (
        weight_target * QUERY_TOLERANCE_NUMERATOR
        // QUERY_TOLERANCE_DENOMINATOR
    )
    weight_tolerance_reserve = weight_hard - weight_target
    payload_only_leaf_bounds = {}
    for symbols_per_leaf in DIGEST_ONLY_LEAF_CANDIDATES:
        payload_only_leaf_bounds[str(symbols_per_leaf)] = {
            "Fp": {
                "target": weight_target
                // (symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES),
                "hard": weight_hard
                // (symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES),
                "tolerance_only": weight_tolerance_reserve
                // (symbols_per_leaf * AUTHENTICATED_FP_SYMBOL_BYTES),
            },
            "Fp2": {
                "target": weight_target
                // (symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES),
                "hard": weight_hard
                // (symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES),
                "tolerance_only": weight_tolerance_reserve
                // (symbols_per_leaf * AUTHENTICATED_FP2_SYMBOL_BYTES),
            },
        }
    total_at_weight_hard = total - weight_target + weight_hard
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
            "weight_oracle_post_fiat_shamir_envelope": {
                "included_in_B_weight_ALFC_not_additive": True,
                "target_bytes": weight_target,
                "hard_ceiling_bytes": weight_hard,
                "tolerance_reserve_over_target_bytes": weight_tolerance_reserve,
                "tolerance_percent": 5,
                "compiled_weight_oracle_query_bytes": None,
                "status": "unknown_fail_closed",
                "payload_only_unique_leaf_upper_bounds": payload_only_leaf_bounds,
                "upper_bound_warning": (
                    "reserves zero bytes for digests, multiproofs, the private "
                    "leaf checker, authenticated IOP messages or framing"
                ),
                "credit": False,
            },
            "total_if_weight_envelope_uses_hard_tolerance": byte_result(
                total_at_weight_hard,
                "allocation_sensitivity_not_a_compiled_certificate",
                "certificate_target-B_weight_ALFC_target+B_weight_ALFC_hard",
            ),
            "unknown_components_fail_closed": [
                "operator_protocol",
                "authenticated_oracle_query_compiler",
                "concrete_codec",
            ],
            "credit": False,
        },
        "source_functional_scan_target": online_scan(
            model, chunk_bytes, bandwidth
        ),
        "selected_artifact_volume_screen": setup_and_refresh(model, bandwidth),
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
    largest_static_leaf_count = ceil_div(
        int(GEMMA_ENVELOPE["weights"]) * ERA_INVERSE_RATE_NUMERATOR
        // ERA_INVERSE_RATE_DENOMINATOR,
        128,
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
            "target Fp2 with one shared Delta; Lean proves extension-field "
            "linearity and coordinate consequences, not the concrete adapter"
        ),
        "one_time_correlations_and_masks_burn_on_abort": True,
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
        "classification": (
            "conditional_union_budget_arithmetic_not_a_security_proof"
        ),
        "leaf_commitment_hiding_screen": {
            "salt_bits": LEAF_SALT_BITS,
            "largest_static_weight_leaf_count_screen": largest_static_leaf_count,
            "adversarial_leaf_oracle_queries_screen": LEAF_ORACLE_QUERY_SCREEN,
            "formula": "2*L_static*Q_leaf/2^salt_bits",
            "hit_probability_exact": f"{leaf_hit.numerator}/{leaf_hit.denominator}",
            "effective_bits": leaf_hit_bits,
            "salt_192_effective_bits_same_screen": leaf_hit_192_bits,
            "salt_192_disposition": "reject",
            "Q_leaf_is_not_R_max": True,
            "connection_wide_leaf_count_complete": False,
            "concrete_arithmetizable_commitment_selected": False,
            "binding_error_derived": False,
            "credit": False,
        },
        "challenge_generation": {
            "mode_selected": False,
            "recommended_mode": (
                "fresh honest-DV challenges after their committed prefixes; "
                "serialize them in the durable transcript"
            ),
            "fiat_shamir_status": (
                "quarantined until Q_FS and grinding loss are derived"
            ),
            "adversarial_fiat_shamir_query_bound": None,
            "warning": (
                "a roughly 128-bit Fp2 challenge loses log2(Q_FS) bits "
                "under a direct ROM grinding bound"
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
        "schema": "volta-c7-stateful-alfc-r03-screen-v4",
        "design": "C7 stateful authenticated linear-functional commitment",
        "screening_only": True,
        "credit": False,
        "authorization": {
            "r03_design_theorem_census_authorized": True,
            "prover_implementation_or_execution_authorized": False,
            "pod_contact_or_execution_authorized": False,
            "pod_preparation_only": True,
            "c7_pod_ready": False,
        },
        "privacy_policy": {
            "active": 3,
            "sole_candidate_shape": (
                "digest-only salted leaf commitment with public Merkle paths "
                "and attempt-local VOLE-private leaf/PCS checks"
            ),
            "policy_3_candidate_exhaustion_documented": False,
            "policy_2_status": "dormant_not_authorized",
            "policy_2_activation_authorized": False,
            "policy_2_root_wide_query_horizon_registered": False,
        },
        "admission_gates": {
            "candidate_setup_manifest_complete": False,
            "setup_disk_time_traffic_refresh_derived": False,
            "peak_resident_or_mapped_setup_bytes_counted": False,
            "numeric_setup_ceiling_registered": True,
            "weight_query_fs_envelope_registered": True,
            "anti_x4d_setup_gate_pass": False,
            "concrete_leaf_commitment_selected": False,
            "leaf_commitment_adaptive_hiding_proved": False,
            "authenticated_checker_soundness_or_pok_refinement_proved": False,
            "all_query_payloads_nonclear_codec_proved": False,
            "malicious_dv_connection_privacy_theorem_complete": False,
            "challenge_generation_and_grinding_policy_selected": False,
            "one_pass_batch_open_blocks_proved": False,
            "query_schedule_compiled": False,
            "query_counter_schema": [
                "q_open_by_root_and_round",
                "unique_leaves",
                "secret_symbols",
                "adversarial_leaf_oracle_queries",
                "adversarial_fiat_shamir_queries",
            ],
            "exact_query_counts_by_root_and_round": {
                str(GPT2["name"]): None,
                str(GEMMA_ENVELOPE["name"]): None,
            },
            "adversarial_leaf_oracle_query_bound": None,
            "adversarial_fiat_shamir_query_bound": None,
            "post_fiat_shamir_query_bytes_by_model": {
                str(GPT2["name"]): None,
                str(GEMMA_ENVELOPE["name"]): None,
            },
            "query_bytes_reconciled_into_certificate_total": False,
            "compiled_tier_a_certificate_gate_pass": False,
        },
        "pod_readiness": {
            "state": "C7_R03_NOT_READY",
            "handoff_spec": "docs/c7-r03-prover-pod-handoff.md",
            "handoff_preparation_authorized": True,
            "required_before_C7_POD_READY": {
                "concrete_crypto_and_composed_security_pass": False,
                "canonical_compiler_and_query_census_pass": False,
                "one_pass_bounded_memory_schedule_pass": False,
                "setup_manifest_within_owner_envelope": False,
                "compiled_certificate_within_owner_envelope": False,
                "no_clear_codec_and_real_finite_pcg_pass": False,
                "two_response_tiny_scaled_serialized_chain_pass": False,
                "reload_full_verifier_and_mutations_pass": False,
                "abort_burn_and_atomic_promotion_pass": False,
                "clean_checkpoint_and_ledger_transition": False,
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
            "weight_transposition_assumption": "The ERA point is security-scaled to 110 bits and log^2-scaled in N; the new VOLE-MAC ALFC adapter is unproved.",
            "post_fiat_shamir_query_ledger": "B_query_FS is a cross-cutting sub-ledger assigned exactly once into the six certificate components; its query census and bytes are unknown.",
            "all_results": "Every byte, time and memory quantity is credit:false.",
        },
        "parameters": {
            "ERA_inverse_rate": 4.4,
            "field_symbol_bytes": FIELD_SYMBOL_BYTES,
            "packed_weight_bytes": PACKED_WEIGHT_BYTES,
            "P1_bytes_per_source_weight": PERMUTATION_INDEX_BYTES,
            "P2_bytes_per_source_weight": PERMUTATION_INDEX_BYTES,
            "multiplier_bytes_per_source_weight": MULTIPLIER_BYTES,
            "Merkle_symbols_per_leaf": MERKLE_SYMBOLS_PER_LEAF,
            "digest_only_leaf_candidates": list(DIGEST_ONLY_LEAF_CANDIDATES),
            "setup_target_multiplier": 2.0,
            "setup_hard_multiplier_with_tolerance": 2.1,
            "weight_query_hard_tolerance_percent": 5,
            "leaf_salt_bits_screen": LEAF_SALT_BITS,
            "leaf_oracle_query_screen": LEAF_ORACLE_QUERY_SCREEN,
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
        "self_check": {"status": "pending", "credit": False},
    }


def self_check(report: dict[str, object]) -> None:
    assert report["schema"] == "volta-c7-stateful-alfc-r03-screen-v4"
    models = report["models"]
    small = models[str(GPT2["name"])]
    large = models[str(GEMMA_ENVELOPE["name"])]
    assert ACCEPTED_CONTEXT_TOKENS + RESPONSE_TOKENS == SUCCESSOR_CONTEXT_TOKENS
    assert int(GEMMA_ENVELOPE["weights"]) / int(GPT2["weights"]) == 248.6
    assert terminal_segments(GPT2)["total"] == 106
    assert terminal_segments(GEMMA_ENVELOPE)["total"] == 378
    assert weight_alfc_bytes(REFERENCE_N) == 4_415_400
    assert (
        small["selected_artifact_volume_screen"]["selected_artifact_volume_sum"]["bytes"]
        == 7_142_399_968
    )
    assert (
        small["selected_artifact_volume_screen"][
            "digest_only_candidate_floor_screen"
        ]["bytes"]
        == 793_599_968
    )
    assert (
        large["selected_artifact_volume_screen"]["selected_artifact_volume_sum"]["bytes"]
        == 1_775_600_639_968
    )
    small_setup = small["selected_artifact_volume_screen"]["owner_setup_envelope"]
    large_setup = large["selected_artifact_volume_screen"]["owner_setup_envelope"]
    assert small_setup["target_bytes"] == 496_000_000
    assert small_setup["hard_ceiling_bytes"] == 520_800_000
    assert large_setup["target_bytes"] == 123_305_600_000
    assert large_setup["hard_ceiling_bytes"] == 129_470_880_000
    assert small_setup["leaf_screens"]["64"]["classification"] == "reject"
    assert small_setup["leaf_screens"]["128"]["classification"] == (
        "within_registered_tolerance_floor_only"
    )
    assert small_setup["leaf_screens"]["256"]["classification"] == (
        "within_target_floor_only"
    )
    assert small_setup["leaf_screens"]["129"]["classification"] == (
        "within_registered_tolerance_floor_only"
    )
    assert small_setup["leaf_screens"]["141"]["classification"] == (
        "within_target_floor_only"
    )
    assert large_setup["leaf_screens"]["128"]["classification"] == (
        "within_registered_tolerance_floor_only"
    )
    assert small_setup["leaf_screens"]["128"][
        "hard_ceiling_metadata_headroom_bytes"
    ] == 32
    assert large_setup["leaf_screens"]["128"][
        "hard_ceiling_metadata_headroom_bytes"
    ] == 32
    assert not small["selected_artifact_volume_screen"][
        "anti_x4d_structural_gate"
    ]["passes"]
    assert not large["selected_artifact_volume_screen"][
        "anti_x4d_structural_gate"
    ]["passes"]
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
    assert not report["security"]["event_registry_complete"]
    assert report["security"]["conditional_budget_fits_78"]
    policy = report["privacy_policy"]
    assert policy["active"] == 3
    assert policy["policy_2_status"] == "dormant_not_authorized"
    assert not policy["policy_2_activation_authorized"]
    authorization = report["authorization"]
    assert authorization["r03_design_theorem_census_authorized"]
    assert not authorization["prover_implementation_or_execution_authorized"]
    assert not authorization["pod_contact_or_execution_authorized"]
    assert not authorization["c7_pod_ready"]
    gates = report["admission_gates"]
    assert gates["numeric_setup_ceiling_registered"]
    assert gates["weight_query_fs_envelope_registered"]
    assert not gates["anti_x4d_setup_gate_pass"]
    assert not gates["leaf_commitment_adaptive_hiding_proved"]
    assert not gates["concrete_leaf_commitment_selected"]
    assert not gates["authenticated_checker_soundness_or_pok_refinement_proved"]
    assert not gates["all_query_payloads_nonclear_codec_proved"]
    assert not gates["malicious_dv_connection_privacy_theorem_complete"]
    assert not gates["challenge_generation_and_grinding_policy_selected"]
    assert not gates["one_pass_batch_open_blocks_proved"]
    assert not gates["query_schedule_compiled"]
    assert gates["query_counter_schema"] == [
        "q_open_by_root_and_round",
        "unique_leaves",
        "secret_symbols",
        "adversarial_leaf_oracle_queries",
        "adversarial_fiat_shamir_queries",
    ]
    assert gates["adversarial_leaf_oracle_query_bound"] is None
    assert gates["adversarial_fiat_shamir_query_bound"] is None
    assert all(
        value is None
        for value in gates["exact_query_counts_by_root_and_round"].values()
    )
    assert all(
        value is None
        for value in gates["post_fiat_shamir_query_bytes_by_model"].values()
    )
    assert not gates["query_bytes_reconciled_into_certificate_total"]
    assert not gates["compiled_tier_a_certificate_gate_pass"]
    small_query = small["certificate"]["weight_oracle_post_fiat_shamir_envelope"]
    large_query = large["certificate"]["weight_oracle_post_fiat_shamir_envelope"]
    assert small_query["target_bytes"] == 3_116_843
    assert small_query["hard_ceiling_bytes"] == 3_272_685
    assert small_query["tolerance_reserve_over_target_bytes"] == 155_842
    assert large_query["target_bytes"] == 5_234_948
    assert large_query["hard_ceiling_bytes"] == 5_496_695
    assert large_query["tolerance_reserve_over_target_bytes"] == 261_747
    assert small["certificate"][
        "total_if_weight_envelope_uses_hard_tolerance"
    ]["bytes"] == 12_541_405
    assert large["certificate"][
        "total_if_weight_envelope_uses_hard_tolerance"
    ]["bytes"] == 19_474_047
    leaf_hide = report["security"]["leaf_commitment_hiding_screen"]
    assert leaf_hide["salt_bits"] == 256
    assert leaf_hide["effective_bits"] > 161
    assert leaf_hide["salt_192_effective_bits_same_screen"] < 98
    assert not leaf_hide["concrete_arithmetizable_commitment_selected"]
    readiness = report["pod_readiness"]
    assert readiness["state"] == "C7_R03_NOT_READY"
    assert not readiness["all_required_gates_pass"]
    assert not any(readiness["required_before_C7_POD_READY"].values())
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
