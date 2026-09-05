#!/usr/bin/env python3
"""Static D126 Gemma-31B checks; no benchmark or protocol credit."""

from __future__ import annotations

import copy
import hashlib
import heapq
import itertools
import json
import math
from collections.abc import Mapping
from fractions import Fraction
from pathlib import Path


SCHEMA = "volta-c7-d126-gemma-stacked-static-v1"
BLOCKED = "BLOCKED"
NO_GO = "NO-GO"

ROOT = Path(__file__).resolve().parents[1]
FROZEN_ARTIFACTS = {
    "source_metadata": (
        ROOT / "manifests" / "c7-d126-gemma31b-source-metadata-v1.json",
        "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2",
    ),
    "public_layer_scalars": (
        ROOT / "manifests" / "c7-d126-gemma31b-layer-scalars-v1.csv",
        "52c10c73dad7a8a81f937d4954d3b38b6cf38216393793e23571b3c6017d67af",
    ),
    "workload": (
        ROOT / "manifests" / "c7-d126-gemma31b-workload-v1.json",
        "70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b",
    ),
}


def verified_artifact_sha256() -> dict[str, str]:
    """Fail closed if any frozen Gemma input changes or disappears."""
    verified: dict[str, str] = {}
    for name, (path, expected) in FROZEN_ARTIFACTS.items():
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            raise RuntimeError(
                f"Gemma artifact {name!r} SHA-256 differs: "
                f"expected {expected}, got {actual}"
            )
        verified[name] = actual
    return verified

_terminal_manifest_digest_source = (
    ROOT
    / "manifests"
    / "c7-d126-gemma31b-terminals-v1.blake3"
).read_text(encoding="ascii")
if (
    len(_terminal_manifest_digest_source) != 65
    or not _terminal_manifest_digest_source.endswith("\n")
    or any(
        character not in "0123456789abcdef"
        for character in _terminal_manifest_digest_source[:64]
    )
):
    raise RuntimeError(
        "Gemma-31B terminal-manifest sidecar is not 64 lowercase hex digits plus LF"
    )
TERMINAL_MANIFEST_BLAKE3 = _terminal_manifest_digest_source[:64]

EXPECTED_PROFILE: dict[str, object] = {
    "profile": "gemma4-31b-stacked-q357",
    "model": "google/gemma-4-31B",
    "revision": "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89",
    "terminal_manifest_blake3": TERMINAL_MANIFEST_BLAKE3,
    "source_metadata_sha256": FROZEN_ARTIFACTS["source_metadata"][1],
    "public_layer_scalars_sha256": FROZEN_ARTIFACTS["public_layer_scalars"][1],
    "workload_sha256": FROZEN_ARTIFACTS["workload"][1],
    "text_only": True,
    "config_sha256": "6a81841cad2b6ba06841e23c6afb5f0a27827bc12c64328ffa6338831a21267e",
    "model_index_sha256": "d4aff3b976d69c123a29d1c085d7ba4de1ac3f4ca1726a7f81e1b11462a64ea2",
    "shard_00001_sha256": "186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac",
    "shard_00001_file_bytes": 49_784_788_364,
    "shard_00002_sha256": "b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0",
    "shard_00002_file_bytes": 12_761_549_884,
    "safetensors_metadata_bytes": 62_546_177_752,
    "safetensors_framing_bytes": 160_496,
    "checkpoint_tensor_count": 1_188,
    "private_learned_tensor_count": 772,
    "public_layer_scalar_count": 60,
    "forbidden_vision_bridge_tensor_count": 356,
    "operational_context_cap": 4_096,
    "prompt_tokens": 100,
    "decode_tokens": 50,
    "live_tokens": 150,
    "kv_capacity_tokens": 4_096,
    "inference_batch_size": 1,
    "max_concurrent_responses_on_device": 1,
    "first_q": 357,
    "q_by_round": (357, 163, 152, 149, 149, 149, 149, 149),
    "w_segments": 472,
    "w_raw_terminals": 472,
    "b_segments": 4,
    "kv_old_segments": 2,
    "kv_new_segments": 2,
    "all_terminals": 480,
    "reducer_instances": 0,
    "product_triples": 480,
    "mask_alternative": 1,
}

GOLDILOCKS_MODULUS = (1 << 64) - (1 << 32) + 1
FP3_VALUE_BYTES = 24
BASE_CORRECTION_BYTES = 8

PACKED_W_BYTES = 61_394_690_560
KV_VALUES_PER_TOKEN = 450_560
I16_BYTES = 2
ROWFOLD_TOTAL_ARENA_CAP_BYTES = 6_442_450_944
STAGING_BYTES = 256_000_000
H100_CAP_BYTES = 80_000_000_000
SPECULATIVE_INCREMENTAL_CAP_BYTES = 2_000_000_000

Q_FS_GLOBAL = 1 << 64
RESPONSE_ATTEMPT_LIFETIME = 1 << 20
GEMMA_FOLD_WIDTHS = (4, 3, 3, 3, 4, 4, 4, 4)
GEMMA_INVERSE_RATE_EXPONENTS = (1, 4, 6, 8, 10, 13, 16, 19)
GEMMA_Q357 = (357, 163, 152, 149, 149, 149, 149, 149)
STACKED_PRODUCT_ROOTS = 480 + 2


def bits(error: Fraction) -> float:
    if error <= 0:
        raise ValueError("error probability must be positive")
    return math.log2(error.denominator) - math.log2(error.numerator)


def exact(error: Fraction) -> str:
    return f"{error.numerator}/{error.denominator}"


def security_report() -> dict[str, object]:
    """Exact q357 arithmetic; hypotheses stay separate from achieved credit."""
    q_multiplier = Q_FS_GLOBAL + 1
    field_cardinality = GOLDILOCKS_MODULUS**3
    query_error = q_multiplier * sum(
        (
            Fraction((1 << ell) + 1, 1 << (ell + 1)) ** q
            for ell, q in zip(
                GEMMA_INVERSE_RATE_EXPONENTS, GEMMA_Q357, strict=True
            )
        ),
        Fraction(),
    )
    # The padded rate-1/2 Gemma source starts at exponent 36.  Each fold
    # lowers the bad-value exponent by one.
    gap_error = q_multiplier * sum(
        (
            Fraction(width * (1 << (36 - round_index)), field_cardinality)
            for round_index, width in enumerate(GEMMA_FOLD_WIDTHS)
        ),
        Fraction(),
    )
    mask_cells_per_root = 1_841_329_152
    root_epochs = 256
    setup_seed_attempts = 2 * root_epochs
    mask_words_lifetime = 5_656_563_154_944
    mask_linear_control = Fraction(mask_words_lifetime, 1 << 128)
    rejection_failure = Fraction(
        setup_seed_attempts
        * mask_cells_per_root
        * ((1 << 32) - 1) ** 6,
        1 << 384,
    )
    plane_envelope = (
        query_error + gap_error + mask_linear_control + rejection_failure
    )

    # `prodBatch_sound_scalar` gives T+2 roots for an abstract fixed-prefix
    # batch: T=480 terminal products plus at most two roots in Delta.  The
    # expression below is only the budget reserved for the still-unproved
    # concrete Fp3/transcript/global-ROM bridge.
    stacked_product_q64_budget = Fraction(
        q_multiplier * STACKED_PRODUCT_ROOTS, field_cardinality
    )

    # The generic Lean theorem gives one root numerator per compatible cohort:
    # K + sum(d_i) + n + 2.  No Gemma cohort values exist yet, so expose only
    # the exact admission ceilings rather than inventing a concrete GKR term.
    base_gkr_single_slot_root_ceiling = field_cardinality // (
        q_multiplier * (1 << 110)
    )
    base_gkr_operator_class_root_ceiling = field_cardinality // (
        q_multiplier * (1 << 86)
    )

    # This is a fail-closed admission allocation, not achieved evidence.
    # Every residual response-local event must already include any applicable
    # Q_FS loss before it can consume one of these 64 slots.
    response_slot_classes = {
        "operator_compute": 16,
        "boundary_commitments": 8,
        "predecessor_successor_state": 8,
        "pcs_binding_privacy": 16,
        "extension_mac": 8,
        "sampling_range": 4,
        "serialization_order": 4,
    }
    response_terms = {
        name: Fraction(RESPONSE_ATTEMPT_LIFETIME * slots, 1 << 110)
        for name, slots in response_slot_classes.items()
    }
    residual_terms = {
        **response_terms,
        "hash": Fraction(1, 1 << 128),
        "production_pcg": Fraction(1, 1 << 128),
        "state_replay": Fraction(1, 1 << 120),
        "codec_transcript": Fraction(1, 1 << 128),
    }
    residual_cap = sum(residual_terms.values(), Fraction())

    cumulative: list[dict[str, object]] = []
    running = Fraction()
    for name, error in (
        ("W", plane_envelope),
        ("B", plane_envelope),
        ("KV-old", plane_envelope),
        ("KV-new", plane_envelope),
        ("stacked-product-Q64-budget", stacked_product_q64_budget),
        *residual_terms.items(),
    ):
        running += error
        used = float(running * (1 << 78))
        cumulative.append(
            {
                "after": name,
                "bits": bits(running),
                "used_78_budget_fraction": used,
                "remaining_78_budget_fraction": 1.0 - used,
            }
        )

    total = 4 * plane_envelope + stacked_product_q64_budget + residual_cap
    dyadic_contract_total = (
        4 * Fraction(1, 1 << 81) + stacked_product_q64_budget + residual_cap
    )
    target = Fraction(1, 1 << 78)
    gkr_direct_remaining_before = target - total
    gkr_direct_additional_root_ceiling = (
        gkr_direct_remaining_before * field_cardinality // q_multiplier
    )
    gkr_direct_error_at_ceiling = Fraction(
        q_multiplier * gkr_direct_additional_root_ceiling,
        field_cardinality,
    )
    gkr_direct_error_at_next = Fraction(
        q_multiplier * (gkr_direct_additional_root_ceiling + 1),
        field_cardinality,
    )
    total_with_gkr_direct_ceiling = total + gkr_direct_error_at_ceiling
    total_with_gkr_direct_next = total + gkr_direct_error_at_next
    assert plane_envelope < Fraction(1, 1 << 81)
    assert total < target
    assert dyadic_contract_total < target
    assert response_terms["operator_compute"] == Fraction(1, 1 << 86)
    assert gkr_direct_additional_root_ceiling == 722_784_653_514_375
    assert total_with_gkr_direct_ceiling < target
    assert total_with_gkr_direct_next >= target
    return {
        "q_fs_global": Q_FS_GLOBAL,
        "q_fs_multiplier": q_multiplier,
        "response_attempt_lifetime": RESPONSE_ATTEMPT_LIFETIME,
        "q_by_round": GEMMA_Q357,
        "inverse_rate_exponents": GEMMA_INVERSE_RATE_EXPONENTS,
        "fold_widths": GEMMA_FOLD_WIDTHS,
        "query_error_exact": exact(query_error),
        "query_bits": bits(query_error),
        "gap_error_exact": exact(gap_error),
        "gap_bits": bits(gap_error),
        "conditional_mask_linear_control_exact": exact(mask_linear_control),
        "conditional_mask_linear_control_bits": bits(mask_linear_control),
        "mask_rejection_error_exact": exact(rejection_failure),
        "mask_rejection_bits": bits(rejection_failure),
        "one_plane_envelope_exact": exact(plane_envelope),
        "one_plane_envelope_bits": bits(plane_envelope),
        "one_plane_dyadic_cap": "1/2^81",
        "required_each_plane_le_q357_envelope": True,
        "stacked_product_fixed_prefix_roots": STACKED_PRODUCT_ROOTS,
        "stacked_product_fixed_prefix_status": "PASS",
        "stacked_product_q64_budget_error_exact": exact(
            stacked_product_q64_budget
        ),
        "stacked_product_q64_budget_bits": bits(stacked_product_q64_budget),
        "stacked_product_q64_bridge_status": BLOCKED,
        "base_transformer_gkr_error": None,
        "base_transformer_gkr_bound": (
            "(2^64+1)*sum_c(K_c+sum_i(d_c[i])+n_c+2)/p^3"
        ),
        "base_transformer_gkr_qfs_lifetime_factor_once": True,
        "base_transformer_gkr_single_2^-110_slot_root_ceiling": (
            base_gkr_single_slot_root_ceiling
        ),
        "base_transformer_gkr_operator_compute_2^-86_root_ceiling": (
            base_gkr_operator_class_root_ceiling
        ),
        "base_transformer_gkr_emitted_root_numerator": None,
        "base_transformer_gkr_operator_compute_reserve_already_in_total": True,
        "base_transformer_gkr_operator_compute_reserved_error_exact": exact(
            response_terms["operator_compute"]
        ),
        "base_transformer_gkr_direct_additional_margin_semantics": (
            "extra headroom after the current conditional total, which already "
            "contains the 2^-86 operator_compute reserve"
        ),
        "base_transformer_gkr_direct_additional_root_ceiling": (
            gkr_direct_additional_root_ceiling
        ),
        "base_transformer_gkr_direct_additional_error_at_ceiling_exact": exact(
            gkr_direct_error_at_ceiling
        ),
        "base_transformer_gkr_direct_remaining_before_exact": exact(
            gkr_direct_remaining_before
        ),
        "base_transformer_gkr_direct_remaining_after_ceiling_exact": exact(
            target - total_with_gkr_direct_ceiling
        ),
        "conditional_total_plus_gkr_direct_ceiling_error_exact": exact(
            total_with_gkr_direct_ceiling
        ),
        "conditional_total_plus_gkr_direct_ceiling_below_78": True,
        "conditional_total_plus_gkr_direct_next_error_exact": exact(
            total_with_gkr_direct_next
        ),
        "conditional_total_plus_gkr_direct_next_below_78": False,
        "base_transformer_gkr_status": BLOCKED,
        "response_slot_classes": response_slot_classes,
        "residual_terms_exact": {
            name: exact(error) for name, error in residual_terms.items()
        },
        "conditional_total_error_exact": exact(total),
        "conditional_total_bits": bits(total),
        "dyadic_contract_total_error_exact": exact(dyadic_contract_total),
        "dyadic_contract_total_bits": bits(dyadic_contract_total),
        "dyadic_contract_remaining_78_budget_fraction": float(
            (target - dyadic_contract_total) / target
        ),
        "target_bits": 78,
        "conditional_total_arithmetic_below_78": total < target,
        "realized_security_status": BLOCKED,
        "used_78_budget_fraction": float(total / target),
        "remaining_78_budget_fraction": float((target - total) / target),
        "cumulative_margin": cumulative,
        "required_unproved_premises": [
            "compiled B plane error is no larger than the q357 plane envelope",
            "compiled KV-old plane error is no larger than the q357 plane envelope",
            "compiled KV-new plane error is no larger than the q357 plane envelope",
            "keyed BLAKE3 satisfies the named linear multi-session control",
            "the concrete C7 Fp3 field has the intended p^3 challenge cardinality",
            "the concrete ProductClosure verifier refines prodBatch_sound_scalar",
            "the C7 transcript fixes product messages before chi and keeps them independent of Delta",
            "one classical-ROM Q_FS_global factor composes across every session, retry, abort, and local query",
            "all base-transformer GKR and PCS events fit the 64-slot response registry",
            "the runtime compiler consumes all 60 bound public layer-scalar "
            "values in the fixed-point relation",
            "every residual event includes its exact Q_FS, lifetime, abort, and retry scope",
            "hash, production PCG, state/replay, and codec bounds meet their allocations",
        ],
        "status": BLOCKED,
        "credit": False,
    }


def expected_profile() -> dict[str, object]:
    return copy.deepcopy(EXPECTED_PROFILE)


def validate_profile(profile: Mapping[str, object]) -> None:
    """Accept only the exact active Gemma-31B profile."""
    expected_keys = set(EXPECTED_PROFILE)
    actual_keys = set(profile)
    if actual_keys != expected_keys:
        missing = sorted(expected_keys - actual_keys)
        extra = sorted(actual_keys - expected_keys)
        raise ValueError(f"Gemma profile keys differ: missing={missing}, extra={extra}")

    for name, expected in EXPECTED_PROFILE.items():
        actual = profile[name]
        if type(actual) is not type(expected) or actual != expected:
            raise ValueError(
                f"Gemma profile field {name!r} differs: expected {expected!r}, got {actual!r}"
            )


def compact_merkle_max_siblings(leaves: int, opened: int) -> int:
    """Exact reserved frontier for largest-power-of-two-left compact trees.

    Maximizing siblings is equivalent to maximizing visited internal nodes:
    H = I + 1 - opened. Child optima have decreasing marginal gains; merge
    those gains and add the root once. Only `opened` gains are retained, not
    the tree. This counts authentication, not an output-pruned encoder.
    """
    if (type(leaves) is not int or type(opened) is not int
            or not 1 <= opened <= leaves):
        raise ValueError("invalid compact-tree reservation")

    def gains(count: int) -> list[int]:
        height = count.bit_length() - 1
        if count == 1 << height:
            return [height - (i - 1).bit_length()
                    for i in range(1, min(count, opened) + 1)]
        left = 1 << height
        merged = list(itertools.islice(
            heapq.merge(gains(left), gains(count - left), reverse=True), opened
        ))
        merged[0] += 1
        return merged

    return sum(gains(leaves)) + 1 - opened


def w_opening_reservation(profile: Mapping[str, object]) -> dict[str, object]:
    """Recompile only the frozen W subcodec, never the missing PCS proof.

    Separate leaf/frontier caps are reservations, not a claim that all maxima
    occur in one FS transcript. No historical budget/code is imported.
    """
    validate_profile(profile)
    remaining = (PACKED_W_BYTES // I16_BYTES - 1).bit_length()
    rows = []
    for index, (fold, rate, queries) in enumerate(zip(
        GEMMA_FOLD_WIDTHS, GEMMA_INVERSE_RATE_EXPONENTS,
        profile["q_by_round"], strict=True,
    )):
        limbs = 1 if index == 0 else 3
        oracle_limbs = (1 << (remaining + rate)) * limbs
        leaves = (oracle_limbs + 140) // 141
        block_limbs = (1 << fold) * limbs
        opened = min(leaves, queries * ((block_limbs + 280) // 141))
        visible = 141 * opened
        siblings = compact_merkle_max_siblings(leaves, opened)
        rows.append({
            "round": index, "queries": queries, "fold_width": fold,
            "oracle_fp_limbs": oracle_limbs, "logical_leaves": leaves,
            "full_oracle_payload_bytes": oracle_limbs * BASE_CORRECTION_BYTES,
            "dense_folded_message_fp3_bytes": (1 << (remaining - fold)) * FP3_VALUE_BYTES,
            "unstacked_fp_atoms": queries * block_limbs,
            "opened_leaves": opened, "visible_fp": visible,
            "merkle_siblings": siblings,
            "payload_bytes": BASE_CORRECTION_BYTES * visible,
            "salt_bytes": 32 * opened,
            "multiproof_bytes": 4 + 32 * siblings,
            "opening_frame_bytes": 16,
            "rederived_fold_challenge_bytes": 16 + FP3_VALUE_BYTES * fold,
        })
        remaining -= fold
    totals = {key: sum(row[key] for row in rows) for key in (
        "queries", "unstacked_fp_atoms", "opened_leaves", "visible_fp",
        "merkle_siblings", "payload_bytes", "salt_bytes", "multiproof_bytes",
        "opening_frame_bytes", "rederived_fold_challenge_bytes",
    )}
    fixed_records = {
        "codec_header": 16,
        "auxiliary_roots_and_frames": (len(rows) - 1) * (16 + 32),
        "tail_and_frame": 16 + (1 << remaining) * FP3_VALUE_BYTES,
        "terminal_adapter_and_frame": 16 + FP3_VALUE_BYTES,
    }
    prover_bytes = sum(fixed_records.values()) + sum(totals[key] for key in (
        "payload_bytes", "salt_bytes", "multiproof_bytes", "opening_frame_bytes",
    ))
    internal = totals["merkle_siblings"] + totals["opened_leaves"] - len(rows)
    return {
        "classification": "exact-subcodec-reservation-not-full-certificate",
        "rows": rows, "totals": totals, "fixed_records": fixed_records,
        "p_to_v_bytes": prover_bytes,
        "rederived_v_to_p_bytes": totals["rederived_fold_challenge_bytes"]
        + 16 + 4 * totals["queries"],
        "verifier_internal_hashes": internal,
        "verifier_hashes_including_opened_leaves": internal + totals["opened_leaves"],
        "complete_serializer_present": False,
        "joint_attainability_of_reservation_caps_claimed": False,
        "protocol_credit": False,
    }


def build_report(profile: Mapping[str, object] | None = None) -> dict[str, object]:
    selected = expected_profile() if profile is None else dict(profile)
    validate_profile(selected)
    artifact_sha256 = verified_artifact_sha256()
    assert selected["source_metadata_sha256"] == artifact_sha256["source_metadata"]
    assert (
        selected["public_layer_scalars_sha256"]
        == artifact_sha256["public_layer_scalars"]
    )
    assert selected["workload_sha256"] == artifact_sha256["workload"]
    workload = json.loads(FROZEN_ARTIFACTS["workload"][0].read_text(encoding="utf-8"))
    workload_lengths = workload["lengths"]
    assert selected["prompt_tokens"] == workload_lengths["prompt_tokens"]
    assert selected["decode_tokens"] == workload_lengths["decode_tokens"]
    assert selected["live_tokens"] == workload_lengths["live_tokens"]
    assert selected["kv_capacity_tokens"] == workload_lengths["context_capacity_tokens"]
    assert selected["kv_capacity_tokens"] == workload["padding"]["kv_capacity_tokens"]
    assert selected["live_tokens"] == (
        int(selected["prompt_tokens"]) + int(selected["decode_tokens"])
    )
    assert int(selected["live_tokens"]) < int(selected["operational_context_cap"])
    assert selected["kv_capacity_tokens"] == selected["operational_context_cap"]
    assert (
        int(selected["shard_00001_file_bytes"])
        + int(selected["shard_00002_file_bytes"])
        == int(selected["safetensors_metadata_bytes"])
        + int(selected["safetensors_framing_bytes"])
    )
    assert (
        int(selected["private_learned_tensor_count"])
        + int(selected["public_layer_scalar_count"])
        + int(selected["forbidden_vision_bridge_tensor_count"])
        == int(selected["checkpoint_tensor_count"])
    )

    w_reservation = w_opening_reservation(selected)
    w_totals = w_reservation["totals"]
    w_stream_p_to_v = w_reservation["p_to_v_bytes"]
    w_stream_v_to_p = w_reservation["rederived_v_to_p_bytes"]
    amended_fixed_w_p_to_v = 11_604
    amended_fixed_w_v_to_p = 120
    offline_fs_w_floor = w_stream_p_to_v + amended_fixed_w_p_to_v
    all_plane_authbind_extension = 24 * 8
    certificate_container = 376
    partial_certificate = (
        offline_fs_w_floor + all_plane_authbind_extension + certificate_container
    )
    frozen_small_reference = 3_466_188
    w_record_target_105 = 5_496_695
    w_record_cap = 6_543_685
    w_record_cap_150 = 7_852_422
    # Historical heuristic components are exposed, never filled in as records.
    proxy_components = {
        "W_subcodec_and_fixed_records": offline_fs_w_floor,
        "three_unselected_D31_B_KV_streams": 3 * 3_683_592,
        "illustrative_compute_base_GKR": 9_379_670,
        "illustrative_MAC_and_framing": 75_248,
    }
    four_plane_proxy = sum(proxy_components.values())

    visible_fp_per_attempt = w_totals["visible_fp"]
    response_attempt_reservations_per_root = 4_096
    lifecycle_load_reserve_equivalent_per_root = 512
    root_epochs = 256
    rootmask_dimension = 2_741_852_160
    mask_cells = (
        response_attempt_reservations_per_root
        + lifecycle_load_reserve_equivalent_per_root
    ) * visible_fp_per_attempt

    context_cap = int(selected["operational_context_cap"])
    kv_capacity_tokens = int(selected["kv_capacity_tokens"])
    kv_bytes = KV_VALUES_PER_TOKEN * I16_BYTES * kv_capacity_tokens
    terminal_product_bytes = int(selected["all_terminals"]) * FP3_VALUE_BYTES
    selected_w_plus_one_kv = PACKED_W_BYTES + kv_bytes
    conditional_subtotal = (
        selected_w_plus_one_kv
        + ROWFOLD_TOTAL_ARENA_CAP_BYTES
        + STAGING_BYTES
        + terminal_product_bytes
    )
    conditional_with_speculative = (
        conditional_subtotal + SPECULATIVE_INCREMENTAL_CAP_BYTES
    )

    return {
        "schema": SCHEMA,
        "scope": "Gemma-31B only; analytic static checks",
        "profile": selected,
        "artifacts": {
            "source_metadata_sha256": artifact_sha256["source_metadata"],
            "public_layer_scalars_sha256": artifact_sha256[
                "public_layer_scalars"
            ],
            "workload_sha256": artifact_sha256["workload"],
            "all_sha256_verified": True,
        },
        "workload": {
            "prompt_tokens": selected["prompt_tokens"],
            "decode_tokens": selected["decode_tokens"],
            "live_tokens": selected["live_tokens"],
            "operational_context_cap": context_cap,
            "kv_capacity_tokens": kv_capacity_tokens,
            "live_tokens_distinct_from_capacity": int(selected["live_tokens"])
            != kv_capacity_tokens,
            "live_tokens_within_context_cap": int(selected["live_tokens"])
            <= context_cap,
            "kv_allocation_uses_capacity_not_live_tokens": True,
        },
        "field": {
            "base": "Goldilocks",
            "modulus": GOLDILOCKS_MODULUS,
            "extension": "Fp[u]/(u^3-2)",
            "degree": 3,
            "value_bytes": FP3_VALUE_BYTES,
            "correction_bytes": BASE_CORRECTION_BYTES,
        },
        "census": {
            "text_only": selected["text_only"],
            "checkpoint_tensor_count": selected["checkpoint_tensor_count"],
            "private_learned_tensor_count": selected["private_learned_tensor_count"],
            "public_layer_scalar_count": selected["public_layer_scalar_count"],
            "forbidden_vision_bridge_tensor_count": selected[
                "forbidden_vision_bridge_tensor_count"
            ],
            "w_segments": selected["w_segments"],
            "w_raw_terminals": selected["w_raw_terminals"],
            "identity_terminals": (
                int(selected["b_segments"])
                + int(selected["kv_old_segments"])
                + int(selected["kv_new_segments"])
            ),
            "all_terminals": selected["all_terminals"],
            "reducer_instances": selected["reducer_instances"],
            "product_triples": selected["product_triples"],
            "known_fp3_correlations": 481,
            "known_w_fp3_correlations": 473,
            "known_base_field_slots": 1_443,
            "known_challenges_before_base_gkr_and_b_kv": 32,
            "non_gemma_or_legacy_profiles_reject": True,
        },
        "wire": {
            "w_subcodec_reservation": w_reservation,
            "q_open": w_totals["queries"],
            "unstacked_fp_atoms": w_totals["unstacked_fp_atoms"],
            "opened_leaves": w_totals["opened_leaves"],
            "visible_fp": visible_fp_per_attempt,
            "merkle_siblings": w_totals["merkle_siblings"],
            "verifier_internal_hashes": w_reservation["verifier_internal_hashes"],
            "verifier_hashes_including_opened_leaves": w_reservation[
                "verifier_hashes_including_opened_leaves"
            ],
            "q357_w_stream_p_to_v_bytes": w_stream_p_to_v,
            "q357_w_stream_v_to_p_bytes": w_stream_v_to_p,
            "fixed_outer_p_to_v_bytes": 11_796,
            "fixed_outer_v_to_p_bytes": 120,
            "fixed_outer_total_bytes": 11_916,
            "offline_fs_w_floor_bytes": offline_fs_w_floor,
            "w_record_cap_125_percent_bytes": w_record_cap,
            "w_record_target_105_percent_bytes": w_record_target_105,
            "w_record_cap_150_percent_bytes": w_record_cap_150,
            "w_record_target_105_margin_bytes": w_record_target_105
            - offline_fs_w_floor,
            "w_record_cap_margin_bytes": w_record_cap - offline_fs_w_floor,
            "w_record_cap_150_margin_bytes": w_record_cap_150
            - offline_fs_w_floor,
            "partial_certificate_bytes": partial_certificate,
            "frozen_small_reference_bytes": frozen_small_reference,
            "partial_growth_numerator": partial_certificate,
            "partial_growth_denominator": frozen_small_reference,
            "partial_to_frozen_reference_growth": partial_certificate
            / frozen_small_reference,
            "frozen_small_certificate_cap_bytes": 30_000_000,
            "frozen_small_reference_within_cap": frozen_small_reference
            <= 30_000_000,
            "gemma_full_certificate_cap_bytes": 100_000_000,
            "maximum_full_certificate_growth": 3,
            "partial_slice_within_gemma_cap": partial_certificate <= 100_000_000,
            "partial_slice_within_growth": partial_certificate
            <= 3 * frozen_small_reference,
            "four_plane_planning_proxy_bytes": four_plane_proxy,
            "proxy_components_bytes": proxy_components,
            "proxy_is_lower_or_upper_bound": False,
            "proxy_unknown_remainder_bytes": None,
            "full_certificate_30MB_target_bytes": 30_000_000,
            "conditional_30MB_allowance_after_partial_reservation_bytes": (
                30_000_000 - partial_certificate
            ),
            "full_growth_reference_bytes": None,
            "full_growth_ratio": None,
            "full_certificate_bytes": None,
            "missing": [
                "compiled B/KV streams",
                "stacked GKR records",
                "ROWFOLD PCS records",
                "QueryClose, receipts, and output records",
            ],
            "status": BLOCKED,
            "credit": False,
        },
        "masks": {
            "visible_fp_per_attempt": visible_fp_per_attempt,
            "response_attempt_reservations_per_root": response_attempt_reservations_per_root,
            "response_attempt_reservations_include_all_outcomes": True,
            "lifecycle_load_reserve_attempt_equivalent_per_root": (
                lifecycle_load_reserve_equivalent_per_root
            ),
            "root_epochs": root_epochs,
            "response_attempt_lifetime": RESPONSE_ATTEMPT_LIFETIME,
            "mask_cells": mask_cells,
            "rootmask_dimension": rootmask_dimension,
            "unused_cells": rootmask_dimension - mask_cells,
            "setup_bytes_unchanged": 92_587_558_592,
            "setup_hard_ratio": "2.10x",
            "setup_within_hard_ratio": 92_587_558_592 * 10
            <= PACKED_W_BYTES * 21,
            "refreshes": root_epochs - 1,
            "generator_bytes_per_root": 176_767_598_592,
            "missing": ["B/KV mask schedules", "adaptive multi-session PRG theorem"],
            "status": BLOCKED,
            "credit": False,
        },
        "h100": {
            "cap_bytes": H100_CAP_BYTES,
            "inference_batch_size": selected["inference_batch_size"],
            "max_concurrent_responses_on_device": selected[
                "max_concurrent_responses_on_device"
            ],
            "live_tokens": selected["live_tokens"],
            "kv_capacity_tokens": kv_capacity_tokens,
            "kv_allocation_uses_capacity_not_live_tokens": True,
            "packed_w_bytes": PACKED_W_BYTES,
            "one_kv_arena_bytes": kv_bytes,
            "rowfold_total_arena_cap_bytes": ROWFOLD_TOTAL_ARENA_CAP_BYTES,
            "rowfold_arena_admission": "conditional",
            "staging_bytes": STAGING_BYTES,
            "v_product_closure_vector_bytes": terminal_product_bytes,
            "v_is_one_physical_allocation": True,
            "selected_w_plus_one_kv_bytes": selected_w_plus_one_kv,
            "conditional_subtotal_if_selected_caps_hold_bytes": conditional_subtotal,
            "conditional_subtotal_lt_cap": conditional_subtotal < H100_CAP_BYTES,
            "conditional_subtotal_headroom_bytes": H100_CAP_BYTES
            - conditional_subtotal,
            "optional_speculative_incremental_cap_bytes": SPECULATIVE_INCREMENTAL_CAP_BYTES,
            "conditional_with_speculative_bytes": conditional_with_speculative,
            "conditional_with_speculative_lt_cap": conditional_with_speculative
            < H100_CAP_BYTES,
            "conditional_with_speculative_headroom_bytes": H100_CAP_BYTES
            - conditional_with_speculative,
            "peak_allocated_bytes": None,
            "missing_live_allocations": [
                "B",
                "mask stream buffers",
                "public layer-scalar, fixed-point LUT, and constant GPU buffers "
                "and liveness",
                "runtime compiler binding and liveness for the exact v vector",
                "all commitment chains",
                "stacked GKR",
                "activations",
                "CUDA/runtime modules",
                "allocator reserve and fragmentation",
                "selected-kernel workspaces",
                "runtime enforcement of one response at a time on the GPU",
            ],
            "status": BLOCKED,
            "credit": False,
        },
        "source_work": {
            "packed_source_bytes": PACKED_W_BYTES,
            "required_hbm_sweeps": 2,
            "required_two_sweep_bytes": 2 * PACKED_W_BYTES,
            "compiled_hbm_sweeps": None,
            "complexity_required": "C(N,q,h)=c_source*N+P(q,h)",
            "compiled_c_source": None,
            "compiled_P": None,
            "selected_dense_first_fold_control": {
                "retained_bytes": w_reservation["rows"][0]["dense_folded_message_fp3_bytes"],
                "arena_cap_bytes": ROWFOLD_TOTAL_ARENA_CAP_BYTES,
                "conditional_on": "retain every coefficient of the padded first-folded message as Fp3",
                "verdict": NO_GO,
            },
            "c_source_independent_of_q_and_N": None,
            "forbidden_terms": ["qN", "N log q", "N log N"],
            "rowfold_report_present": False,
            "output_pruned_implementation_present": False,
            "two_hbm_sweeps_status": BLOCKED,
            "complexity_bound_status": BLOCKED,
            "current_direct_qN_path": NO_GO,
            "credit": False,
        },
        "planning_estimates": {
            "classification": "owner-targets-not-predictions",
            "complete_cryptographic_path_present": False,
            "kernel_optimization_alone_suffices": False,
            "warm_resident_model": True,
            "prover_seconds_low": 45.0,
            "prover_seconds_high": 50.0,
            "complete_proof_bytes": 30_000_000,
            "verifier_four_core_seconds_low": 6.4,
            "verifier_four_core_seconds_high": 8.2,
            "storage_onboarding_seconds_once": 19.186,
            "confidence": "low",
            "measurement_credit": False,
            "measurement_boundaries": {
                "prover": "warm request admission through complete serialized certificate, including inference, response-local correlations and encoding",
                "proof": "all certificate records, openings, corrections, roots, framing and receipts; no component-only substitution",
                "verifier": "four-core local correlation preparation, complete parsing/hash/algebra and durable verdict; ACK may follow",
                "storage_once": "model-resident weight acquisition only; excludes connection/capacity setup, quantization, root refresh and network transfer",
                "root_refresh": "separate counted lifecycle cost; never free or hidden in the 19.186-second acquisition",
            },
            "required_measurements": [
                "fixed-point 16-bit H100 kernel throughput",
                "complete prover wall time",
                "complete serialized proof size",
                "four-core correlation-prepare-through-durable-verdict wall time",
            ],
            "status": BLOCKED,
        },
        "security": security_report(),
        "verdicts": {
            "SECURITY_78": BLOCKED,
            "SECURITY_84": NO_GO,
            "FS_Q64": BLOCKED,
            "MASK_LIFETIME": BLOCKED,
            "COMPLEXITY_BOUND": BLOCKED,
            "TWO_HBM_SWEEPS": BLOCKED,
            "EXACT_WIRE_CENSUS": BLOCKED,
            "FULL_CERTIFICATE": BLOCKED,
            "H100_STATIC_FIT": BLOCKED,
            "D126": BLOCKED,
        },
        "overall": {
            "static_known_slice_consistent": True,
            "admission_pass": False,
            "status": BLOCKED,
            "credit": False,
        },
    }


def main() -> None:
    print(json.dumps(build_report(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
