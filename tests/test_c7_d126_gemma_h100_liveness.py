from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "c7_d126_gemma_h100_liveness.py"


def load_module():
    spec = importlib.util.spec_from_file_location("c7_gemma_h100_liveness", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def allocation(
    allocation_id: str,
    category: str,
    allocated_bytes: int,
    live_from: str,
    live_until: str,
    *,
    storage_id: str | None = None,
    logical_bytes: int | None = None,
) -> dict[str, object]:
    return {
        "id": allocation_id,
        "category": category,
        "storage_id": storage_id or allocation_id,
        "logical_bytes": allocated_bytes if logical_bytes is None else logical_bytes,
        "allocated_bytes": allocated_bytes,
        "live_from": live_from,
        "live_until": live_until,
    }


def complete_synthetic_manifest() -> dict[str, object]:
    module = load_module()
    events = [
        "model_resident",
        "response_begin",
        "inference_begin",
        "inference_end",
        "rowfold_pass1_begin",
        "rowfold_pass1_end",
        "offline_challenges_ready",
        "rowfold_pass2_begin",
        "rowfold_pass2_end",
        "base_gkr_begin",
        "base_gkr_end",
        "product_closure_begin",
        "product_closure_end",
        "response_end",
        "model_release",
    ]
    v_count, v_width = 480, 24
    return {
        "schema": module.SCHEMA,
        "profile": module.expected_profile(),
        "workload": {
            "prompt_tokens": 2_048,
            "decode_tokens": 2_048,
            "total_tokens": 4_096,
            "synthetic": True,
        },
        "events": events,
        "inventories": {
            "b": ["b_arena"],
            "mask": ["mask_stream_buffer"],
            "public_constant": ["public_model_constants"],
            "commitment_chain": ["chain_arena"],
            "product_closure": ["product_scratch"],
            "base_gkr": ["base_gkr_scratch"],
            "activation": ["activation_arena"],
            "workspace": ["gemm_workspace", "proof_workspace"],
        },
        "v_definition": {
            "allocation_id": "v",
            "meaning": "ordered ProductClosure terminal vector",
            "producer_event": "rowfold_pass2_end",
            "consumer_events": ["product_closure_begin", "product_closure_end"],
            "element_type": "Goldilocks-Fp3-canonical",
            "element_count": v_count,
            "element_bytes": v_width,
            "terminal_manifest_blake3": module.TERMINAL_MANIFEST_BLAKE3,
            "excludes": sorted(module.REQUIRED_V_EXCLUDES),
        },
        "derived_zero_allocations": {
            "use_reducer": {
                "instances": 0,
                "allocated_bytes": 0,
                "basis": "480 declared use axes each have length one",
            }
        },
        "prohibitions": {
            "spill_bytes": 0,
            "second_packed_w_copy_bytes": 0,
            "full_codeword_bytes": 0,
            "qN_workspace_bytes": 0,
            "N_log_q_workspace_bytes": 0,
            "N_log_N_workspace_bytes": 0,
            "unregistered_device_bytes": 0,
            "packed_w_hbm_sweeps": 2,
        },
        "allocations": [
            allocation(
                "packed_w", "packed_w", 61_394_690_560,
                "model_resident", "model_release",
            ),
            allocation(
                "kv_arena", "kv_arena", module.kv_arena_bytes(),
                "response_begin", "response_end",
            ),
            allocation(
                "v", "v", v_count * v_width,
                "rowfold_pass2_end", "response_end",
            ),
            allocation(
                "staging", "staging", 256_000_000,
                "response_begin", "response_end",
            ),
            allocation(
                "rowfold_arena", "rowfold", 6_000_000_000,
                "rowfold_pass1_begin", "base_gkr_begin",
            ),
            allocation(
                "cuda_runtime", "cuda_runtime", 300_000_000,
                "model_resident", "model_release",
            ),
            allocation(
                "allocator_reserve", "allocator_reserve", 200_000_000,
                "model_resident", "model_release",
            ),
            allocation(
                "public_model_constants", "public_constant", 1_000_000,
                "model_resident", "model_release",
            ),
            allocation(
                "b_arena", "b", 50_000_000,
                "inference_begin", "product_closure_begin",
            ),
            allocation(
                "mask_stream_buffer", "mask", 64_000_000,
                "rowfold_pass1_begin", "response_end",
            ),
            allocation(
                "chain_arena", "commitment_chain", 30_000_000,
                "rowfold_pass2_begin", "response_end",
            ),
            allocation(
                "product_scratch", "product_closure", 100_000_000,
                "product_closure_begin", "response_end",
            ),
            allocation(
                "base_gkr_scratch", "base_gkr", 250_000_000,
                "base_gkr_begin", "product_closure_begin",
            ),
            allocation(
                "activation_arena", "activation", 400_000_000,
                "inference_begin", "rowfold_pass1_begin",
                storage_id="shared_ephemeral",
            ),
            allocation(
                "gemm_workspace", "workspace", 256_000_000,
                "inference_begin", "inference_end",
            ),
            allocation(
                "proof_workspace", "workspace", 400_000_000,
                "base_gkr_begin", "response_end",
                storage_id="shared_ephemeral",
            ),
        ],
        "aliases": [
            {
                "storage_id": "shared_ephemeral",
                "allocation_ids": ["activation_arena", "proof_workspace"],
            }
        ],
    }


def find_allocation(manifest: dict[str, object], allocation_id: str) -> dict[str, object]:
    return next(row for row in manifest["allocations"] if row["id"] == allocation_id)


def test_repository_values_are_blocked_without_implicit_zeroes() -> None:
    module = load_module()
    report = module.evaluate_manifest(None)

    assert module.TERMINAL_MANIFEST_BLAKE3_SIDECAR.read_text(encoding="ascii") == (
        module.TERMINAL_MANIFEST_BLAKE3 + "\n"
    )
    assert module.kv_arena_bytes() == (
        2 * (50 * 16 * 256 + 10 * 4 * 512) * 4_096 * 2
    ) == 3_690_987_520
    assert report["status"] == "BLOCKED"
    assert report["H100_STATIC_FIT"] == "BLOCKED"
    assert report["credit"] is False
    assert report["known"]["packed_w_bytes"] == 30_697_345_280 * 2
    assert report["known"]["raw_bf16_multimodal_metadata_bytes_excluded"] == 62_546_177_752
    profile = module.expected_profile()
    assert profile["shard_00001_file_bytes"] + profile["shard_00002_file_bytes"] == (
        profile["raw_bf16_multimodal_metadata_bytes"]
        + profile["safetensors_framing_bytes"]
    ) == 62_546_338_248
    assert profile["inference_batch_size"] == 1
    assert profile["max_concurrent_responses_on_device"] == 1
    assert (
        "compiler proof that v is the ordered 480-terminal vector and its liveness"
        in report["missing_mandatory_inputs"]
    )


def test_complete_synthetic_timeline_passes_structure_without_gate_credit() -> None:
    module = load_module()
    report = module.validate_manifest(complete_synthetic_manifest())

    assert report["status"] == "BLOCKED"
    assert report["structural_fixture_validation"] == "PASS"
    assert report["H100_STATIC_FIT"] == "BLOCKED"
    assert report["credit"] is False
    assert report["peak_allocated_bytes"] < 80_000_000_000
    assert report["headroom_bytes"] == 80_000_000_000 - report["peak_allocated_bytes"]
    assert report["physical_storage_count"] == report["allocation_count"] - 1
    assert report["measurement_credit"] is False


def test_base_gkr_must_precede_product_closure() -> None:
    module = load_module()
    manifest = complete_synthetic_manifest()
    events = manifest["events"]
    base_begin = events.index("base_gkr_begin")
    base_end = events.index("base_gkr_end")
    product_begin = events.index("product_closure_begin")
    product_end = events.index("product_closure_end")
    events[base_begin : product_end + 1] = [
        "product_closure_begin",
        "product_closure_end",
        "base_gkr_begin",
        "base_gkr_end",
    ]

    report = module.evaluate_manifest(manifest)
    assert report["status"] == "NO-GO"
    assert "lifecycle markers are out of order" in report["reason"]


def test_workload_must_fill_context_and_name_prompt_decode_split() -> None:
    module = load_module()

    missing = complete_synthetic_manifest()
    missing.pop("workload")
    assert module.evaluate_manifest(missing)["status"] == "BLOCKED"

    wrong_sum = complete_synthetic_manifest()
    wrong_sum["workload"]["decode_tokens"] -= 1
    assert module.evaluate_manifest(wrong_sum)["status"] == "NO-GO"

    concurrent = complete_synthetic_manifest()
    concurrent["profile"]["max_concurrent_responses_on_device"] = 2
    assert module.evaluate_manifest(concurrent)["status"] == "NO-GO"


@pytest.mark.parametrize(
    "field,value",
    [
        ("context_cap", 1_024),
        ("text_only", False),
        ("hidden_size", 2_048),
        ("layers", 12),
        ("q_by_round", [357]),
        ("w_terminals", 471),
        ("packed_w_bytes", 62_546_177_752),
        ("config_sha256", "0" * 64),
    ],
)
def test_non_active_or_raw_metadata_profile_is_no_go(field: str, value: object) -> None:
    module = load_module()
    manifest = complete_synthetic_manifest()
    manifest["profile"][field] = value

    report = module.evaluate_manifest(manifest)
    assert report["status"] == "NO-GO"
    assert field in report["reason"]


def test_missing_quantities_are_blocked_but_invalid_zero_is_no_go() -> None:
    module = load_module()
    missing = complete_synthetic_manifest()
    missing.pop("v_definition")
    assert module.evaluate_manifest(missing)["status"] == "BLOCKED"

    missing_category = complete_synthetic_manifest()
    missing_category["allocations"] = [
        row for row in missing_category["allocations"] if row["category"] != "base_gkr"
    ]
    assert module.evaluate_manifest(missing_category)["status"] == "BLOCKED"

    zero = complete_synthetic_manifest()
    find_allocation(zero, "base_gkr_scratch")["allocated_bytes"] = 0
    assert module.evaluate_manifest(zero)["status"] == "NO-GO"


def test_v_must_have_exact_shape_definition_and_full_liveness() -> None:
    module = load_module()
    wrong_shape = complete_synthetic_manifest()
    wrong_shape["v_definition"]["element_count"] = 481
    assert "exactly 480" in module.evaluate_manifest(wrong_shape)["reason"]

    wrong_type = complete_synthetic_manifest()
    wrong_type["v_definition"]["element_bytes"] = 24.0
    assert module.evaluate_manifest(wrong_type)["status"] == "NO-GO"

    wrong_manifest = complete_synthetic_manifest()
    wrong_manifest["v_definition"]["terminal_manifest_blake3"] = "0" * 64
    assert module.evaluate_manifest(wrong_manifest)["status"] == "NO-GO"

    produced_too_early = complete_synthetic_manifest()
    produced_too_early["v_definition"]["producer_event"] = "model_resident"
    assert module.evaluate_manifest(produced_too_early)["status"] == "NO-GO"

    ambiguous = complete_synthetic_manifest()
    ambiguous["v_definition"]["excludes"].remove("rowfold_arena")
    assert module.evaluate_manifest(ambiguous)["status"] == "NO-GO"

    dead_early = complete_synthetic_manifest()
    find_allocation(dead_early, "v")["live_until"] = "base_gkr_end"
    assert module.evaluate_manifest(dead_early)["status"] == "NO-GO"


@pytest.mark.parametrize(
    "allocation_id,live_until",
    [
        ("staging", "inference_end"),
        ("b_arena", "inference_end"),
        ("mask_stream_buffer", "rowfold_pass2_end"),
        ("chain_arena", "product_closure_begin"),
        ("activation_arena", "inference_end"),
    ],
)
def test_protocol_buffers_cannot_die_before_their_last_required_phase(
    allocation_id: str, live_until: str
) -> None:
    module = load_module()
    manifest = complete_synthetic_manifest()
    find_allocation(manifest, allocation_id)["live_until"] = live_until
    assert module.evaluate_manifest(manifest)["status"] == "NO-GO"


def test_aliases_must_be_declared_exclusive_and_equal_capacity() -> None:
    module = load_module()
    undeclared = complete_synthetic_manifest()
    undeclared["aliases"] = []
    assert module.evaluate_manifest(undeclared)["status"] == "NO-GO"

    overlap = complete_synthetic_manifest()
    find_allocation(overlap, "activation_arena")["live_until"] = "base_gkr_end"
    assert "overlap" in module.evaluate_manifest(overlap)["reason"]

    unequal = complete_synthetic_manifest()
    find_allocation(unequal, "proof_workspace")["allocated_bytes"] += 1
    assert "same capacity" in module.evaluate_manifest(unequal)["reason"]

    resident_alias = complete_synthetic_manifest()
    find_allocation(resident_alias, "cuda_runtime")["storage_id"] = "shared_ephemeral"
    resident_alias["aliases"][0]["allocation_ids"].append("cuda_runtime")
    assert module.evaluate_manifest(resident_alias)["status"] == "NO-GO"


@pytest.mark.parametrize(
    "field,value",
    [
        ("spill_bytes", 1),
        ("second_packed_w_copy_bytes", 1),
        ("full_codeword_bytes", 1),
        ("qN_workspace_bytes", 1),
        ("N_log_q_workspace_bytes", 1),
        ("N_log_N_workspace_bytes", 1),
        ("unregistered_device_bytes", 1),
        ("packed_w_hbm_sweeps", 3),
    ],
)
def test_every_forbidden_resource_is_no_go(field: str, value: int) -> None:
    module = load_module()
    manifest = complete_synthetic_manifest()
    manifest["prohibitions"][field] = value
    assert module.evaluate_manifest(manifest)["status"] == "NO-GO"


def test_second_weight_copy_rowfold_overflow_and_cap_equality_are_no_go() -> None:
    module = load_module()
    duplicate = complete_synthetic_manifest()
    duplicate["allocations"].append(
        allocation(
            "packed_w_copy", "packed_w", 61_394_690_560,
            "response_begin", "response_end",
        )
    )
    assert module.evaluate_manifest(duplicate)["status"] == "NO-GO"

    rowfold = complete_synthetic_manifest()
    find_allocation(rowfold, "rowfold_arena")["logical_bytes"] = 6_442_450_945
    find_allocation(rowfold, "rowfold_arena")["allocated_bytes"] = 6_442_450_945
    assert module.evaluate_manifest(rowfold)["status"] == "NO-GO"

    exact_cap = complete_synthetic_manifest()
    initial = module.validate_manifest(exact_cap)["peak_allocated_bytes"]
    allocator = find_allocation(exact_cap, "allocator_reserve")
    allocator["logical_bytes"] += 80_000_000_000 - initial
    allocator["allocated_bytes"] += 80_000_000_000 - initial
    report = module.evaluate_manifest(exact_cap)
    assert report["status"] == "NO-GO"
    assert "peak_allocated must be <80000000000" in report["reason"]


def test_use_reducer_zero_is_explicit_and_derived() -> None:
    module = load_module()
    missing = complete_synthetic_manifest()
    missing["derived_zero_allocations"] = {}
    assert module.evaluate_manifest(missing)["status"] == "BLOCKED"

    invented = complete_synthetic_manifest()
    invented["derived_zero_allocations"]["use_reducer"]["basis"] = "assumed"
    assert module.evaluate_manifest(invented)["status"] == "NO-GO"


def test_tamper_does_not_mutate_the_control_fixture() -> None:
    module = load_module()
    control = complete_synthetic_manifest()
    tampered = copy.deepcopy(control)
    find_allocation(tampered, "v")["logical_bytes"] = 0

    assert module.evaluate_manifest(tampered)["status"] == "NO-GO"
    assert module.validate_manifest(control)["status"] == "BLOCKED"
