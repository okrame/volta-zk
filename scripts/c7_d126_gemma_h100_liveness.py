#!/usr/bin/env python3
"""Fail-closed H100 liveness census for the active Gemma-31B profile.

This module deliberately has no dependency on an older protocol budget.  A
complete compiler-owned manifest may pass the structural test; with the
quantities currently present in the repository the result is BLOCKED.

``v`` is exactly the ordered ProductClosure terminal vector: 480 canonical
Fp3 values, hence 11,520 bytes.  It is one physical allocation, not a second
copy beside "terminal scalars".  Its producer, consumers, canonical terminal-
manifest BLAKE3 and liveness are mandatory inputs.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import NoReturn


SCHEMA = "volta-c7-d126-gemma31b-h100-liveness-v1"
PASS = "PASS"
BLOCKED = "BLOCKED"
NO_GO = "NO-GO"

H100_CAP_BYTES = 80_000_000_000
ROWFOLD_ARENA_CAP_BYTES = 6_442_450_944
FP3_BYTES = 24
I16_BYTES = 2
TERMINAL_MANIFEST_BLAKE3_SIDECAR = (
    Path(__file__).resolve().parents[1]
    / "manifests"
    / "c7-d126-gemma31b-terminals-v1.blake3"
)
_terminal_manifest_digest_source = TERMINAL_MANIFEST_BLAKE3_SIDECAR.read_text(
    encoding="ascii"
)
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

# Pinned Gemma-only facts.  KV is derived below; its byte total is not copied
# from another profile.
EXPECTED_PROFILE: dict[str, object] = {
    "model": "google/gemma-4-31B",
    "revision": "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89",
    "text_only": True,
    "config_sha256": "6a81841cad2b6ba06841e23c6afb5f0a27827bc12c64328ffa6338831a21267e",
    "model_index_sha256": "d4aff3b976d69c123a29d1c085d7ba4de1ac3f4ca1726a7f81e1b11462a64ea2",
    "shard_00001_sha256": "186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac",
    "shard_00001_file_bytes": 49_784_788_364,
    "shard_00002_sha256": "b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0",
    "shard_00002_file_bytes": 12_761_549_884,
    "checkpoint_tensor_count": 1_188,
    "private_learned_tensor_count": 772,
    "public_layer_scalar_count": 60,
    "forbidden_vision_bridge_tensor_count": 356,
    "context_cap": 4_096,
    "inference_batch_size": 1,
    "max_concurrent_responses_on_device": 1,
    "hidden_size": 5_376,
    "layers": 60,
    "local_layers": 50,
    "local_kv_heads": 16,
    "local_head_dim": 256,
    "global_layers": 10,
    "global_kv_heads": 4,
    "global_head_dim": 512,
    "global_k_eq_v": True,
    "kv_element_bytes": I16_BYTES,
    "packed_w_scalars": 30_697_345_280,
    "packed_w_bytes": 61_394_690_560,
    "raw_bf16_multimodal_metadata_bytes": 62_546_177_752,
    "safetensors_framing_bytes": 160_496,
    "q_by_round": [357, 163, 152, 149, 149, 149, 149, 149],
    "w_terminals": 472,
    "all_terminals": 480,
    "use_reducer_instances": 0,
}

FIXED_IDS = {
    "packed_w": "packed_w",
    "kv_arena": "kv_arena",
    "v": "v",
    "staging": "staging",
    "rowfold": "rowfold_arena",
    "cuda_runtime": "cuda_runtime",
    "allocator_reserve": "allocator_reserve",
}
INVENTORY_CATEGORIES = (
    "b",
    "mask",
    "public_constant",
    "commitment_chain",
    "product_closure",
    "base_gkr",
    "activation",
    "workspace",
)
ALL_CATEGORIES = set(FIXED_IDS) | set(INVENTORY_CATEGORIES)
NON_ALIASABLE = {
    "packed_w",
    "kv_arena",
    "public_constant",
    "cuda_runtime",
    "allocator_reserve",
}

TOP_KEYS = {
    "schema",
    "profile",
    "workload",
    "events",
    "inventories",
    "v_definition",
    "derived_zero_allocations",
    "prohibitions",
    "allocations",
    "aliases",
}
WORKLOAD_KEYS = {"prompt_tokens", "decode_tokens", "total_tokens", "synthetic"}
ALLOCATION_KEYS = {
    "id",
    "category",
    "storage_id",
    "logical_bytes",
    "allocated_bytes",
    "live_from",
    "live_until",
}
V_KEYS = {
    "allocation_id",
    "meaning",
    "producer_event",
    "consumer_events",
    "element_type",
    "element_count",
    "element_bytes",
    "terminal_manifest_blake3",
    "excludes",
}
PROHIBITION_KEYS = {
    "spill_bytes",
    "second_packed_w_copy_bytes",
    "full_codeword_bytes",
    "qN_workspace_bytes",
    "N_log_q_workspace_bytes",
    "N_log_N_workspace_bytes",
    "unregistered_device_bytes",
    "packed_w_hbm_sweeps",
}
REQUIRED_V_EXCLUDES = {
    "packed_w",
    "kv_arena",
    "b",
    "mask_buffers",
    "public_model_constants",
    "activations",
    "rowfold_arena",
    "cuda_runtime",
    "allocator_reserve",
    "kernel_workspaces",
}
class CensusError(ValueError):
    """Validation result with the gate status that caused it."""

    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = status


def _fail(status: str, message: str) -> NoReturn:
    raise CensusError(status, message)


def _mapping(value: object, where: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _fail(NO_GO, f"{where} must be an object")
    if not all(type(key) is str for key in value):
        _fail(NO_GO, f"{where} keys must be strings")
    return value


def _exact_keys(value: object, expected: set[str], where: str) -> Mapping[str, object]:
    row = _mapping(value, where)
    missing = sorted(expected - set(row))
    if missing:
        _fail(BLOCKED, f"{where} is missing mandatory fields: {missing}")
    extra = sorted(set(row) - expected)
    if extra:
        _fail(NO_GO, f"{where} has unregistered fields: {extra}")
    return row


def _positive_int(value: object, where: str) -> int:
    if type(value) is not int or value <= 0:
        _fail(NO_GO, f"{where} must be a positive integer")
    return value


def _zero_int(value: object, where: str) -> int:
    if type(value) is not int or value != 0:
        _fail(NO_GO, f"{where} must be the explicit integer zero")
    return value


def _string_list(value: object, where: str, *, nonempty: bool = True) -> list[str]:
    if not isinstance(value, list) or (nonempty and not value):
        _fail(BLOCKED, f"{where} must be a{' non-empty' if nonempty else ''} list")
    if any(type(item) is not str or not item for item in value):
        _fail(NO_GO, f"{where} must contain non-empty strings")
    if len(value) != len(set(value)):
        _fail(NO_GO, f"{where} contains duplicates")
    return value


def expected_profile() -> dict[str, object]:
    """Return an independent JSON-shaped copy of the only admitted profile."""
    return json.loads(json.dumps(EXPECTED_PROFILE))


def kv_arena_bytes() -> int:
    """Two i16 caches (K and V) for every local/global attention layer."""
    p = EXPECTED_PROFILE
    per_token = 2 * (
        int(p["local_layers"])
        * int(p["local_kv_heads"])
        * int(p["local_head_dim"])
        + int(p["global_layers"])
        * int(p["global_kv_heads"])
        * int(p["global_head_dim"])
    )
    return per_token * int(p["context_cap"]) * int(p["kv_element_bytes"])


def current_repository_report() -> dict[str, object]:
    """Report only what is known without inventing missing allocations."""
    return {
        "schema": SCHEMA,
        "status": BLOCKED,
        "H100_STATIC_FIT": BLOCKED,
        "credit": False,
        "cap_bytes": H100_CAP_BYTES,
        "known": {
            "config_sha256": EXPECTED_PROFILE["config_sha256"],
            "model_index_sha256": EXPECTED_PROFILE["model_index_sha256"],
            "shard_00001_sha256": EXPECTED_PROFILE["shard_00001_sha256"],
            "shard_00002_sha256": EXPECTED_PROFILE["shard_00002_sha256"],
            "terminal_manifest_blake3": TERMINAL_MANIFEST_BLAKE3,
            "raw_bf16_multimodal_metadata_bytes_excluded": EXPECTED_PROFILE[
                "raw_bf16_multimodal_metadata_bytes"
            ],
            "packed_w_bytes": EXPECTED_PROFILE["packed_w_bytes"],
            "kv_arena_bytes": kv_arena_bytes(),
            "rowfold_arena_cap_bytes": ROWFOLD_ARENA_CAP_BYTES,
            "staging_bytes": 256_000_000,
            "v_product_terminal_vector_bytes": (
                int(EXPECTED_PROFILE["all_terminals"]) * FP3_BYTES
            ),
            "text_only": True,
            "private_public_forbidden_tensor_partition": [772, 60, 356],
        },
        "missing_mandatory_inputs": [
            "compiler proof that v is the ordered 480-terminal vector and its liveness",
            "B buffers",
            "mask stream buffers",
            "public layer-scalar values/digest and all fixed-point LUT/constant buffers",
            "all commitment-chain buffers",
            "ProductClosure working buffers",
            "base-GKR buffers",
            "ROWFOLD arena actual allocation and liveness",
            "all activation buffers",
            "CUDA/runtime allocation",
            "allocator reserve and fragmentation",
            "every selected-kernel workspace",
            "one complete ordered event timeline and alias proof",
            "pinned prompt/decode workload and runtime enforcement of one GPU response at a time",
        ],
    }


def _validate_profile(value: object) -> None:
    row = _exact_keys(value, set(EXPECTED_PROFILE), "profile")
    for name, expected in EXPECTED_PROFILE.items():
        actual = row[name]
        if type(actual) is not type(expected) or actual != expected:
            _fail(
                NO_GO,
                f"profile.{name} differs from active Gemma-31B: "
                f"expected {expected!r}, got {actual!r}",
            )
    if int(row["packed_w_scalars"]) * I16_BYTES != row["packed_w_bytes"]:
        _fail(NO_GO, "packed W is not the pinned i16 scalar count")
    if int(row["local_layers"]) + int(row["global_layers"]) != row["layers"]:
        _fail(NO_GO, "local/global layers do not sum to 60")
    if (
        int(row["private_learned_tensor_count"])
        + int(row["public_layer_scalar_count"])
        + int(row["forbidden_vision_bridge_tensor_count"])
        != row["checkpoint_tensor_count"]
    ):
        _fail(NO_GO, "private/public/forbidden tensors do not cover the checkpoint")
    if (
        int(row["shard_00001_file_bytes"])
        + int(row["shard_00002_file_bytes"])
        != int(row["raw_bf16_multimodal_metadata_bytes"])
        + int(row["safetensors_framing_bytes"])
    ):
        _fail(NO_GO, "pinned shard bytes do not reconcile with metadata plus framing")


def _validate_events(value: object) -> tuple[list[str], dict[str, int]]:
    events = _string_list(value, "events")
    required = {
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
    }
    missing = sorted(required - set(events))
    if missing:
        _fail(BLOCKED, f"events is missing lifecycle markers: {missing}")
    if events[0] != "model_resident" or events[-1] != "model_release":
        _fail(NO_GO, "timeline must start at model_resident and end at model_release")
    index = {name: i for i, name in enumerate(events)}
    ordered = (
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
    )
    if [index[name] for name in ordered] != sorted(index[name] for name in ordered):
        _fail(NO_GO, "the inference/proof lifecycle markers are out of order")
    for begin, end in (
        ("response_begin", "response_end"),
        ("inference_begin", "inference_end"),
        ("base_gkr_begin", "base_gkr_end"),
        ("product_closure_begin", "product_closure_end"),
    ):
        if index[begin] >= index[end]:
            _fail(NO_GO, f"{begin} must precede {end}")
    response_begin = index["response_begin"]
    response_end = index["response_end"]
    for name in required - {"model_resident", "model_release", "response_begin", "response_end"}:
        if not response_begin < index[name] < response_end:
            _fail(NO_GO, f"{name} must be inside the response lifetime")
    return events, index


def _validate_workload(value: object) -> Mapping[str, object]:
    row = _exact_keys(value, WORKLOAD_KEYS, "workload")
    prompt = _positive_int(row["prompt_tokens"], "workload.prompt_tokens")
    decode = _positive_int(row["decode_tokens"], "workload.decode_tokens")
    total = _positive_int(row["total_tokens"], "workload.total_tokens")
    if prompt + decode != total:
        _fail(NO_GO, "workload prompt plus decode tokens must equal total_tokens")
    if total != EXPECTED_PROFILE["context_cap"]:
        _fail(NO_GO, "the static peak workload must fill the 4,096-token context cap")
    if type(row["synthetic"]) is not bool:
        _fail(NO_GO, "workload.synthetic must explicitly be true or false")
    return row


def _validate_inventories(value: object) -> dict[str, list[str]]:
    row = _exact_keys(value, set(INVENTORY_CATEGORIES), "inventories")
    inventories = {
        category: _string_list(row[category], f"inventories.{category}")
        for category in INVENTORY_CATEGORIES
    }
    all_ids = [item for values in inventories.values() for item in values]
    if len(all_ids) != len(set(all_ids)):
        _fail(NO_GO, "one allocation id occurs in multiple inventories")
    if set(all_ids) & set(FIXED_IDS.values()):
        _fail(NO_GO, "an inventory id shadows a fixed allocation id")
    return inventories


def _validate_v(value: object, event_index: Mapping[str, int]) -> Mapping[str, object]:
    row = _exact_keys(value, V_KEYS, "v_definition")
    if row["allocation_id"] != FIXED_IDS["v"]:
        _fail(NO_GO, "v_definition must name the unique v allocation")
    if row["meaning"] != "ordered ProductClosure terminal vector":
        _fail(NO_GO, "v must mean exactly the ordered ProductClosure terminal vector")
    if row["producer_event"] != "rowfold_pass2_end":
        _fail(NO_GO, "v must be produced exactly at rowfold_pass2_end")
    consumers = _string_list(row["consumer_events"], "v_definition.consumer_events")
    if consumers != ["product_closure_begin", "product_closure_end"]:
        _fail(NO_GO, "v must name both ordered ProductClosure consumer events")
    if row["element_type"] != "Goldilocks-Fp3-canonical":
        _fail(NO_GO, "v elements must be canonical Goldilocks Fp3 values")
    if (
        type(row["element_count"]) is not int
        or row["element_count"] != EXPECTED_PROFILE["all_terminals"]
    ):
        _fail(NO_GO, "v must contain exactly 480 terminal values")
    if type(row["element_bytes"]) is not int or row["element_bytes"] != FP3_BYTES:
        _fail(NO_GO, "each v element must occupy exactly 24 bytes")
    if row["terminal_manifest_blake3"] != TERMINAL_MANIFEST_BLAKE3:
        _fail(NO_GO, "v must bind the canonical 480-terminal manifest BLAKE3")
    excludes = set(_string_list(row["excludes"], "v_definition.excludes"))
    if excludes != REQUIRED_V_EXCLUDES:
        _fail(NO_GO, "v exclusions do not exactly separate all other memory classes")
    if event_index[str(row["producer_event"])] > min(event_index[x] for x in consumers):
        _fail(NO_GO, "v is consumed before it is produced")
    return row


def _validate_zeroes(value: object) -> None:
    row = _exact_keys(value, {"use_reducer"}, "derived_zero_allocations")
    proof = _exact_keys(
        row["use_reducer"], {"instances", "allocated_bytes", "basis"},
        "derived_zero_allocations.use_reducer",
    )
    _zero_int(proof["instances"], "use reducer instances")
    _zero_int(proof["allocated_bytes"], "use reducer allocated bytes")
    if proof["basis"] != "480 declared use axes each have length one":
        _fail(NO_GO, "use-reducer zero lacks the active-profile derivation")


def _validate_prohibitions(value: object) -> None:
    row = _exact_keys(value, PROHIBITION_KEYS, "prohibitions")
    for name in PROHIBITION_KEYS - {"packed_w_hbm_sweeps"}:
        _zero_int(row[name], f"prohibitions.{name}")
    if type(row["packed_w_hbm_sweeps"]) is not int or row["packed_w_hbm_sweeps"] != 2:
        _fail(NO_GO, "the proof must use exactly two packed-W HBM sweeps")


def _validate_allocations(
    value: object,
    event_index: Mapping[str, int],
    inventories: Mapping[str, list[str]],
    v_definition: Mapping[str, object],
) -> tuple[list[dict[str, object]], dict[str, tuple[int, int]]]:
    if not isinstance(value, list) or not value:
        _fail(BLOCKED, "allocations must be a non-empty caller-declared list")
    rows: list[dict[str, object]] = []
    intervals: dict[str, tuple[int, int]] = {}
    for offset, raw in enumerate(value):
        row = dict(_exact_keys(raw, ALLOCATION_KEYS, f"allocations[{offset}]"))
        allocation_id = row["id"]
        category = row["category"]
        if type(allocation_id) is not str or not allocation_id:
            _fail(NO_GO, f"allocations[{offset}].id must be a non-empty string")
        if allocation_id in intervals:
            _fail(NO_GO, f"duplicate allocation id {allocation_id!r}")
        if type(category) is not str or category not in ALL_CATEGORIES:
            _fail(NO_GO, f"allocation {allocation_id!r} has unknown category {category!r}")
        if type(row["storage_id"]) is not str or not row["storage_id"]:
            _fail(NO_GO, f"allocation {allocation_id!r} has no storage_id")
        logical = _positive_int(row["logical_bytes"], f"{allocation_id}.logical_bytes")
        allocated = _positive_int(row["allocated_bytes"], f"{allocation_id}.allocated_bytes")
        if logical > allocated:
            _fail(NO_GO, f"allocation {allocation_id!r} exceeds its physical capacity")
        start_name, end_name = row["live_from"], row["live_until"]
        if (
            type(start_name) is not str
            or type(end_name) is not str
            or start_name not in event_index
            or end_name not in event_index
        ):
            _fail(NO_GO, f"allocation {allocation_id!r} refers to an unknown event")
        start, end = event_index[str(start_name)], event_index[str(end_name)]
        if start >= end:
            _fail(NO_GO, f"allocation {allocation_id!r} has an empty/reversed lifetime")
        intervals[str(allocation_id)] = (start, end)
        rows.append(row)

    ids_by_category: dict[str, set[str]] = defaultdict(set)
    by_id = {str(row["id"]): row for row in rows}
    for row in rows:
        ids_by_category[str(row["category"])].add(str(row["id"]))
    for category, allocation_id in FIXED_IDS.items():
        actual_ids = ids_by_category[category]
        if len(actual_ids) > 1:
            _fail(NO_GO, f"category {category} has a forbidden second allocation")
        if actual_ids != {allocation_id}:
            _fail(BLOCKED, f"category {category} must have exactly allocation {allocation_id!r}")
    for category, expected_ids in inventories.items():
        if ids_by_category[category] != set(expected_ids):
            _fail(BLOCKED, f"category {category} does not cover its complete inventory")

    exact_bytes = {
        "packed_w": int(EXPECTED_PROFILE["packed_w_bytes"]),
        "kv_arena": kv_arena_bytes(),
        "v": int(EXPECTED_PROFILE["all_terminals"]) * FP3_BYTES,
        "staging": 256_000_000,
    }
    for allocation_id, expected in exact_bytes.items():
        row = by_id[allocation_id]
        if row["logical_bytes"] != expected:
            _fail(NO_GO, f"{allocation_id} must contain exactly {expected} logical bytes")
    rowfold = by_id[FIXED_IDS["rowfold"]]
    if int(rowfold["allocated_bytes"]) > ROWFOLD_ARENA_CAP_BYTES:
        _fail(NO_GO, "the total ROWFOLD arena exceeds 6,442,450,944 bytes")

    v = by_id[FIXED_IDS["v"]]
    expected_v = int(v_definition["element_count"]) * int(v_definition["element_bytes"])
    if v["logical_bytes"] != expected_v:
        _fail(NO_GO, "v bytes do not equal element_count * element_bytes")
    v_start, v_end = intervals[FIXED_IDS["v"]]
    used_at = [str(v_definition["producer_event"]), *v_definition["consumer_events"]]
    if any(not v_start <= event_index[event] < v_end for event in used_at):
        _fail(NO_GO, "v is not live at every declared producer/consumer event")

    first, last = 0, max(event_index.values())
    for allocation_id in ("packed_w", "cuda_runtime", "allocator_reserve"):
        if intervals[allocation_id] != (first, last):
            _fail(NO_GO, f"{allocation_id} must cover the complete resident lifetime")
    for allocation_id in inventories["public_constant"]:
        if intervals[allocation_id] != (first, last):
            _fail(NO_GO, f"public constant {allocation_id!r} must remain model-resident")
    response = (event_index["response_begin"], event_index["response_end"])
    if intervals["staging"] != response:
        _fail(NO_GO, "staging must cover the complete response lifetime")
    kv_start, kv_end = intervals["kv_arena"]
    if kv_start > response[0] or kv_end < response[1]:
        _fail(NO_GO, "the one KV arena must cover the complete response")
    row_start, row_end = intervals["rowfold_arena"]
    if (
        row_start > event_index["rowfold_pass1_begin"]
        or row_end <= event_index["rowfold_pass2_end"]
    ):
        _fail(NO_GO, "ROWFOLD arena is not live through both passes")
    for allocation_id in inventories["base_gkr"]:
        start, end = intervals[allocation_id]
        if start > event_index["base_gkr_begin"] or end <= event_index["base_gkr_end"]:
            _fail(NO_GO, f"base-GKR buffer {allocation_id!r} misses its active phase")
    for allocation_id in inventories["b"]:
        start, end = intervals[allocation_id]
        if start > event_index["inference_begin"] or end <= event_index["base_gkr_end"]:
            _fail(NO_GO, f"B buffer {allocation_id!r} misses inference/base-GKR use")
    for allocation_id in inventories["mask"]:
        start, end = intervals[allocation_id]
        if start > event_index["rowfold_pass1_begin"] or end < response[1]:
            _fail(NO_GO, f"mask buffer {allocation_id!r} misses proof/response use")
    for allocation_id in inventories["commitment_chain"]:
        start, end = intervals[allocation_id]
        if start > event_index["rowfold_pass2_begin"] or end < response[1]:
            _fail(NO_GO, f"commitment chain {allocation_id!r} misses closure/response use")
    for allocation_id in inventories["activation"]:
        start, end = intervals[allocation_id]
        if start > event_index["inference_begin"] or end <= event_index["inference_end"]:
            _fail(NO_GO, f"activation {allocation_id!r} misses the inference phase")
    for allocation_id in inventories["product_closure"] + ["v"]:
        start, end = intervals[allocation_id]
        if (
            start > event_index["product_closure_begin"]
            or end <= event_index["product_closure_end"]
        ):
            _fail(NO_GO, f"ProductClosure buffer {allocation_id!r} misses its active phase")
    return rows, intervals


def _validate_aliases(
    value: object,
    rows: Sequence[Mapping[str, object]],
    intervals: Mapping[str, tuple[int, int]],
) -> None:
    if not isinstance(value, list):
        _fail(BLOCKED, "aliases must be an explicit list, even when empty")
    by_storage: dict[str, list[Mapping[str, object]]] = defaultdict(list)
    for row in rows:
        by_storage[str(row["storage_id"])].append(row)
    shared = {storage: group for storage, group in by_storage.items() if len(group) > 1}

    declared: dict[str, set[str]] = {}
    for offset, raw in enumerate(value):
        alias = _exact_keys(raw, {"storage_id", "allocation_ids"}, f"aliases[{offset}]")
        storage = alias["storage_id"]
        if type(storage) is not str or not storage:
            _fail(NO_GO, f"aliases[{offset}].storage_id is invalid")
        if storage in declared:
            _fail(NO_GO, f"storage {storage!r} has duplicate alias declarations")
        declared[storage] = set(
            _string_list(alias["allocation_ids"], f"aliases[{offset}].allocation_ids")
        )

    if set(declared) != set(shared):
        _fail(NO_GO, "alias declarations do not exactly match shared physical storage")
    for storage, group in shared.items():
        ids = {str(row["id"]) for row in group}
        if declared[storage] != ids:
            _fail(NO_GO, f"alias group {storage!r} does not list every occupant")
        categories = {str(row["category"]) for row in group}
        if categories & NON_ALIASABLE:
            _fail(NO_GO, f"resident storage {storage!r} may not alias")
        capacities = {int(row["allocated_bytes"]) for row in group}
        if len(capacities) != 1:
            _fail(NO_GO, f"all aliases of {storage!r} must declare the same capacity")
        ordered = sorted((intervals[str(row["id"])], str(row["id"])) for row in group)
        for ((_, previous_end), previous_id), ((next_start, _), next_id) in zip(
            ordered, ordered[1:]
        ):
            if next_start < previous_end:
                _fail(NO_GO, f"aliases {previous_id!r}/{next_id!r} overlap")


def _timeline_report(
    events: Sequence[str], rows: Sequence[Mapping[str, object]], event_index: Mapping[str, int]
) -> tuple[list[dict[str, object]], int]:
    timeline: list[dict[str, object]] = []
    peak = 0
    for position, event in enumerate(events[:-1]):
        live = [
            row
            for row in rows
            if event_index[str(row["live_from"])] <= position < event_index[str(row["live_until"])]
        ]
        storage_bytes: dict[str, int] = {}
        for row in live:
            storage = str(row["storage_id"])
            size = int(row["allocated_bytes"])
            if storage in storage_bytes and storage_bytes[storage] != size:
                _fail(NO_GO, f"storage {storage!r} has inconsistent capacity")
            storage_bytes[storage] = size
        allocated = sum(storage_bytes.values())
        peak = max(peak, allocated)
        timeline.append(
            {
                "from": event,
                "until": events[position + 1],
                "allocated_bytes": allocated,
                "live_allocation_ids": sorted(str(row["id"]) for row in live),
                "live_storage_ids": sorted(storage_bytes),
            }
        )
    return timeline, peak


def validate_manifest(manifest: object) -> dict[str, object]:
    """Check one caller-supplied map's internal consistency.

    Completeness and realistic lower bounds require a compiler-owned inventory;
    this function deliberately returns ``BLOCKED`` even for a consistent map.
    """
    top = _exact_keys(manifest, TOP_KEYS, "manifest")
    if top["schema"] != SCHEMA:
        _fail(NO_GO, f"schema must be {SCHEMA!r}")
    _validate_profile(top["profile"])
    workload = _validate_workload(top["workload"])
    events, event_index = _validate_events(top["events"])
    inventories = _validate_inventories(top["inventories"])
    v_definition = _validate_v(top["v_definition"], event_index)
    _validate_zeroes(top["derived_zero_allocations"])
    _validate_prohibitions(top["prohibitions"])
    rows, intervals = _validate_allocations(
        top["allocations"], event_index, inventories, v_definition
    )
    _validate_aliases(top["aliases"], rows, intervals)
    timeline, peak = _timeline_report(events, rows, event_index)
    if peak >= H100_CAP_BYTES:
        _fail(NO_GO, f"peak_allocated must be <{H100_CAP_BYTES}, got {peak}")
    return {
        "schema": SCHEMA,
        "status": BLOCKED,
        "structural_fixture_validation": PASS,
        "H100_STATIC_FIT": BLOCKED,
        "credit": False,
        "cap_bytes": H100_CAP_BYTES,
        "peak_allocated_bytes": peak,
        "headroom_bytes": H100_CAP_BYTES - peak,
        "strictly_below_cap": True,
        "allocation_count": len(rows),
        "physical_storage_count": len({str(row["storage_id"]) for row in rows}),
        "kv_arena_bytes": kv_arena_bytes(),
        "workload": dict(workload),
        "timeline": timeline,
        "measurement_credit": False,
        "remaining_unblock": (
            "compiler-generated complete allocation artifact with measured "
            "allocated-byte values"
        ),
    }


def evaluate_manifest(manifest: object | None) -> dict[str, object]:
    """Return PASS/BLOCKED/NO-GO without converting omissions to zero."""
    if manifest is None:
        return current_repository_report()
    try:
        return validate_manifest(manifest)
    except CensusError as error:
        return {
            "schema": SCHEMA,
            "status": error.status,
            "H100_STATIC_FIT": error.status,
            "credit": False,
            "reason": str(error),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path)
    args = parser.parse_args()
    if args.manifest is None:
        report = current_repository_report()
    else:
        try:
            report = evaluate_manifest(json.loads(args.manifest.read_text()))
        except (OSError, json.JSONDecodeError) as error:
            report = {
                "schema": SCHEMA,
                "status": NO_GO,
                "H100_STATIC_FIT": NO_GO,
                "credit": False,
                "reason": f"cannot read canonical JSON manifest: {error}",
            }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
