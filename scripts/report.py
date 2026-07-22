#!/usr/bin/env python3
"""P7 report and GPU/communication budget model.

This is intentionally a reporting layer over benchmark JSONs. It does not
change proving parameters, transcript layout, PCS openings, or soundness
assumptions. PCS alternatives are projections from the checked
`MultiOpenProof::bytes()` formula.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import platform
import subprocess
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = REPO / "benchmarks" / "results"
P7_RHO_TARGETS = {"prefill": 10.0, "decode": 2.0}
P7B_REPORT_SCHEMA_VERSION = 6
P7B_CUDA_ABI_VERSION = 28
P7B_OFFICIAL_RESIDENT_TIMING_POLICY = "wall-only-counters"
P7B_OFFICIAL_SESSION_TIMING_METHOD = "wall-only-counters"
P7B_GATE_PROFILE = "runpod-a100-v1"
P7B_OFFICIAL_RAYON_THREADS = 8
P7B_PREFILL_CORE_GATE_S = 10.0
P7B_DECODE_MARGINAL_GATE_S = 4.0
P7B_SYNC_WALL_FRACTION_GATE = 0.02
P7B_H2D_GATE_BYTES = 100_000_000
P7B_RESPONSE_COMMUNICATION_ENVELOPE_BYTES = 200_000_000
P7B_TRANSCRIPT_REFERENCE_BYTES = 137_413_808
P7B_PCS_OPENING_REFERENCE_BYTES = 66_733_504
P7B_PACKED_LOGITS_REFERENCE_BYTES = 7_407_122
P7B_PACKED_RESPONSE_REFERENCE_BYTES = 144_820_930
FASE_D_POD_REPORT_SCHEMA_VERSION = 7
FASE_D_POD_GATE_PROFILE_V1 = "runpod-a100-realpcg-v1"
FASE_D_POD_GATE_PROFILE_V2 = "runpod-a100-realpcg-v2"
FASE_D_POD_SYNC_WALL_ABSOLUTE_GATE_S = 0.150
C3B_REPORT_SCHEMA_VERSION = 9
C3B_POD_GATE_PROFILE = "runpod-a100-realpcg-v3"
C3B_TRANSCRIPT_REFERENCE_BYTES = 105_717_632
C3B_PCS_OPENING_REFERENCE_BYTES = 43_273_888
C3B_PACKED_RESPONSE_GATE_BYTES = 115_000_000
C3B_L4_TRANSCRIPT_BYTES = 57_840
C3B_LIMBS = 3
C3B_RANGE_INSTANCES = 6
C3B_REAL_COMPARISONS = 2_512_850
C3B_PACKED_ENTRIES_PER_LIMB = (1 << 21) + (1 << 19)
C3B_PACKED_ENTRIES_TOTAL = C3B_LIMBS * C3B_PACKED_ENTRIES_PER_LIMB
C3B_L4_EMULT_INSTANCES = 157_705_530.0
C3B_L4_EMULT_CEILING = 260_000_000.0
C3B_EMULT_INSTANCES_TOTAL = 2_775_723_398.8
C3B_G2_POD_BASELINE_S = 4.911_634
C3B_G2_POD_CEILING_S = 5.648_379_1
T1_REPORT_SCHEMA_VERSION = 10
T1_POD_GATE_PROFILE = "runpod-a100-realpcg-v4"
T1_RESPONSE_GATE_BYTES = 85_000_000
T1_RESPONSE_REFERENCE_BYTES = 84_544_352
T1_AUTH_CORRECTION_REFERENCE_BYTES = 38_348_720
T1_EQ_REDUCER_TRANSCRIPT_BYTES = 22_848
T1_Q_BRIDGE_CORRECTION_BYTES = 672
T1_SUB_CORRS = 4_793_590
T1_FULL_CORRS = 181_933
T1_PROD_CLAIMS = 21_667
T1_ZERO_CLAIMS = 8_170
T1_EMULT_INSTANCES_TOTAL = 2_800_595_736.8
T1_EMULT_OTHER_TOTAL = 114_852_961.2
P7B_TIMING_STATISTIC = "upper median across measured repetitions"
P7B_COUNTER_STATISTIC = "maximum across measured sessions"
C1_REPORT_SCHEMA_VERSION = 3
C1_TRANSCRIPT_REFERENCE_BYTES = 129_119_408
C1_AUTH_CORRECTION_REFERENCE_BYTES = 59_545_008
C1_PCS_OPENING_REFERENCE_BYTES = 66_733_504
C1_PACKED_LOGITS_REFERENCE_BYTES = 7_407_122
C1_PACKED_RESPONSE_REFERENCE_BYTES = 136_526_530
C1_IDENTITY_SEAM_ALIAS_VALUES = 1_036_800
C1_SUB_CORR_REFERENCE = 7_443_126
C1_FULL_CORR_REFERENCE = 176_880
X4_V4_PROFILE = "x4-zkdeepfold-ud-e29-v4"
X4_V4_DESIGN_SHA256 = (
    "c963831373783504e855c6c9b54a4d1bf425206ccb68992c242c94290e1cf544"
)
X4_V4_SOUNDNESS_EXPRESSION = (
    "3320*(9/16)^111 + "
    "28522064267253/340282366762482138490186164457219031041"
)
X4_V4_SOUNDNESS_BITS = 80.25537016399041
X4_V4_SOUNDNESS_FLOOR_BITS = 78.809294874
X4_V4_PACKED_OPENING_BYTES = 2_615_414
X4_V4_PCS_BYTES = 2_683_236
X4_V4_RESPONSE_BYTES = 43_953_700
X4_V4_POD_PROFILE = "runpod-a100-x4-v1"
X4_V4_FROZEN_BASELINE_SHA256 = (
    "1383fa5d0a2eb9155f1ca76fe814238c04eaaa7aab965e10374b5f07d220bfb7"
)
X4_V4_MIGRATION_SHA256 = (
    "d7c73d7f74cbc226c768330582cebcaed02939eb7940111715da2fc3d87d2d5e"
)
X4_V4_NOTE6_SHA256 = (
    "8fef35aae0412c45556b37fbfba89c88041d9de8b3c9733ad65227daeb83b0c2"
)
X4_V4_SOURCE_FLOOR_BYTES = 31_923_699_712
X4_V4_PHYSICAL_ORACLE_BYTES = 76_948_701_184
X4_V4_COEFFICIENT_BYTES = 9_618_587_648
X4_V4_INNER_MERKLE_DIGESTS = 12_333_875_200
X4_V4_OUTER_MERKLE_DIGESTS = 2_318_401_531
X4_V4_MERKLE_BYTES = 468_872_855_392
X4_V4_MATERIALIZATION_BYTES = 545_821_556_576
X4_V4_RESPONSE_RECOMPUTE_BYTES = 1_091_643_113_152
X4_V4_PERSISTENT_COEFFICIENTS_ROOTS_BYTES = 9_618_587_808
X4_V4_MAX_CURRENT_COHORT_WORKING_SET_BYTES = 363_998_478_304
X4_V4_COUNTER_FAMILIES = [
    "frame_reject",
    "packed_schedule_reject",
    "packed_reconstruction_reject",
    "cohort_binding_reject",
    "slot_identity_reject",
    "early_query_reject",
    "accepted_unsealed_chain",
    "fold_query_bad",
    "claim_reduce_bad",
    "auth_link_bad",
    "response_zero_batch_bad",
    "pending_escape_reject",
    "target_eval_leak_reject",
    "correlation_view_reject",
    "epoch_reuse_reject",
    "delta_shift_attempt",
    "beta_collision_witness",
]
X4B_DESIGN_SHA256 = (
    "bc057e458041e8123e3ef065d22b74573bcb7238a8dcee239bccfa0e8ff6be01"
)
X4B_POD_PROFILE = "runpod-a100-x4b-v1"
X4B_QUERY_TAPE_BLAKE3 = (
    "3654af24af8a3e903e15db2bf25e0ec587d1bd774aaab433d1fb6e1064b3d299"
)
X4B_CPU_CANONICAL_BYTES = 460_324_760
X4B_CPU_HASH_CALLS = 5_242_879
X4B_CPU_GATE_BPS = 500_000_000.0
X4B_OPEN_CEILING_S = 1.50
X4B_VERIFY_CEILING_S = 0.25
X4B_COMMIT_CEILING_S = 15.0
X4B_DURABLE_BYTES = 86_567_288_992
X4B_FULL_INITIAL_CACHE_BYTES = 37_094_424_416
X4B_DEGRADED_INITIAL_CACHE_BYTES = 18_547_212_128
X4B_FULL_FOLD_CACHE_BYTES = 34_359_737_248
X4B_DEGRADED_FOLD_CACHE_BYTES = 17_179_868_192
X4B_DEVICE_BYTE_CEILING = 48 * 1024 * 1024 * 1024
X4B_MIN_VOLUME_BYTES = 150_000_000_000
X4B_BASELINE_RAM_BYTES = 128 * 1024 * 1024 * 1024

LAYER_PARAMS = {
    "rows": 1 << 10,
    "cols": 1 << 14,
    "pad": 512,
    "code_bits": 15,
    "n_queries": 200,
}
EMBED_PARAMS = {
    "rows": 1 << 13,
    "cols": 1 << 14,
    "pad": 512,
    "code_bits": 15,
    "n_queries": 200,
}


def git(args: list[str], default: str = "") -> str:
    try:
        out = subprocess.check_output(["git", *args], cwd=REPO, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return default
    return out.decode().strip()


def git_dirty() -> bool:
    try:
        out = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=REPO,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return True
    return bool(out)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    data["_path"] = str(path.relative_to(REPO))
    data["_mtime"] = path.stat().st_mtime
    return data


def load_results(results_dir: Path) -> list[dict[str, Any]]:
    return [load_json(p) for p in sorted(results_dir.glob("*.json"))]


def _x4_v4_cpu_result_valid(row: dict[str, Any]) -> bool:
    gate = row.get("gate")
    abba = row.get("abba")
    recompute = row.get("recompute_case")
    touched = row.get("touched_family")
    return (
        row.get("schema") == 2
        and row.get("milestone") == "X4-v4-CPU-synthetic"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("profile") == X4_V4_PROFILE
        and row.get("design_sha256") == X4_V4_DESIGN_SHA256
        and row.get("query_count") == 111
        and row.get("soundness_expression") == X4_V4_SOUNDNESS_EXPRESSION
        and row.get("soundness_bits") == X4_V4_SOUNDNESS_BITS
        and row.get("required_soundness_bits") == X4_V4_SOUNDNESS_FLOOR_BITS
        and row.get("soundness_resummed_new_terms") == 0
        and row.get("security_counter_inventory") == X4_V4_COUNTER_FAMILIES
        and isinstance(touched, list)
        and [case.get("touched_blocks") for case in touched] == [1, 2, 4, 8, 16]
        and all(case.get("accepted") is True for case in touched)
        and all(
            case.get("bytes", {}).get("closed_formula_total")
            == case.get("bytes", {}).get("serialized_total")
            for case in touched
        )
        and isinstance(recompute, dict)
        and recompute.get("policy") == "RecomputeOracleAndMerkle"
        and recompute.get("traffic", {}).get("recomputed_source_bytes_read", 0) > 0
        and recompute.get("traffic", {}).get("recomputed_oracle_bytes", 0) > 0
        and recompute.get("traffic", {}).get("recomputed_merkle_bytes", 0) > 0
        and row.get("recompute_matches_persisted_response") is True
        and isinstance(abba, dict)
        and abba.get("order") == "A/B/B/A"
        and abba.get("ceiling") == 1.05
        and abba.get("pass") is True
        and isinstance(gate, dict)
        and gate.get("g5_verdict") == "PASS"
        and gate.get("g6_verdict") == "PASS"
        and gate.get("overall_x4_verdict")
        == "NOT_EVALUATED_UNTIL_GPT2_MIGRATION_AND_A100_RECORDS"
    )


def validate_x4_v4_cpu_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4_v4_cpu_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4_v4_migration_result_valid(row: dict[str, Any]) -> bool:
    codec = row.get("codec")
    golden = row.get("golden_decode")
    historical = row.get("historical_records")
    gate = row.get("gate")
    return (
        row.get("schema") == 1
        and row.get("milestone") == "X4-v4-GPT2-migration"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("profile") == X4_V4_PROFILE
        and row.get("design_sha256") == X4_V4_DESIGN_SHA256
        and row.get("query_count") == 111
        and row.get("rate") == "1/8"
        and row.get("maximum_claim_union") == 3_320
        and row.get("soundness_expression") == X4_V4_SOUNDNESS_EXPRESSION
        and row.get("soundness_bits") == X4_V4_SOUNDNESS_BITS
        and row.get("soundness_floor_bits") == X4_V4_SOUNDNESS_FLOOR_BITS
        and row.get("soundness_resummed_new_terms") == 0
        and isinstance(codec, dict)
        and codec.get("opened_symbols") == 27_564
        and codec.get("all_real_sibling_digests") == 67_930
        and codec.get("packed_opening_frame") == X4_V4_PACKED_OPENING_BYTES
        and codec.get("summed_bytes") == X4_V4_PCS_BYTES
        and codec.get("serialized_bytes") == X4_V4_PCS_BYTES
        and isinstance(codec.get("encoded_sha256"), str)
        and len(codec["encoded_sha256"]) == 64
        and row.get("complete_pcs_bytes") == X4_V4_PCS_BYTES
        and row.get("g3_limit_bytes") == 4_000_000
        and row.get("g3_headroom_bytes") == 1_316_764
        and row.get("non_pcs_response_bytes") == 41_270_464
        and row.get("measured_response_bytes") == X4_V4_RESPONSE_BYTES
        and row.get("response_limit_bytes") == 45_270_464
        and row.get("response_headroom_bytes") == 1_316_764
        and row.get("correlations_gpt2_claim_reduction") == 2_208
        and row.get("correlations_gpt2_seam") == 106
        and row.get("correlations_gpt2_total") == 2_314
        and row.get("logical_first_oracle_floor_bytes") == 31_923_699_712
        and row.get("production_codec") is True
        and row.get("cryptographic_oracle_materialized") is False
        and isinstance(golden, dict)
        and golden.get("prompt_tokens") == 100
        and golden.get("decode_tokens") == 50
        and golden.get("checked") is True
        and golden.get("exact_match") is True
        and isinstance(historical, list)
        and len(historical) == 3
        and all(pin.get("unchanged") is True for pin in historical)
        and row.get("historical_rows_mutated") is False
        and isinstance(gate, dict)
        and gate.get("g3_communication", "").startswith("PASS")
        and gate.get("overall_x4") == "NOT EVALUATED UNTIL A100 RECORDS"
    )


def validate_x4_v4_migration_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4_v4_migration_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4_v4_pod_result_valid(row: dict[str, Any]) -> bool:
    machine = row.get("machine")
    frozen = row.get("frozen")
    inventory = row.get("physical_inventory")
    probes = row.get("production_commit_probe")
    streaming = row.get("informative_streaming_commit")
    recompute = row.get("informative_per_query_cohort_recompute")
    gpu = row.get("informative_gpu_assisted_streaming_commit")
    gate = row.get("gate")
    if not (
        row.get("schema") == 1
        and row.get("milestone") == "X4-v4-A100-production-record"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("pod_profile") == X4_V4_POD_PROFILE
        and row.get("protocol_or_parameter_change") is False
        and isinstance(machine, dict)
        and machine.get("provider") == "RunPod"
        and "A100-SXM4-80GB" in machine.get("gpu", "")
        and machine.get("rayon_threads") == 8
        and machine.get("timing_policy") == "wall-only+counters; no CUDA-event timing"
        and machine.get("memory_bytes", 0) > X4_V4_MAX_CURRENT_COHORT_WORKING_SET_BYTES
        and machine.get("persistent_volume_available_bytes", 0)
        > X4_V4_PERSISTENT_COEFFICIENTS_ROOTS_BYTES
        and isinstance(frozen, dict)
        and frozen.get("profile") == X4_V4_PROFILE
        and frozen.get("design_sha256") == X4_V4_DESIGN_SHA256
        and frozen.get("frozen_design_baseline_sha256")
        == X4_V4_FROZEN_BASELINE_SHA256
        and frozen.get("migration_sha256") == X4_V4_MIGRATION_SHA256
        and frozen.get("note6_sha256") == X4_V4_NOTE6_SHA256
        and frozen.get("rate") == "1/8"
        and frozen.get("query_count") == 111
        and frozen.get("maximum_claim_union") == 3_320
        and frozen.get("opened_symbols") == 27_564
        and frozen.get("real_sibling_digests") == 67_930
        and frozen.get("pcs_bytes") == X4_V4_PCS_BYTES
        and frozen.get("response_bytes") == X4_V4_RESPONSE_BYTES
        and frozen.get("soundness_expression") == X4_V4_SOUNDNESS_EXPRESSION
        and frozen.get("soundness_bits") == X4_V4_SOUNDNESS_BITS
        and frozen.get("soundness_floor_bits") == X4_V4_SOUNDNESS_FLOOR_BITS
        and frozen.get("soundness_new_terms") == 0
        and isinstance(inventory, dict)
        and inventory.get("source_equivalent_unpadded_floor_bytes")
        == X4_V4_SOURCE_FLOOR_BYTES
        and inventory.get("coefficient_bytes") == X4_V4_COEFFICIENT_BYTES
        and inventory.get("physical_padded_first_oracle_bytes")
        == X4_V4_PHYSICAL_ORACLE_BYTES
        and inventory.get("inner_merkle_digests") == X4_V4_INNER_MERKLE_DIGESTS
        and inventory.get("outer_merkle_digests") == X4_V4_OUTER_MERKLE_DIGESTS
        and inventory.get("merkle_digest_bytes") == X4_V4_MERKLE_BYTES
        and inventory.get("bytes_per_materialization") == X4_V4_MATERIALIZATION_BYTES
        and inventory.get("bytes_recomputed_per_response")
        == X4_V4_RESPONSE_RECOMPUTE_BYTES
        and inventory.get("persistent_coefficients_plus_roots_bytes")
        == X4_V4_PERSISTENT_COEFFICIENTS_ROOTS_BYTES
        and inventory.get("maximum_current_cohort_working_set_bytes")
        == X4_V4_MAX_CURRENT_COHORT_WORKING_SET_BYTES
        and isinstance(inventory.get("cohorts"), list)
        and [cohort.get("name") for cohort in inventory["cohorts"]]
        == [
            "Wext-mu26-global-tied-roles",
            "Wext-mu22-all-layers",
            "Wext-mu20-layers-and-position",
            "auxiliary-ell17",
            "auxiliary-ell16",
        ]
    ):
        return False
    return (
        isinstance(probes, list)
        and len(probes) == 4
        and [probe.get("role") for probe in probes]
        == ["warmup", "measured-1", "measured-2", "measured-3"]
        and all(probe.get("exact_cohort") == "Wext-mu26-global-tied-roles" for probe in probes)
        and all(probe.get("domain_log2") == 30 for probe in probes)
        and all(probe.get("present_slots") == 2 for probe in probes)
        and all(probe.get("structural_slots") == 2 for probe in probes)
        and all(probe.get("ceiling_s") == 15.0 for probe in probes)
        and all(probe.get("completed") is False for probe in probes)
        and all(probe.get("timed_out") is True for probe in probes)
        and all(probe.get("observed_wall_s", 0) >= 15.0 for probe in probes)
        and all(probe.get("h2d_bytes") == 0 for probe in probes)
        and all(probe.get("d2h_bytes") == 0 for probe in probes)
        and all(probe.get("peak_vram_bytes") == 0 for probe in probes)
        and isinstance(streaming, dict)
        and streaming.get("status")
        == "MEASURED_EXACT_AUX17_ANCHOR; FULL_FLOOR_BLOCKED_BY_G4_TIMEOUT"
        and streaming.get("warmup_count") == 1
        and streaming.get("measured_candidates") == 3
        and len(streaming.get("candidate_wall_s", [])) == 3
        and streaming.get("selected_upper_median_wall_s", 0) > 0
        and streaming.get("measured_first_oracle_bytes_per_candidate") == 33_554_432
        and streaming.get("measured_merkle_bytes_per_candidate") == 167_772_128
        and streaming.get("selected_first_oracle_bytes_per_s", 0) > 0
        and streaming.get("projected_unpadded_floor_wall_s_at_measured_rate", 0) > 0
        and streaming.get("projected_physical_padded_oracle_wall_s_at_measured_rate", 0) > 0
        and streaming.get("full_31_9gb_pass_completed") is False
        and isinstance(recompute, dict)
        and recompute.get("query_count_per_candidate") == 1
        and len(recompute.get("candidate_wall_s", [])) == 3
        and recompute.get("selected_upper_median_wall_s", 0) > 0
        and recompute.get("source_bytes_read_per_query") == 4_194_304
        and recompute.get("oracle_bytes_recomputed_per_query") == 33_554_432
        and recompute.get("merkle_bytes_recomputed_per_query") == 167_772_128
        and recompute.get("total_logical_bytes_per_query") == 205_520_864
        and recompute.get("root_checked") is True
        and isinstance(gpu, dict)
        and gpu.get("available") is False
        and gpu.get("measured") is False
        and isinstance(gate, dict)
        and gate.get("g1_lean", "").startswith("PASS")
        and gate.get("g2_full_production_correctness", "").startswith("NOT EVALUATED")
        and gate.get("g3_communication", "").startswith("PASS")
        and gate.get("g4_commit", "").startswith("FAIL")
        and gate.get("g4_open", "").startswith("NOT EVALUATED")
        and gate.get("g4_verify", "").startswith("NOT EVALUATED")
        and gate.get("g6_storage_traffic", "").startswith("NOT EVALUATED AS PASS")
        and gate.get("overall_x4")
        == "FAIL — conjunctive G4 commit gate failed; no threshold was relaxed"
    )


def validate_x4_v4_pod_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4_v4_pod_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4b_upper_median(values: list[float]) -> float:
    return sorted(values)[len(values) // 2]


def _x4b_close(left: Any, right: Any, tolerance: float = 1e-9) -> bool:
    return (
        isinstance(left, (int, float))
        and not isinstance(left, bool)
        and isinstance(right, (int, float))
        and not isinstance(right, bool)
        and math.isfinite(float(left))
        and math.isfinite(float(right))
        and abs(float(left) - float(right)) <= tolerance * max(1.0, abs(float(right)))
    )


def _x4b_open_policy_valid(
    row: Any,
    *,
    omitted: int,
    cache_bytes: int,
    saved_bytes: int,
    traffic: dict[str, int],
) -> bool:
    if not isinstance(row, dict):
        return False
    opens = row.get("candidate_open_wall_s")
    verifies = row.get("candidate_verify_wall_s")
    return (
        row.get("bottom_outer_levels_omitted") == omitted
        and row.get("logical_outer_cache_bytes") == cache_bytes
        and row.get("cache_bytes_saved_vs_full") == saved_bytes
        and row.get("warmup_count") == 1
        and isinstance(opens, list)
        and len(opens) >= 3
        and all(isinstance(value, (int, float)) and value > 0 for value in opens)
        and _x4b_close(row.get("selected_upper_median_open_wall_s"), _x4b_upper_median(opens))
        and row.get("open_ceiling_s") == X4B_OPEN_CEILING_S
        and row.get("open_pass")
        is (row.get("selected_upper_median_open_wall_s", math.inf) <= X4B_OPEN_CEILING_S)
        and isinstance(verifies, list)
        and len(verifies) >= 3
        and all(isinstance(value, (int, float)) and value > 0 for value in verifies)
        and _x4b_close(
            row.get("selected_upper_median_verify_wall_s"), _x4b_upper_median(verifies)
        )
        and row.get("verify_ceiling_s") == X4B_VERIFY_CEILING_S
        and row.get("verify_pass")
        is (row.get("selected_upper_median_verify_wall_s", math.inf) <= X4B_VERIFY_CEILING_S)
        and row.get("traffic_per_open") == traffic
        and row.get("encoded_bytes") == X4_V4_PACKED_OPENING_BYTES
        and isinstance(row.get("encoded_blake3"), str)
        and len(row["encoded_blake3"]) == 64
    )


def _x4b_local_result_valid(row: dict[str, Any]) -> bool:
    cpu = row.get("cpu_full_node_pipeline")
    sparse = row.get("sparse_artifacts")
    full = row.get("persisted_open_full_cache")
    degraded = row.get("persisted_open_ram_degraded")
    if not (
        row.get("schema") == 1
        and row.get("milestone") == "X4b-local-CPU-persisted-opening-preflight"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("profile") == X4_V4_PROFILE
        and row.get("pod_profile") == X4B_POD_PROFILE
        and row.get("design_sha256") == X4B_DESIGN_SHA256
        and row.get("source_policy") == "PersistedOracle (record eligible)"
        and row.get("audit_recompute_refused") is True
        and row.get("query_count") == 111
        and row.get("query_draws_blake3") == X4B_QUERY_TAPE_BLAKE3
        and isinstance(row.get("profile_digest"), str)
        and len(row["profile_digest"]) == 64
        and isinstance(cpu, dict)
    ):
        return False
    scope = cpu.get("measurement_scope", "")
    candidates = cpu.get("candidates")
    if not (
        all(word in scope for word in ("serialization", "allocations", "hash_many"))
        and cpu.get("pinned_workers") == 1
        and cpu.get("warmup_count") == 1
        and isinstance(candidates, list)
        and len(candidates) >= 5
        and cpu.get("measured_candidates") == len(candidates)
        and cpu.get("canonical_frame_bytes") == X4B_CPU_CANONICAL_BYTES
        and cpu.get("logical_oracle_bytes") == 33_554_432
        and cpu.get("hash_calls") == X4B_CPU_HASH_CALLS
        and cpu.get("gate_bytes_per_s_per_core") == X4B_CPU_GATE_BPS
        and cpu.get("local_gate_comparison_only") is True
        and isinstance(cpu.get("root_hex"), str)
        and len(cpu["root_hex"]) == 64
    ):
        return False
    walls: list[float] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            return False
        wall = candidate.get("wall_s")
        allocator = candidate.get("allocator")
        if not (
            isinstance(wall, (int, float))
            and wall > 0
            and _x4b_close(
                candidate.get("canonical_frame_bytes_per_s"), X4B_CPU_CANONICAL_BYTES / wall
            )
            and _x4b_close(candidate.get("hash_calls_per_s"), X4B_CPU_HASH_CALLS / wall)
            and isinstance(allocator, dict)
            and allocator.get("allocations", 0) > 0
            and allocator.get("reallocations", 0) > 0
            and allocator.get("cumulative_requested_bytes", 0) > 0
        ):
            return False
        walls.append(float(wall))
    selected_wall = _x4b_upper_median(walls)
    selected_bps = X4B_CPU_CANONICAL_BYTES / selected_wall
    cpu_pass = selected_bps >= X4B_CPU_GATE_BPS
    if not (
        _x4b_close(cpu.get("selected_upper_median_wall_s"), selected_wall)
        and _x4b_close(cpu.get("selected_canonical_frame_bytes_per_s"), selected_bps)
        and cpu.get("local_gate_met") is cpu_pass
        and isinstance(sparse, dict)
        and sparse.get("file_count") == 32
        and sparse.get("logical_bytes") == 94_128_570_240
        and sparse.get("allocated_bytes", -1) >= 0
    ):
        return False
    full_ok = _x4b_open_policy_valid(
        full,
        omitted=0,
        cache_bytes=X4B_FULL_INITIAL_CACHE_BYTES + X4B_FULL_FOLD_CACHE_BYTES,
        saved_bytes=0,
        traffic={
            "oracle_file_bytes_read": 875_328,
            "outer_cache_bytes_read": 1_930_304,
            "inner_trees_rebuilt": 6_720,
            "outer_frontier_leaves_rebuilt": 5_610,
            "outer_internal_nodes_rebuilt": 0,
        },
    )
    degraded_ok = _x4b_open_policy_valid(
        degraded,
        omitted=1,
        cache_bytes=X4B_DEGRADED_INITIAL_CACHE_BYTES + X4B_DEGRADED_FOLD_CACHE_BYTES,
        saved_bytes=35_727_081_344,
        traffic={
            "oracle_file_bytes_read": 1_737_728,
            "outer_cache_bytes_read": 1_756_992,
            "inner_trees_rebuilt": 17_552,
            "outer_frontier_leaves_rebuilt": 16_442,
            "outer_internal_nodes_rebuilt": 5_416,
        },
    )
    byte_identity = (
        isinstance(full, dict)
        and isinstance(degraded, dict)
        and full.get("encoded_blake3") == degraded.get("encoded_blake3")
        and row.get("full_and_degraded_openings_byte_identical") is True
    )
    expected_pass = cpu_pass and full_ok and degraded_ok and byte_identity
    return (
        full_ok
        and degraded_ok
        and byte_identity
        and row.get("local_pre_pod_gate_pass") is expected_pass
        and expected_pass
        and "125 GiB" in row.get("ram_guidance", "")
    )


def validate_x4b_local_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4b_local_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def _x4b_accelerator_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and row.get("timing_method") == "wall-only-counters"
        and row.get("phase_attribution_available") is False
        and row.get("timing_event_api_calls") == 0
        and row.get("timing_records") == 0
        and row.get("peak_device_bytes", X4B_DEVICE_BYTE_CEILING + 1)
        <= X4B_DEVICE_BYTE_CEILING
        and row.get("h2d_bytes", -1) >= 0
        and row.get("d2h_bytes", -1) >= 0
        and row.get("device_generated_bytes", -1) >= 0
        and row.get("device_zeroed_bytes", -1) >= 0
    )


def _x4b_initial_pass_valid(row: Any, *, retained: bool) -> bool:
    return (
        isinstance(row, dict)
        and isinstance(row.get("wall_s"), (int, float))
        and row["wall_s"] > 0
        and row.get("peak_rss_bytes", 0) > 0
        and isinstance(row.get("process_io"), dict)
        and _x4b_accelerator_valid(row.get("accelerator"))
        and isinstance(row.get("cohorts"), list)
        and len(row["cohorts"]) == 5
        and [cohort.get("name") for cohort in row["cohorts"]]
        == [
            "Wext-mu26-global-tied-roles",
            "Wext-mu22-all-layers",
            "Wext-mu20-layers-and-position",
            "auxiliary-ell17",
            "auxiliary-ell16",
        ]
        and row.get("totals", {}).get("coefficient_bytes_persisted") == 9_618_587_648
        and row.get("totals", {}).get("oracle_bytes_persisted") == 76_948_701_184
        and row.get("totals", {}).get("root_bytes_persisted") == 160
        and row.get("totals", {}).get("persistent_artifact_bytes") == X4B_DURABLE_BYTES
        and row.get("reconciliation_pass") is True
        and row.get("artifacts_retained") is retained
    )


def _x4b_isolated_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and isinstance(row.get("wall_s"), (int, float))
        and row["wall_s"] > 0
        and row.get("ceiling_s") == X4B_COMMIT_CEILING_S
        and _x4b_close(row.get("margin_s"), X4B_COMMIT_CEILING_S - row["wall_s"])
        and _x4b_close(
            row.get("margin_percent"),
            100.0 * (X4B_COMMIT_CEILING_S - row["wall_s"]) / X4B_COMMIT_CEILING_S,
        )
        and row.get("pass") is (row["wall_s"] <= X4B_COMMIT_CEILING_S)
        and row.get("reconciliation_pass") is True
        and _x4b_accelerator_valid(row.get("accelerator"))
        and isinstance(row.get("root_hex"), str)
        and len(row["root_hex"]) == 64
    )


def _x4b_response_candidate_valid(row: Any) -> bool:
    return (
        isinstance(row, dict)
        and row.get("accepted") is True
        and row.get("packed_opening_bytes") == X4_V4_PACKED_OPENING_BYTES
        and row.get("opened_symbols") == 27_564
        and row.get("real_sibling_digests") == 67_930
        and isinstance(row.get("seal_wall_s"), (int, float))
        and row["seal_wall_s"] > 0
        and isinstance(row.get("open_wall_s"), (int, float))
        and row["open_wall_s"] > 0
        and isinstance(row.get("verify_wall_s"), (int, float))
        and row["verify_wall_s"] > 0
        and row.get("g6_reconciliation_pass") is True
        and _x4b_accelerator_valid(row.get("accelerator_seal"))
        and row.get("metrics", {}).get("recomputed_source_bytes_read") == 0
        and row.get("metrics", {}).get("recomputed_oracle_bytes") == 0
        and row.get("metrics", {}).get("recomputed_merkle_bytes") == 0
        and row.get("metrics", {}).get("persisted_oracle_bytes_read", 0) > 0
    )


def _x4b_pod_result_valid(row: dict[str, Any]) -> bool:
    machine = row.get("machine")
    frozen = row.get("frozen")
    cache = row.get("cache_policy")
    correctness = row.get("correctness")
    full = row.get("full_pass_commit")
    isolated = row.get("isolated_wext_mu26_commit")
    artifacts = row.get("final_artifacts")
    opening = row.get("persisted_response")
    codec = row.get("codec_reference")
    gate = row.get("gate")

    def typed_sample_valid(item: Any) -> bool:
        return (
            isinstance(item, dict)
            and item.get("all_equal") is True
            and item.get("ntt_symbols_checked", 0) > 0
            and item.get("typed_inner_leaves_checked", 0) > 0
            and item.get("typed_inner_nodes_checked", 0) > 0
            and item.get("typed_inner_roots_checked") == 1
            and item.get("typed_outer_leaves_checked", 0) >= 8
            and item.get("outer_levels_checked", 0) > 0
        )
    if not (
        row.get("schema") == 1
        and row.get("milestone") == "X4b-A100-production-record"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("pod_profile") == X4B_POD_PROFILE
        and row.get("protocol_or_parameter_change") is False
        and row.get("audit_recompute_refused") is True
        and row.get("draw_before_complete_seal_rejected") is True
        and isinstance(machine, dict)
        and machine.get("provider") == "RunPod"
        and "A100-SXM4-80GB" in machine.get("gpu", "")
        and machine.get("rayon_threads") == 8
        and machine.get("timing_policy") == "wall-only+counters; no CUDA-event timing"
        and machine.get("persistent_volume_bytes", 0) >= X4B_MIN_VOLUME_BYTES
        and isinstance(frozen, dict)
        and frozen.get("design_sha256") == X4B_DESIGN_SHA256
        and frozen.get("migration_sha256") == X4_V4_MIGRATION_SHA256
        and frozen.get("amendment5_preflight_sha256")
        == "ba87722362c8825e13e02a6c563a436797ea852e09e1cebcf4a9265c6ce56499"
        and isinstance(frozen.get("local_preflight_sha256"), str)
        and len(frozen["local_preflight_sha256"]) == 64
        and frozen.get("profile") == X4_V4_PROFILE
        and frozen.get("rate") == "1/8"
        and frozen.get("query_count") == 111
        and frozen.get("maximum_claim_union") == 3_320
        and frozen.get("opened_symbols") == 27_564
        and frozen.get("real_sibling_digests") == 67_930
        and frozen.get("packed_opening_bytes") == X4_V4_PACKED_OPENING_BYTES
        and frozen.get("pcs_bytes") == X4_V4_PCS_BYTES
        and frozen.get("response_bytes") == X4_V4_RESPONSE_BYTES
        and frozen.get("soundness_expression") == X4_V4_SOUNDNESS_EXPRESSION
        and frozen.get("soundness_bits") == X4_V4_SOUNDNESS_BITS
        and frozen.get("soundness_floor_bits") == X4_V4_SOUNDNESS_FLOOR_BITS
        and frozen.get("soundness_new_terms") == 0
        and isinstance(frozen.get("note6"), dict)
        and frozen["note6"].get("passed") is True
        and frozen["note6"].get("first_action") is True
        and isinstance(frozen["note6"].get("sha256"), str)
        and len(frozen["note6"]["sha256"]) == 64
        and _x4b_local_result_valid(row.get("local_preflight_of_record", {}))
        and _x4b_local_result_valid(row.get("pod_host_cpu_preflight", {}))
        and isinstance(cache, dict)
    ):
        return False
    if cache.get("name") == "full":
        cache_ok = (
            cache.get("bottom_levels_omitted") == 0
            and cache.get("retained_initial_outer_cache_bytes")
            == X4B_FULL_INITIAL_CACHE_BYTES
            and cache.get("retained_fold_outer_cache_bytes") == X4B_FULL_FOLD_CACHE_BYTES
        )
    elif cache.get("name") == "ram-degraded-one-level":
        cache_ok = (
            cache.get("bottom_levels_omitted") == 1
            and cache.get("retained_initial_outer_cache_bytes")
            == X4B_DEGRADED_INITIAL_CACHE_BYTES
            and cache.get("retained_fold_outer_cache_bytes")
            == X4B_DEGRADED_FOLD_CACHE_BYTES
        )
    else:
        cache_ok = False
    cache_ok = cache_ok and cache.get("retained_total_outer_cache_bytes") == (
        cache.get("retained_initial_outer_cache_bytes", 0)
        + cache.get("retained_fold_outer_cache_bytes", 0)
    )
    if not (
        cache_ok
        and isinstance(correctness, dict)
        and correctness.get("synthetic_preflight_before_full_pass") is True
        and correctness.get("all_equal") is True
        and len(correctness.get("contexts", [])) == 4
        and all(item.get("equal") is True for item in correctness["contexts"])
        and len(correctness.get("synthetic", [])) == 5
        and all(item.get("equal") is True for item in correctness["synthetic"])
        and len(correctness.get("complete_aux_roots", [])) == 2
        and all(typed_sample_valid(item) for item in correctness["complete_aux_roots"])
        and len(correctness.get("larger_cohort_samples", [])) == 3
        and all(typed_sample_valid(item) for item in correctness["larger_cohort_samples"])
        and isinstance(full, dict)
        and full.get("hard_ceiling") is None
        and full.get("status")
        == "MEASURED/INFORMATIVE; no hard ceiling in runpod-a100-x4b-v1"
        and _x4b_initial_pass_valid(full.get("warmup"), retained=False)
        and isinstance(full.get("measured"), list)
        and len(full["measured"]) == 3
        and all(_x4b_initial_pass_valid(item, retained=False) for item in full["measured"])
        and _x4b_close(
            full.get("selected_upper_median_wall_s"),
            _x4b_upper_median([item["wall_s"] for item in full["measured"]]),
        )
        and _x4b_initial_pass_valid(full.get("final_materialization"), retained=True)
        and isinstance(isolated, dict)
        and _x4b_isolated_valid(isolated.get("warmup"))
        and isinstance(isolated.get("measured"), list)
        and len(isolated["measured"]) == 3
        and all(_x4b_isolated_valid(item) for item in isolated["measured"])
    ):
        return False
    isolated_selected = _x4b_upper_median([item["wall_s"] for item in isolated["measured"]])
    isolated_pass = isolated_selected <= X4B_COMMIT_CEILING_S
    if not (
        _x4b_close(isolated.get("selected_upper_median_wall_s"), isolated_selected)
        and isolated.get("ceiling_s") == X4B_COMMIT_CEILING_S
        and _x4b_close(isolated.get("margin_s"), X4B_COMMIT_CEILING_S - isolated_selected)
        and isolated.get("pass") is isolated_pass
        and isinstance(artifacts, dict)
        and artifacts.get("page_cache_dontneed_bytes") == 9_618_587_808
        and artifacts.get("page_cache_advice_calls") == 10
        and artifacts.get("footprint", {}).get("coefficient_bytes") == 9_618_587_648
        and artifacts.get("footprint", {}).get("oracle_bytes") == 76_948_701_184
        and artifacts.get("footprint", {}).get("root_bytes") == 160
        and artifacts.get("footprint", {}).get("durable_bytes") == X4B_DURABLE_BYTES
        and artifacts.get("footprint", {}).get("all_lengths_and_bindings_checked") is True
        and isinstance(opening, dict)
        and opening.get("source_policy")
        == "PersistedOracle (record eligible); AuditRecompute refused"
        and _x4b_response_candidate_valid(opening.get("warmup"))
        and isinstance(opening.get("measured"), list)
        and len(opening["measured"]) == 3
        and all(_x4b_response_candidate_valid(item) for item in opening["measured"])
    ):
        return False
    selected_open = _x4b_upper_median([item["open_wall_s"] for item in opening["measured"]])
    selected_verify = _x4b_upper_median([item["verify_wall_s"] for item in opening["measured"]])
    open_pass = selected_open <= X4B_OPEN_CEILING_S
    verify_pass = selected_verify <= X4B_VERIFY_CEILING_S
    communication_pass = opening.get("all_byte_counts_exact") is True
    g6_pass = opening.get("all_g6_reconciled") is True
    hardware_pass = (
        machine.get("memory_bytes", 0) >= X4B_BASELINE_RAM_BYTES
        and machine.get("persistent_volume_bytes", 0) >= X4B_MIN_VOLUME_BYTES
        and "A100-SXM4-80GB" in machine.get("gpu", "")
        and machine.get("rayon_threads") == 8
    )
    cpu_pass = (
        row["pod_host_cpu_preflight"]["cpu_full_node_pipeline"]
        ["selected_canonical_frame_bytes_per_s"]
        >= X4B_CPU_GATE_BPS
    )
    overall_pass = (
        cpu_pass
        and correctness["all_equal"]
        and isolated_pass
        and open_pass
        and verify_pass
        and opening.get("all_accepted") is True
        and communication_pass
        and g6_pass
        and hardware_pass
    )
    expected_prefix = "PASS" if overall_pass else "FAIL"
    return (
        _x4b_close(opening.get("selected_upper_median_open_wall_s"), selected_open)
        and _x4b_close(opening.get("selected_upper_median_verify_wall_s"), selected_verify)
        and opening.get("open_pass") is open_pass
        and opening.get("verify_pass") is verify_pass
        and opening.get("all_accepted") is True
        and isinstance(codec, dict)
        and codec.get("migration_sha256") == X4_V4_MIGRATION_SHA256
        and codec.get("packed_opening_bytes") == X4_V4_PACKED_OPENING_BYTES
        and codec.get("complete_pcs_bytes") == X4_V4_PCS_BYTES
        and codec.get("response_bytes") == X4_V4_RESPONSE_BYTES
        and codec.get("golden_decode_exact") is True
        and codec.get("exact_match") is True
        and isinstance(gate, dict)
        and gate.get("overall_x4b", "").startswith(expected_prefix)
        and gate.get("historical_x4", "").startswith("FAIL IMMUTABLE")
        and row.get("historical_baseline", {}).get("immutable") is True
        and row.get("historical_baseline", {}).get("verdict")
        == "G4 COMMIT FAIL; OVERALL X4 FAIL"
    )


def validate_x4b_pod_result(path: Path) -> bool:
    try:
        if not path.is_absolute():
            path = REPO / path
        return _x4b_pod_result_valid(load_json(path))
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return False


def p6_shape(data: dict[str, Any]) -> bool:
    return (
        data.get("milestone") == "P6"
        and data.get("accepted") is True
        and data.get("t_prefill") == 100
        and data.get("n_decode") == 50
    )


def select_p6_record(results: list[dict[str, Any]]) -> dict[str, Any]:
    clean = [r for r in results if p6_shape(r) and not r.get("git_dirty", True)]
    if clean:
        return max(clean, key=lambda r: r["_mtime"])
    dirty = [r for r in results if p6_shape(r)]
    if dirty:
        return max(dirty, key=lambda r: r["_mtime"])
    raise SystemExit("no accepted P6 result for prompt 100 + decode 50")


def _c1_record_valid(row: dict[str, Any]) -> bool:
    reuse = row.get("c1_identity_seam_reuse")
    labels = row.get("comm_response_by_label")
    return (
        row.get("report_schema_version") == C1_REPORT_SCHEMA_VERSION
        and row.get("milestone") == "C1"
        and row.get("git_dirty") is False
        and isinstance(row.get("git_sha"), str)
        and len(row["git_sha"]) == 40
        and row.get("t_prefill") == 100
        and row.get("n_decode") == 50
        and row.get("accepted") is True
        and row.get("golden_decode_checked") is True
        and row.get("golden_decode_match") is True
        and row.get("chunked_accepted") is True
        and row.get("gate_flat_cost_per_token") is True
        and row.get("comm_response_bytes") == C1_TRANSCRIPT_REFERENCE_BYTES
        and isinstance(labels, dict)
        and labels.get("auth_corrections") == C1_AUTH_CORRECTION_REFERENCE_BYTES
        and row.get("pcs_opening_bytes_total") == C1_PCS_OPENING_REFERENCE_BYTES
        and row.get("public_logits_packed_bytes") == C1_PACKED_LOGITS_REFERENCE_BYTES
        and row.get("total_response_download_packed_bytes")
        == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and row.get("pcs_n_queries") == 200
        and row.get("n_weight_claims") == 96
        and row.get("n_embed_claims") == 6
        and row.get("corr_sub_corrs") == C1_SUB_CORR_REFERENCE
        and row.get("corr_full_corrs") == C1_FULL_CORR_REFERENCE
        and row.get("pcg_backend") == "mock"
        and row.get("pcg_production_ready") is False
        and row.get("pcg_setup_comm_bytes") == 0
        and isinstance(reuse, dict)
        and reuse.get("identity_seam_alias_values") == C1_IDENTITY_SEAM_ALIAS_VALUES
        and reuse.get("saved_response_bytes")
        == P7B_PACKED_RESPONSE_REFERENCE_BYTES - C1_PACKED_RESPONSE_REFERENCE_BYTES
        and reuse.get("measured_transcript_bytes") == C1_TRANSCRIPT_REFERENCE_BYTES
        and reuse.get("measured_auth_correction_bytes")
        == C1_AUTH_CORRECTION_REFERENCE_BYTES
        and reuse.get("measured_packed_response_bytes") == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and reuse.get("measured_prover_sub_corrs") == C1_SUB_CORR_REFERENCE
        and reuse.get("measured_verifier_sub_corrs") == C1_SUB_CORR_REFERENCE
        and reuse.get("measured_prover_full_corrs") == C1_FULL_CORR_REFERENCE
        and reuse.get("measured_verifier_full_corrs") == C1_FULL_CORR_REFERENCE
        and reuse.get("full_corrs_unchanged") is True
        and reuse.get("pcs_parameters_unchanged") is True
        and reuse.get("claims_unchanged") is True
        and reuse.get("byte_formulas_reconcile") is True
        and reuse.get("counters_reconcile") is True
        and reuse.get("typed_correlation_lanes") == 0
        and reuse.get("second_phase_b_shard_required") is False
    )


def select_c1_record(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    rows = [row for row in results if row.get("milestone") == "C1"]
    if not rows:
        return None
    valid = [row for row in rows if _c1_record_valid(row)]
    if not valid:
        raise SystemExit("C1 result exists but does not satisfy the registered reference")
    return max(valid, key=lambda row: row["_mtime"])


def select_packed_source(results: list[dict[str, Any]], baseline: dict[str, Any]) -> dict[str, Any] | None:
    same_shape = [
        r
        for r in results
        if p6_shape(r)
        and r.get("t_prefill") == baseline.get("t_prefill")
        and r.get("n_decode") == baseline.get("n_decode")
        and "public_logits_packed_bytes" in r
    ]
    return max(same_shape, key=lambda r: r["_mtime"]) if same_shape else None


def msg_len(params: dict[str, int]) -> int:
    return params["cols"] + params["pad"]


def rate(params: dict[str, int]) -> float:
    return msg_len(params) / float(1 << params["code_bits"])


def distance(params: dict[str, int]) -> float:
    return 1.0 - rate(params)


def query_error_bits(params: dict[str, int]) -> float:
    base = 1.0 - distance(params) / 2.0
    return -params["n_queries"] * math.log2(base)


def queries_for_bits(params: dict[str, int], bits: float) -> int:
    base = 1.0 - distance(params) / 2.0
    return math.ceil(bits / -math.log2(base))


def multi_open_breakdown(params: dict[str, int], n_claims: int) -> dict[str, int]:
    rows = params["rows"]
    code_bits = params["code_bits"]
    q = params["n_queries"]
    masks = n_claims + 1
    u_vectors = 16 * msg_len(params) * masks
    corr_ss = 16 * n_claims
    zero_batch = 32  # mask_corr + m_z
    column_indices = 4 * q
    data_columns = 8 * rows * q
    mask_columns = 16 * masks * q
    merkle_paths = 32 * (code_bits + code_bits) * q
    columns = column_indices + data_columns + mask_columns + merkle_paths
    total = 32 + u_vectors + corr_ss + zero_batch + columns
    cached_query_cut = data_columns + 32 * code_bits * q
    return {
        "mask_root": 32,
        "u_vectors": u_vectors,
        "corr_ss": corr_ss,
        "zero_batch": zero_batch,
        "column_indices": column_indices,
        "data_columns": data_columns,
        "mask_columns": mask_columns,
        "merkle_paths": merkle_paths,
        "columns_total": columns,
        "cached_query_cut_bytes": cached_query_cut,
        "total": total,
    }


def with_queries(params: dict[str, int], n_queries: int) -> dict[str, int]:
    out = dict(params)
    out["n_queries"] = n_queries
    return out


def embed_pow2_shape(rows: int) -> dict[str, int]:
    total = 1 << 27
    assert total % rows == 0
    cols = total // rows
    msg = cols + EMBED_PARAMS["pad"]
    return {
        "rows": rows,
        "cols": cols,
        "pad": EMBED_PARAMS["pad"],
        "code_bits": (msg - 1).bit_length(),
        "n_queries": EMBED_PARAMS["n_queries"],
    }


def pcs_total(layer_params: dict[str, int], layer_claims: int, embed_params: dict[str, int], embed_claims: int) -> int:
    return (
        12 * multi_open_breakdown(layer_params, layer_claims)["total"]
        + multi_open_breakdown(embed_params, embed_claims)["total"]
    )


def pcs_cached_total(
    layer_params: dict[str, int],
    layer_claims: int,
    embed_params: dict[str, int],
    embed_claims: int,
) -> int:
    layer = multi_open_breakdown(layer_params, layer_claims)
    embed = multi_open_breakdown(embed_params, embed_claims)
    return 12 * (layer["total"] - layer["cached_query_cut_bytes"]) + (
        embed["total"] - embed["cached_query_cut_bytes"]
    )


def response_total(current_packed: int, current_pcs: int, new_pcs: int) -> int:
    return current_packed - current_pcs + new_pcs


def mb(x: float) -> float:
    return x / 1_000_000.0


def pcs_scenarios(baseline: dict[str, Any], current_packed_download: int) -> list[dict[str, Any]]:
    current_pcs = int(baseline["pcs_opening_bytes_total"])
    q60 = queries_for_bits(LAYER_PARAMS, 60.0)
    layer_q60 = with_queries(LAYER_PARAMS, q60)
    embed_q60 = with_queries(EMBED_PARAMS, q60)
    embed_4096 = embed_pow2_shape(1 << 12)

    rows = [
        (
            "current",
            "measured shape and claims",
            pcs_total(LAYER_PARAMS, 8, EMBED_PARAMS, 6),
            "implemented",
            None,
        ),
        (
            "q60_same_rate",
            f"projection only: Q={q60}, same rate/distance, >=60-bit query error",
            pcs_total(layer_q60, 8, embed_q60, 6),
            "soundness-decision-required",
            {"n_queries": q60, "error_bits": query_error_bits(layer_q60)},
        ),
        (
            "per_tensor_rlc",
            "projection only: layer claims 8->4, embed claims 6->3",
            pcs_total(LAYER_PARAMS, 4, EMBED_PARAMS, 3),
            "protocol-design-required",
            None,
        ),
        (
            "q60_plus_rlc",
            f"projection only: Q={q60} plus per-tensor RLC",
            pcs_total(layer_q60, 4, embed_q60, 3),
            "soundness-and-protocol-design-required",
            {"n_queries": q60, "error_bits": query_error_bits(layer_q60)},
        ),
        (
            "embed_4096_rows",
            "projection only: embed rows=2^12, cols=2^15, code_bits=16",
            pcs_total(LAYER_PARAMS, 8, embed_4096, 6),
            "layout-variant-required",
            {"embed_params": embed_4096, "embed_error_bits": query_error_bits(embed_4096)},
        ),
        (
            "static_query_cache_marginal",
            "projection only: verifier caches data columns and their Merkle paths after setup",
            pcs_cached_total(LAYER_PARAMS, 8, EMBED_PARAMS, 6),
            "stateful-verifier-design-required",
            None,
        ),
        (
            "static_query_cache_plus_rlc_marginal",
            "projection only: static query cache plus per-tensor RLC",
            pcs_cached_total(LAYER_PARAMS, 4, EMBED_PARAMS, 3),
            "stateful-verifier-and-protocol-design-required",
            None,
        ),
    ]

    out = []
    for name, note, pcs_bytes, status, extra in rows:
        row = {
            "name": name,
            "status": status,
            "note": note,
            "pcs_opening_bytes": pcs_bytes,
            "pcs_delta_bytes": pcs_bytes - current_pcs,
            "packed_response_download_bytes": response_total(current_packed_download, current_pcs, pcs_bytes),
        }
        if extra:
            row.update(extra)
        out.append(row)
    return out


def rho_model(baseline: dict[str, Any]) -> dict[str, Any]:
    rho_prefill = float(baseline["rho_prefill"])
    rho_decode = float(baseline["rho_decode"])
    relative = [1.0, 2.0, 2.5, 3.0, 5.0, 8.0, 10.0]
    return {
        "definition": "predicted_gpu_rho = cpu_rho / relative_prover_vs_native_gpu_speedup",
        "targets": P7_RHO_TARGETS,
        "required_relative_prover_vs_native_speedup": {
            phase: rho / P7_RHO_TARGETS[phase]
            for phase, rho in (("prefill", rho_prefill), ("decode", rho_decode))
        },
        "sensitivity": [
            {
                "relative_prover_vs_native_speedup": r,
                "rho_prefill": rho_prefill / r,
                "rho_decode": rho_decode / r,
                "prefill_target_met": rho_prefill / r <= P7_RHO_TARGETS["prefill"],
                "decode_target_met": rho_decode / r <= P7_RHO_TARGETS["decode"],
            }
            for r in relative
        ],
    }


def summarize_rhos(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = [
        "rho_kernel_weighted_layer",
        "rho_blind_total",
        "rho",
        "rho_prefill",
        "rho_decode",
        "rho_cpu_prefill",
        "rho_cpu_decode",
    ]
    rows = []
    for r in results:
        vals = {k: r[k] for k in keys if k in r}
        if vals:
            rows.append(
                {
                    "source": r["_path"],
                    "milestone": r.get("milestone"),
                    "git_dirty": r.get("git_dirty"),
                    **vals,
                }
            )
    return rows


def measured_pcs_profiles(results: list[dict[str, Any]], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    rows_by_shape: dict[tuple[Any, Any, Any, Any], dict[str, Any]] = {}
    seen: set[str] = set()
    candidates = [baseline] + [
        r
        for r in results
        if r.get("accepted") is True
        and r.get("milestone")
        in {
            "P6",
            "P6-quick",
            "P7-integrated-hybrid",
            "P7-integrated-hybrid-quick",
            "P7-integrated-resident",
            "P7-integrated-resident-quick",
        }
        and "pcs_opening_bytes_total" in r
    ]
    for r in candidates:
        source = r["_path"]
        if source in seen:
            continue
        seen.add(source)
        n_queries = int(r.get("pcs_n_queries", 200))
        params = with_queries(LAYER_PARAMS, n_queries)
        packed = r.get("total_response_download_packed_bytes")
        if packed is None and "public_logits_packed_bytes" in r:
            packed = int(r["comm_response_bytes"]) + int(r["public_logits_packed_bytes"])
        row = {
            "_mtime": r["_mtime"],
            "source": source,
            "milestone": r.get("milestone"),
            "git_dirty": r.get("git_dirty"),
            "t_prefill": r.get("t_prefill"),
            "n_decode": r.get("n_decode"),
            "pcs_n_queries": n_queries,
            "pcs_query_error_bits": float(r.get("pcs_query_error_bits", query_error_bits(params))),
            "pcs_opening_bytes_total": int(r["pcs_opening_bytes_total"]),
            "pcs_cached_query_marginal_bytes_total": r.get("pcs_cached_query_marginal_bytes_total"),
            "comm_response_bytes": r.get("comm_response_bytes"),
            "total_response_download_packed_bytes": packed,
        }
        key = (row["milestone"], row["t_prefill"], row["n_decode"], row["pcs_n_queries"])
        prev = rows_by_shape.get(key)
        if prev is None or row["_mtime"] > prev["_mtime"]:
            rows_by_shape[key] = row
    rows = list(rows_by_shape.values())
    for row in rows:
        row.pop("_mtime", None)
    rows.sort(key=lambda x: (x["t_prefill"] or 0, x["n_decode"] or 0, x["pcs_n_queries"], x["source"]))
    return rows


def mock_pcg_lower_bounds(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") != "P7-mock-pcg-lower-bound":
            continue
        rows.append(
            {
                "source": r["_path"],
                "git_dirty": r.get("git_dirty"),
                "is_real_pcg": r.get("is_real_pcg"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "t_total_mock_expansion_s": r.get("t_total_mock_expansion_s"),
                "expanded_prover_bytes": r.get("expanded_prover_bytes"),
                "expanded_verifier_bytes": r.get("expanded_verifier_bytes"),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "note": r.get("note"),
            }
        )
    rows.sort(key=lambda x: x["source"])
    return rows


def real_pcg_phase_a(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") != "P7-real-pcg-phase-a":
            continue
        timings = r.get("phase_a_timings") or {}
        params = r.get("lpn_parameters") or {}
        rows.append(
            {
                "source": r["_path"],
                "git_dirty": r.get("git_dirty"),
                "is_real_pcg": r.get("is_real_pcg"),
                "base_vole": r.get("base_vole"),
                "setup_comm_bytes": r.get("setup_comm_bytes"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "sub_equiv_corrs": (r.get("corr_sub_corrs") or 0)
                + 2 * (r.get("corr_full_corrs") or 0),
                "t_total_real_expansion_s": r.get(
                    "t_total_real_expansion_s", timings.get("t_total_real_expansion_s")
                ),
                "t_setup_stub_s": timings.get("t_setup_stub_s"),
                "t_ggm_pprf_s": timings.get("t_ggm_pprf_s"),
                "t_lpn_expand_s": timings.get("t_lpn_expand_s"),
                "t_consistency_check_s": timings.get("t_consistency_check_s"),
                "sub_equiv_corrs_per_s_joint": r.get("sub_equiv_corrs_per_s_joint"),
                "expanded_prover_bytes": r.get("expanded_prover_bytes"),
                "expanded_verifier_bytes": r.get("expanded_verifier_bytes"),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "lpn_parameters": params,
                "consistency": r.get("consistency"),
                "note": r.get("note"),
            }
        )
    rows.sort(key=lambda x: x["source"])
    return rows


def real_pcg_phase_b(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") != "P7-real-pcg-phase-b":
            continue
        timings = r.get("phase_b_timings") or {}
        setup = r.get("phase_b_setup") or {}
        comm = setup.get("comm") or {}
        rows.append(
            {
                "source": r["_path"],
                "git_dirty": r.get("git_dirty"),
                "is_real_pcg": r.get("is_real_pcg"),
                "base_vole": r.get("base_vole"),
                "production_ready": r.get("production_ready"),
                "setup_comm_bytes": r.get("setup_comm_bytes"),
                "base_ot_bytes": comm.get("base_ot_bytes"),
                "ot_extension_bytes": comm.get("ot_extension_bytes"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "t_total_real_expansion_s": r.get(
                    "t_total_real_expansion_s", timings.get("t_total_setup_and_expansion_s")
                ),
                "t_base_ot_s": timings.get("t_base_ot_s"),
                "t_ot_extension_s": timings.get("t_ot_extension_s"),
                "t_ggm_pprf_s": timings.get("t_ggm_pprf_s"),
                "t_lpn_expand_s": timings.get("t_lpn_expand_s"),
                "t_consistency_check_s": timings.get("t_consistency_check_s"),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "setup": setup,
                "consistency": r.get("consistency"),
                "note": r.get("note"),
            }
        )
    rows.sort(key=lambda x: x["source"])
    return rows


def gpu_roofline_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {"P7-gpu-roofline", "P7-gpu-roofline-quick"}:
            continue
        kernel = r.get("kernel") or {}
        # Early remote-provider diagnostics had correct outputs but non-blocking
        # event timings (0 s / impossible bandwidth). Keep the raw JSON
        # append-only, but never promote it into the aggregate roofline profiles.
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        stream = kernel.get("stream") or {}
        chain = kernel.get("chain") or {}
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "device": kernel.get("device"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "stream_gpu_s": stream.get("gpu_s"),
                "stream_gpu_cpu_speedup": stream.get("gpu_cpu_speedup"),
                "stream_gpu_bandwidth_gb_s": stream.get("gpu_bandwidth_gb_s"),
                "chain_gpu_s": chain.get("gpu_s"),
                "chain_gpu_cpu_speedup": chain.get("gpu_cpu_speedup"),
                "chain_gpu_fp2_mul_s": chain.get("gpu_fp2_mul_s"),
                "screening": r.get("screening"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_fused_epilogue_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-fused-epilogue",
            "P7-gpu-fused-epilogue-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "device": kernel.get("device"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "weighted_rho_kernel": kernel.get("weighted_rho_kernel"),
                "gate_weighted_rho_le_1_30": kernel.get("gate_weighted_rho_le_1_30"),
                "shapes": kernel.get("shapes"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_logup_tree_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {"P7-gpu-logup-tree", "P7-gpu-logup-tree-quick"}:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "cpu_s": kernel.get("cpu_s"),
                "gpu_s": kernel.get("gpu_s"),
                "gpu_cpu_speedup": kernel.get("gpu_cpu_speedup"),
                "gate_speedup_ge_5_48": kernel.get("gate_speedup_ge_5_48"),
                "all_layers_checksum": kernel.get("all_layers_checksum"),
                "operation_counts": kernel.get("operation_counts"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_logup_round_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {"P7-gpu-logup-rounds", "P7-gpu-logup-rounds-quick"}:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "cpu_s": kernel.get("cpu_s"),
                "gpu_s": kernel.get("gpu_s"),
                "gpu_cpu_speedup": kernel.get("gpu_cpu_speedup"),
                "gate_speedup_ge_5_48": kernel.get("gate_speedup_ge_5_48"),
                "all_rounds_checksum": kernel.get("all_rounds_checksum"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_logup_blind_round_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-logup-blind-rounds",
            "P7-gpu-logup-blind-rounds-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "blind_corrections_correct": kernel.get("blind_corrections_correct"),
                "timing_sane": kernel.get("timing_sane"),
                "cpu_blind_s": kernel.get("cpu_blind_s"),
                "gpu_blind_s": kernel.get("gpu_blind_s"),
                "gpu_clear_s": kernel.get("gpu_clear_s"),
                "gpu_cpu_speedup": kernel.get("gpu_cpu_speedup"),
                "blind_over_clear": kernel.get("blind_over_clear"),
                "gate_speedup_ge_5_48_and_overhead_le_1_05": kernel.get(
                    "gate_speedup_ge_5_48_and_overhead_le_1_05"
                ),
                "all_rounds_checksum": kernel.get("all_rounds_checksum"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_pcs_arithmetic_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-pcs-arithmetic",
            "P7-gpu-pcs-arithmetic-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "gate_each_speedup_ge_5_48": kernel.get("gate_each_speedup_ge_5_48"),
                "ntt": kernel.get("ntt"),
                "combine_rows": kernel.get("combine_rows"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_blake3_merkle_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-blake3-merkle",
            "P7-gpu-blake3-merkle-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        rust = r.get("rust_reference") or {}
        if (
            not kernel.get("host_device_correctness")
            or not kernel.get("timing_sane")
            or not r.get("root_matches_rust_blake3")
        ):
            continue
        gpu_s = kernel.get("gpu_s")
        cpu_s = rust.get("cpu_s")
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "host_device_correctness": kernel.get("host_device_correctness"),
                "root_matches_rust_blake3": r.get("root_matches_rust_blake3"),
                "timing_sane": kernel.get("timing_sane"),
                "root": kernel.get("root"),
                "gpu_s": gpu_s,
                "rust_cpu_s": cpu_s,
                "gpu_cpu_speedup": cpu_s / gpu_s if cpu_s and gpu_s else None,
                "gate_gpu_s_le_0_075": kernel.get("gate_gpu_s_le_0_075"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_native_inference_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-native-inference",
            "P7-gpu-native-inference-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if (
            not r.get("correctness")
            or not r.get("golden_match")
            or not kernel.get("deterministic")
            or kernel.get("fixed_point_errors")
        ):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "baseline": r.get("baseline"),
                "correctness": r.get("correctness"),
                "golden_match": r.get("golden_match"),
                "parameters": kernel.get("parameters"),
                "prefill_s": kernel.get("prefill_s"),
                "decode_50_s": kernel.get("decode_50_s"),
                "prefill_timing": kernel.get("prefill_timing"),
                "decode_50_timing": kernel.get("decode_50_timing"),
                "memory": kernel.get("memory"),
                "prefill_argmax": kernel.get("prefill_argmax"),
                "native_gpu_speedup": r.get("native_gpu_speedup"),
                "report_schema_version": r.get("report_schema_version"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def integrated_accelerator_profiles(
    results: list[dict[str, Any]],
    milestones: set[str],
    backend: str,
    *,
    include_p7b_fields: bool = False,
) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in milestones:
            continue
        if not r.get("accepted") or r.get("accelerator_backend") != backend:
            continue
        cleanup_live = r.get("accelerator_live_device_bytes_after_cleanup")
        cleanup_workspace = r.get("accelerator_workspace_device_bytes_after_cleanup")
        cleanup_resident = r.get("accelerator_resident_device_bytes_after_cleanup")
        cleanup_cached = r.get("accelerator_cached_resident_device_bytes_after_cleanup")
        cleanup_values = (cleanup_live, cleanup_workspace, cleanup_resident, cleanup_cached)
        cleanup_accounting_ok = (
            None
            if any(value is None for value in cleanup_values)
            else cleanup_resident == 0
            and cleanup_live == cleanup_workspace + cleanup_cached
        )
        trimmed_live = r.get("accelerator_live_device_bytes_after_cache_trim")
        trimmed_workspace = r.get("accelerator_workspace_device_bytes_after_cache_trim")
        trimmed_resident = r.get("accelerator_resident_device_bytes_after_cache_trim")
        trimmed_cached = r.get("accelerator_cached_resident_device_bytes_after_cache_trim")
        trimmed_values = (trimmed_live, trimmed_workspace, trimmed_resident, trimmed_cached)
        cache_trim_accounting_ok = (
            None
            if any(value is None for value in trimmed_values)
            else trimmed_resident == 0 and trimmed_cached == 0 and trimmed_live == trimmed_workspace
        )
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "threads": r.get("threads"),
                "report_schema_version": r.get("report_schema_version"),
                "t_prefill": r.get("t_prefill"),
                "n_decode": r.get("n_decode"),
                "benchmark_warmup_repetitions": r.get("benchmark_warmup_repetitions"),
                "benchmark_repetitions": r.get("benchmark_repetitions"),
                "prove_prefill_s": r.get("t_prove_prefill_only_s"),
                "prove_response_s": r.get("t_prove_response_s"),
                "prove_decode_marginal_s": r.get("t_prove_decode_marginal_s"),
                "prover_online_accounted_response_s": r.get(
                    "t_prover_online_accounted_response_s"
                ),
                "prover_online_accounted_decode_marginal_s": r.get(
                    "t_prover_online_accounted_decode_marginal_s"
                ),
                "response_session_wall_s": r.get("t_response_session_wall_s"),
                "protocol_closure_exchange_s": r.get("t_protocol_closure_exchange_s"),
                "verifier_accounted_s": r.get("t_verifier_accounted_s"),
                "prove_prefill_timing": r.get("prove_prefill_timing"),
                "prove_response_timing": r.get("prove_response_timing"),
                "prove_decode_marginal_timing": r.get("prove_decode_marginal_timing"),
                "prover_online_accounted_response_timing": r.get(
                    "prover_online_accounted_response_timing"
                ),
                "prover_online_accounted_decode_marginal_timing": r.get(
                    "prover_online_accounted_decode_marginal_timing"
                ),
                "response_session_wall_timing": r.get("response_session_wall_timing"),
                "protocol_closure_exchange_timing": r.get(
                    "protocol_closure_exchange_timing"
                ),
                "verifier_accounted_timing": r.get("verifier_accounted_timing"),
                "cpu_relative_rho": {
                    "prefill": r.get("rho_cpu_prefill", r.get("rho_prefill")),
                    "decode": r.get("rho_cpu_decode", r.get("rho_decode")),
                },
                "rho_denominator": r.get("rho_denominator"),
                "golden_decode_checked": r.get("golden_decode_checked"),
                "golden_decode_match": r.get("golden_decode_match"),
                "flat_cost_last_over_first": r.get("curve_last_over_first"),
                "flat_cost_gate": r.get("gate_flat_cost_per_token"),
                "packed_response_bytes": r.get("total_response_download_packed_bytes"),
                "communication": {
                    "prefill_bytes": r.get("comm_prefill_bytes"),
                    "response_bytes": r.get("comm_response_bytes"),
                    "decode_marginal_bytes": r.get("comm_decode_marginal_bytes"),
                    "pcs_opening_bytes": r.get("pcs_opening_bytes_total"),
                    "public_logits_packed_bytes": r.get("public_logits_packed_bytes"),
                    "response_by_label": r.get("comm_response_by_label"),
                    "pcs_by_label": r.get("comm_pcs_by_label"),
                },
                "pcs_commit_timing": r.get("pcs_commit_timing"),
                "pcs_open_timing": r.get("pcs_open_timing"),
                "pcs_verify_timing": r.get("pcs_verify_timing"),
                "verify_response_timing": r.get("verify_response_timing"),
                "scalar_closure_soundness": {
                    "prod_claims": r.get("closure_prod_claims"),
                    "zero_claims": r.get("closure_zero_claims"),
                    "prod_bits": r.get("closure_prod_scalar_soundness_bits"),
                    "zero_bits": r.get("closure_zero_scalar_soundness_bits"),
                    "union_bits": r.get("closure_union_scalar_soundness_bits"),
                },
                "accelerator_witness": r.get("accelerator_witness"),
                "accelerator_response_witness": r.get("accelerator_response_witness"),
                "accelerator_prefill": r.get("accelerator_prefill_proving"),
                "accelerator_session": r.get("accelerator_proving"),
                "accelerator_live_device_bytes_after_cleanup": r.get(
                    "accelerator_live_device_bytes_after_cleanup"
                ),
                "accelerator_workspace_device_bytes_after_cleanup": r.get(
                    "accelerator_workspace_device_bytes_after_cleanup"
                ),
                "accelerator_resident_device_bytes_after_cleanup": r.get(
                    "accelerator_resident_device_bytes_after_cleanup"
                ),
                "accelerator_cached_resident_device_bytes_after_cleanup": r.get(
                    "accelerator_cached_resident_device_bytes_after_cleanup"
                ),
                "accelerator_cleanup_memory_accounting_ok": cleanup_accounting_ok,
                "accelerator_live_device_bytes_after_cache_trim": trimmed_live,
                "accelerator_workspace_device_bytes_after_cache_trim": trimmed_workspace,
                "accelerator_resident_device_bytes_after_cache_trim": trimmed_resident,
                "accelerator_cached_resident_device_bytes_after_cache_trim": trimmed_cached,
                "accelerator_cache_trim_memory_accounting_ok": cache_trim_accounting_ok,
                "peak_rss_gb": r.get("peak_rss_gb"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "pcg_backend": r.get("pcg_backend"),
                "pcg_setup_comm_bytes": r.get("pcg_setup_comm_bytes"),
                "pcg_real_phase_a_total_s": r.get("pcg_real_phase_a_total_s"),
            }
        )
        if include_p7b_fields:
            rows[-1].update(
                {
                    "accepted": r.get("accepted"),
                    "accelerator_backend": r.get("accelerator_backend"),
                    "git_sha": r.get("git_sha"),
                    "git_sha_before_benchmark": r.get("git_sha_before_benchmark"),
                    "git_sha_before_serialization": r.get(
                        "git_sha_before_serialization"
                    ),
                    "git_dirty_before_benchmark": r.get("git_dirty_before_benchmark"),
                    "git_dirty_before_serialization": r.get(
                        "git_dirty_before_serialization"
                    ),
                    "accelerator_cuda_abi_version": r.get(
                        "accelerator_cuda_abi_version"
                    ),
                    "resident_timing_policy": r.get("resident_timing_policy"),
                    "p7b_gate_evaluated": r.get("p7b_gate_evaluated"),
                    "p7b_gate_profile": r.get("p7b_gate_profile"),
                    "p7b_machine_eligible": r.get("p7b_machine_eligible"),
                    "p7b_timing_statistic": r.get("p7b_timing_statistic"),
                    "p7b_counter_statistic": r.get("p7b_counter_statistic"),
                    "p7b_prefill_core_gate_s": r.get("p7b_prefill_core_gate_s"),
                    "p7b_decode_marginal_gate_s": r.get(
                        "p7b_decode_marginal_gate_s"
                    ),
                    "p7b_sync_count_gate_retired": r.get(
                        "p7b_sync_count_gate_retired"
                    ),
                    "p7b_sync_wall_fraction_gate": r.get(
                        "p7b_sync_wall_fraction_gate"
                    ),
                    "p7b_sync_wall_absolute_gate_s": r.get(
                        "p7b_sync_wall_absolute_gate_s"
                    ),
                    "p7b_h2d_gate_bytes": r.get("p7b_h2d_gate_bytes"),
                    "p7b_prefill_core_observed_s": r.get(
                        "p7b_prefill_core_observed_s"
                    ),
                    "p7b_decode_marginal_observed_s": r.get(
                        "p7b_decode_marginal_observed_s"
                    ),
                    "p7b_sync_observed": r.get("p7b_sync_observed"),
                    "p7b_sync_wall_fraction_observed": r.get(
                        "p7b_sync_wall_fraction_observed"
                    ),
                    "p7b_sync_wall_absolute_observed_s": r.get(
                        "p7b_sync_wall_absolute_observed_s"
                    ),
                    "p7b_h2d_observed_bytes": r.get("p7b_h2d_observed_bytes"),
                    "p7b_prefill_core_gate_pass": r.get(
                        "p7b_prefill_core_gate_pass"
                    ),
                    "p7b_decode_marginal_gate_pass": r.get(
                        "p7b_decode_marginal_gate_pass"
                    ),
                    "p7b_sync_wall_fraction_gate_pass": r.get(
                        "p7b_sync_wall_fraction_gate_pass"
                    ),
                    "p7b_sync_wall_absolute_gate_pass": r.get(
                        "p7b_sync_wall_absolute_gate_pass"
                    ),
                    "p7b_h2d_gate_pass": r.get("p7b_h2d_gate_pass"),
                    "response_communication_envelope_bytes": r.get(
                        "response_communication_envelope_bytes"
                    ),
                    "response_communication_observed_bytes": r.get(
                        "response_communication_observed_bytes"
                    ),
                    "response_communication_invariant_pass": r.get(
                        "response_communication_invariant_pass"
                    ),
                    "p7b_transcript_reference_bytes": r.get(
                        "p7b_transcript_reference_bytes"
                    ),
                    "p7b_pcs_opening_reference_bytes": r.get(
                        "p7b_pcs_opening_reference_bytes"
                    ),
                    "p7b_packed_logits_reference_bytes": r.get(
                        "p7b_packed_logits_reference_bytes"
                    ),
                    "p7b_packed_response_reference_bytes": r.get(
                        "p7b_packed_response_reference_bytes"
                    ),
                    "p7b_response_communication_no_growth_pass": r.get(
                        "p7b_response_communication_no_growth_pass"
                    ),
                    "p7b_all_gates_pass": r.get("p7b_all_gates_pass"),
                    "pcs_n_queries": r.get("pcs_n_queries"),
                    "repetitions": r.get("repetitions"),
                    "pcg_production_ready": r.get("pcg_production_ready"),
                }
            )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def integrated_hybrid_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return integrated_accelerator_profiles(
        results,
        {"P7-integrated-hybrid", "P7-integrated-hybrid-quick"},
        "cuda-hybrid",
    )


def integrated_resident_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return integrated_accelerator_profiles(
        results,
        {"P7-integrated-resident", "P7-integrated-resident-quick"},
        "cuda-resident",
    )


def integrated_p7b_resident_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return integrated_accelerator_profiles(
        results,
        {"P7b-integrated-resident", "P7b-integrated-resident-quick"},
        "cuda-resident",
        include_p7b_fields=True,
    )


def resident_run_of_record_eligible(row: dict[str, Any]) -> bool:
    """Require schema-4 arena invariants while retaining historical schema-3 records."""
    if row.get("milestone") != "P7-integrated-resident" or row.get("git_dirty", True):
        return False
    schema = row.get("report_schema_version") or 0
    # P7 is a closed historical artifact. Later P7b schemas must never replace
    # its negative run of record even if a caller mislabels one as P7.
    if schema > 4 or row.get("p7b_gate_evaluated") is not None:
        return False
    if schema < 4:
        return True
    return (
        row.get("accelerator_cleanup_memory_accounting_ok") is True
        and row.get("accelerator_cache_trim_memory_accounting_ok") is True
    )


def p7b_resident_run_of_record_eligible(row: dict[str, Any]) -> bool:
    """Recognize a complete official P7b verdict, whether performance passes or fails.

    This is intentionally a fail-closed schema validator, not a selector for
    successful runs. A valid measured failure is a run of record; missing or
    internally inconsistent gate evidence is not.
    """
    fixed_invariants = (
        row.get("milestone") == "P7b-integrated-resident"
        and type(row.get("report_schema_version")) is int
        and row.get("report_schema_version") == P7B_REPORT_SCHEMA_VERSION
        and row.get("accelerator_backend") == "cuda-resident"
        and type(row.get("accelerator_cuda_abi_version")) is int
        and row.get("accelerator_cuda_abi_version") == P7B_CUDA_ABI_VERSION
        and row.get("resident_timing_policy") == P7B_OFFICIAL_RESIDENT_TIMING_POLICY
        and row.get("p7b_gate_profile") == P7B_GATE_PROFILE
        and row.get("accepted") is True
        and row.get("git_dirty") is False
        and row.get("git_dirty_before_benchmark") is False
        and row.get("git_dirty_before_serialization") is False
        and _p7b_git_provenance_valid(row)
        and _p7b_machine_metadata_valid(row)
        and row.get("p7b_machine_eligible") is True
        and row.get("p7b_gate_evaluated") is True
        and type(row.get("benchmark_warmup_repetitions")) is int
        and row.get("benchmark_warmup_repetitions") >= 1
        and type(row.get("benchmark_repetitions")) is int
        and row.get("benchmark_repetitions") >= 3
        and type(row.get("t_prefill")) is int
        and row.get("t_prefill") == 100
        and type(row.get("n_decode")) is int
        and row.get("n_decode") == 50
        and type(row.get("pcs_n_queries")) is int
        and row.get("pcs_n_queries") == 200
        and row.get("golden_decode_checked") is True
        and row.get("golden_decode_match") is True
        and row.get("flat_cost_gate") is True
        and _finite_nonnegative(row.get("flat_cost_last_over_first"))
        and row.get("flat_cost_last_over_first") <= 1.5
        and row.get("pcg_backend") == "mock"
        and row.get("pcg_production_ready") is False
        and row.get("accelerator_cleanup_memory_accounting_ok") is True
        and row.get("accelerator_cache_trim_memory_accounting_ok") is True
    )
    repetitions = row.get("repetitions")
    timing_policy_valid = isinstance(repetitions, list) and all(
        isinstance(repetition, dict)
        and isinstance(repetition.get("accelerator_session"), dict)
        and repetition["accelerator_session"].get("timing_method")
        == P7B_OFFICIAL_SESSION_TIMING_METHOD
        and repetition["accelerator_session"].get("phase_attribution_available") is False
        and type(repetition["accelerator_session"].get("timing_records")) is int
        and repetition["accelerator_session"]["timing_records"] == 0
        and type(repetition["accelerator_session"].get("timing_elapsed_query_attempts"))
        is int
        and repetition["accelerator_session"]["timing_elapsed_query_attempts"] == 0
        and type(repetition["accelerator_session"].get("timing_elapsed_no_write")) is int
        and repetition["accelerator_session"]["timing_elapsed_no_write"] == 0
        and type(repetition["accelerator_session"].get("timing_event_queries")) is int
        and repetition["accelerator_session"]["timing_event_queries"] == 0
        and type(repetition["accelerator_session"].get("timing_event_api_calls")) is int
        and repetition["accelerator_session"]["timing_event_api_calls"] == 0
        and _nonnegative_int(
            repetition["accelerator_session"].get("resident_h2d_host_calls")
        )
        and _nonnegative_int(
            repetition["accelerator_session"].get("resident_d2h_host_calls")
        )
        and _finite_nonnegative(
            repetition["accelerator_session"].get("resident_h2d_host_call_s")
        )
        and _finite_nonnegative(
            repetition["accelerator_session"].get("resident_d2h_host_call_s")
        )
        for repetition in repetitions
    )
    return (
        fixed_invariants
        and timing_policy_valid
        and _p7b_sampling_statistics_valid(row)
        and _p7b_communication_valid(row)
        and _p7b_performance_verdict_valid(row)
    )


def validate_p7b_official_result(path: Path) -> bool:
    """Validate one raw JSON through the same projection and fail-closed selector."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict):
        return False
    raw["_path"] = str(path)
    try:
        raw["_mtime"] = path.stat().st_mtime
    except OSError:
        return False
    rows = integrated_p7b_resident_profiles([raw])
    return len(rows) == 1 and p7b_resident_run_of_record_eligible(rows[0])


def validate_fase_d_pod_official_result(path: Path) -> bool:
    """Fail closed on the preregistered fase-D G4 raw artifact."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict):
        return False
    raw["_path"] = str(path)
    try:
        raw["_mtime"] = path.stat().st_mtime
    except OSError:
        return False
    rows = integrated_accelerator_profiles(
        [raw], {"fase-D-G4"}, "cuda-resident", include_p7b_fields=True
    )
    if len(rows) != 1:
        return False
    row = rows[0]
    cloud = raw.get("cloud")
    cloud_fields = (
        "provider",
        "instance_id",
        "region",
        "image",
        "driver_version",
        "cuda_version",
        "gpu_sku",
        "cpu_model",
        "ram_gib",
        "vcpus",
    )
    setup = raw.get("fase_d_setup")
    lifecycle = raw.get("fase_d_lifecycle")
    setup_comm = setup.get("comm") if isinstance(setup, dict) else None
    capacity = setup.get("capacity") if isinstance(setup, dict) else None
    pcs_rows = raw.get("pcs_commitments")
    repetitions = raw.get("repetitions")
    timing_policy_valid = isinstance(repetitions, list) and all(
        isinstance(repetition, dict)
        and isinstance(repetition.get("accelerator_session"), dict)
        and repetition["accelerator_session"].get("timing_method")
        == P7B_OFFICIAL_SESSION_TIMING_METHOD
        and repetition["accelerator_session"].get("phase_attribution_available") is False
        and repetition["accelerator_session"].get("timing_records") == 0
        and repetition["accelerator_session"].get("timing_elapsed_query_attempts") == 0
        and repetition["accelerator_session"].get("timing_elapsed_no_write") == 0
        and repetition["accelerator_session"].get("timing_event_queries") == 0
        and repetition["accelerator_session"].get("timing_event_api_calls") == 0
        for repetition in repetitions
    )
    fixed = (
        raw.get("report_schema_version") == FASE_D_POD_REPORT_SCHEMA_VERSION
        and raw.get("milestone") == "fase-D-G4"
        and raw.get("accelerator_backend") == "cuda-resident"
        and raw.get("accelerator_cuda_abi_version") == P7B_CUDA_ABI_VERSION
        and raw.get("resident_timing_policy") == P7B_OFFICIAL_RESIDENT_TIMING_POLICY
        and raw.get("p7b_gate_profile")
        in (FASE_D_POD_GATE_PROFILE_V1, FASE_D_POD_GATE_PROFILE_V2)
        and raw.get("accepted") is True
        and raw.get("chunked_accepted") is True
        and raw.get("git_dirty") is False
        and raw.get("git_dirty_before_benchmark") is False
        and raw.get("git_dirty_before_serialization") is False
        and _p7b_git_provenance_valid(raw)
        and isinstance(cloud, dict)
        and all(isinstance(cloud.get(field), str) and cloud[field].strip() for field in cloud_fields)
        and cloud.get("provider") == "RunPod"
        and cloud.get("gpu_sku") == "NVIDIA A100-SXM4-80GB"
        and raw.get("threads") == P7B_OFFICIAL_RAYON_THREADS
        and raw.get("p7b_machine_eligible") is True
        and raw.get("p7b_gate_evaluated") is True
        and raw.get("benchmark_warmup_repetitions", 0) >= 1
        and raw.get("benchmark_repetitions", 0) >= 3
        and raw.get("t_prefill") == 100
        and raw.get("n_decode") == 50
        and raw.get("pcs_n_queries") == 200
        and raw.get("golden_decode_checked") is True
        and raw.get("golden_decode_match") is True
        and raw.get("gate_flat_cost_per_token") is True
        and _finite_nonnegative(raw.get("curve_last_over_first"))
        and raw.get("curve_last_over_first") <= 1.5
        and isinstance(pcs_rows, list)
        and len(pcs_rows) == 13
        and all(isinstance(pcs, dict) and pcs.get("verified") is True for pcs in pcs_rows)
        and raw.get("n_weight_claims") == 96
        and raw.get("n_embed_claims") == 6
        and raw.get("pcg_backend") == "real"
        and raw.get("ggm_prg") == "aes128-mmo"
        and raw.get("pcg_production_ready") is True
        and raw.get("fase_d_g1_pass") is True
        and raw.get("pcg_mock_prepass_counters_match") is True
        and raw.get("pcg_mock_prepass_channel_ledger_digest_match") is True
        and raw.get("pcg_mock_prepass_allocation_digest_match") is True
        and raw.get("pcg_allocation_hash_match") is True
        and raw.get("comm_response_bytes") == C1_TRANSCRIPT_REFERENCE_BYTES
        and raw.get("pcs_opening_bytes_total") == C1_PCS_OPENING_REFERENCE_BYTES
        and raw.get("public_logits_packed_bytes") == C1_PACKED_LOGITS_REFERENCE_BYTES
        and raw.get("total_response_download_packed_bytes") == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and raw.get("response_communication_observed_bytes") == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and raw.get("p7b_transcript_reference_bytes") == C1_TRANSCRIPT_REFERENCE_BYTES
        and raw.get("p7b_pcs_opening_reference_bytes") == C1_PCS_OPENING_REFERENCE_BYTES
        and raw.get("p7b_packed_logits_reference_bytes") == C1_PACKED_LOGITS_REFERENCE_BYTES
        and raw.get("p7b_packed_response_reference_bytes") == C1_PACKED_RESPONSE_REFERENCE_BYTES
        and raw.get("response_communication_invariant_pass") is True
        and raw.get("p7b_response_communication_no_growth_pass") is True
        and isinstance(setup, dict)
        and setup.get("ggm_prg") == "aes128-mmo"
        and setup.get("pcg_production_ready") is True
        and setup.get("one_connection_base_phase") is True
        and setup.get("g2_capacity_gate_pass") is True
        and setup.get("g2_traffic_gate_pass") is True
        and isinstance(setup_comm, dict)
        and _nonnegative_int(setup_comm.get("total_bytes"))
        and setup_comm["total_bytes"] <= 40_000_000
        and isinstance(capacity, dict)
        and capacity.get("allocatable_stage3", 0) >= 110_000_000
        and isinstance(lifecycle, dict)
        and lifecycle.get("completed_responses", 0) >= 5
        and lifecycle.get("responses_after_first_repeat_base_ot_bytes") == 0
        and lifecycle.get("responses_after_first_repeat_ot_extension_bytes") == 0
        and row.get("accelerator_cleanup_memory_accounting_ok") is True
        and row.get("accelerator_cache_trim_memory_accounting_ok") is True
    )
    return (
        fixed
        and timing_policy_valid
        and _p7b_sampling_statistics_valid(row)
        and _p7b_performance_verdict_valid(row)
    )


def _c3b_timing_distribution_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    samples = value.get("samples_s")
    return isinstance(samples, list) and _timing_distribution_valid(value, samples)


def _c3b_g2_valid(value: Any, *, pod: bool) -> bool:
    if not isinstance(value, dict):
        return False
    baseline = value.get("baseline_prove_response")
    candidate = value.get("candidate_prove_response")
    if not (
        _c3b_timing_distribution_valid(baseline)
        and _c3b_timing_distribution_valid(candidate)
        and _finite_positive(value.get("baseline_s"))
        and _finite_nonnegative(value.get("candidate_s"))
        and _finite_number(value.get("delta_s"))
        and _finite_number(value.get("delta_percent"))
        and value.get("gate_percent") == 15.0
        and _finite_positive(value.get("ceiling_s"))
        and type(value.get("pass")) is bool
        and _same_number(value["baseline_s"], baseline["median_s"])
        and _same_number(value["candidate_s"], candidate["median_s"])
        and _same_finite_number(value["delta_s"], value["candidate_s"] - value["baseline_s"])
        and _same_finite_number(
            value["delta_percent"], value["delta_s"] / value["baseline_s"] * 100.0
        )
        and value["pass"] is (value["candidate_s"] <= value["ceiling_s"])
    ):
        return False
    if pod:
        return (
            value.get("timing_policy")
            == "wall-only+counters; upper median candidate; pinned same-host control"
            and value.get("baseline_source")
            == (
                "c3b-l4-ablation-diagnostic-2026-07-18-5a2edbe.json; "
                "pinned rounded median"
            )
            and value["baseline_s"] == C3B_G2_POD_BASELINE_S
            and value["ceiling_s"] == C3B_G2_POD_CEILING_S
        )
    return (
        value.get("timing_policy")
        == "same-process ABBA; one paired warmup + three rounds; protocol-core prove wall"
        and value.get("baseline_source")
        == "unchanged fase-D Q=200 public-logit response arm in this record"
        and len(baseline["samples_s"]) == 6
        and len(candidate["samples_s"]) == 6
        and _same_number(value["ceiling_s"], value["baseline_s"] * 1.15)
    )


def _c3b_spool_and_lifecycle_valid(row: dict[str, Any]) -> bool:
    setup = row.get("fase_d_setup")
    lifecycle = row.get("fase_d_lifecycle")
    if not isinstance(setup, dict) or not isinstance(lifecycle, dict):
        return False
    entries = setup.get("correlation_spool_entries")
    spool_bytes = setup.get("correlation_spool_bytes")
    setup_comm = setup.get("comm")
    return (
        setup.get("ggm_prg") == "aes128-mmo"
        and setup.get("pcg_production_ready") is True
        and setup.get("one_connection_base_phase") is True
        and setup.get("g2_capacity_gate_pass") is True
        and setup.get("g2_traffic_gate_pass") is True
        and setup.get("correlation_storage")
        == "unlinked-0600-file; connection-scoped; range-read only; page-cache discarded"
        and _nonnegative_int(entries)
        and entries >= 110_000_000
        and _nonnegative_int(spool_bytes)
        and spool_bytes == entries * 40
        and setup.get("correlation_spool_chunk_entries") == 1 << 16
        and setup.get("correlation_spool_resident_raw_entries") == 0
        and _finite_nonnegative(setup.get("correlation_spool_write_wall_s"))
        and _full_hex_digest(setup.get("correlation_spool_digest"))
        and isinstance(setup_comm, dict)
        and _nonnegative_int(setup_comm.get("total_bytes"))
        and setup_comm["total_bytes"] <= 40_000_000
        and row.get("pcg_setup_comm_bytes") == setup_comm["total_bytes"]
        and lifecycle.get("completed_responses", 0) >= 4
        and lifecycle.get("responses_after_first_repeat_base_ot_bytes") == 0
        and lifecycle.get("responses_after_first_repeat_ot_extension_bytes") == 0
        and isinstance(lifecycle.get("response_base_ot_bytes"), list)
        and len(lifecycle["response_base_ot_bytes"]) == lifecycle["completed_responses"]
        and isinstance(lifecycle.get("response_ot_extension_bytes"), list)
        and len(lifecycle["response_ot_extension_bytes"]) == lifecycle["completed_responses"]
    )


def _c3b_common_record_valid(row: dict[str, Any]) -> bool:
    transcript_labels = row.get("comm_response_by_label")
    pcs_labels = row.get("comm_pcs_by_label")
    pcs_rows = row.get("pcs_commitments")
    common = (
        row.get("report_schema_version") == C3B_REPORT_SCHEMA_VERSION
        and row.get("milestone") == "C3b"
        and row.get("git_dirty") is False
        and _full_git_sha(row.get("git_sha"))
        and row.get("benchmark_warmup_repetitions", 0) >= 1
        and row.get("benchmark_repetitions", 0) >= 3
        and row.get("t_prefill") == 100
        and row.get("n_decode") == 50
        and row.get("accepted") is True
        and row.get("chunked_accepted") is True
        and row.get("golden_decode_checked") is True
        and row.get("golden_decode_match") is True
        and row.get("gate_flat_cost_per_token") is True
        and _finite_nonnegative(row.get("curve_last_over_first"))
        and row["curve_last_over_first"] <= 1.5
        and row.get("c3_packed_response_gate_bytes") == C3B_PACKED_RESPONSE_GATE_BYTES
        and row.get("comm_response_bytes") == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("pcs_opening_bytes_total") == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("public_logits_bytes") == 0
        and row.get("public_logits_packed_bytes") == 0
        and row.get("total_response_download_bytes") == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("total_response_download_packed_bytes")
        == C3B_TRANSCRIPT_REFERENCE_BYTES
        and isinstance(transcript_labels, dict)
        and all(_nonnegative_int(value) for value in transcript_labels.values())
        and sum(transcript_labels.values()) == C3B_TRANSCRIPT_REFERENCE_BYTES
        and isinstance(pcs_labels, dict)
        and all(_nonnegative_int(value) for value in pcs_labels.values())
        and sum(pcs_labels.values()) == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("pcs_n_queries") == 120
        and isinstance(pcs_rows, list)
        and len(pcs_rows) == 2
        and all(isinstance(item, dict) and item.get("verified") is True for item in pcs_rows)
        and row.get("n_weight_claims") == 96
        and row.get("n_embed_claims") == 6
        and row.get("c3b_l4_transcript_bytes") == C3B_L4_TRANSCRIPT_BYTES
        and row.get("c3b_transcript_reference_bytes") == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("c3b_limb_count") == C3B_LIMBS
        and row.get("c3b_range_instances") == C3B_RANGE_INSTANCES
        and row.get("c3b_real_comparisons") == C3B_REAL_COMPARISONS
        and row.get("c3b_packed_entries_per_limb") == C3B_PACKED_ENTRIES_PER_LIMB
        and row.get("c3b_packed_entries_total") == C3B_PACKED_ENTRIES_TOTAL
        and _same_number(
            row.get("c3b_padding_ratio"),
            C3B_PACKED_ENTRIES_PER_LIMB / C3B_REAL_COMPARISONS,
        )
        and row.get("c3b_l4_emult_instances") == C3B_L4_EMULT_INSTANCES
        and row.get("c3b_l4_emult_ceiling") == C3B_L4_EMULT_CEILING
        and row.get("c3b_l4_emult_gate_pass") is True
        and row.get("emult_instances_total") == C3B_EMULT_INSTANCES_TOTAL
        and row.get("c3b_exact_instance_counter_pass") is True
        and row.get("c3b_transcript_category_sum_pass") is True
        and row.get("c3b_pcs_category_sum_pass") is True
        and row.get("c3b_public_logits_disabled") is True
        and row.get("pcg_backend") == "real"
        and row.get("ggm_prg") == "aes128-mmo"
        and row.get("pcg_production_ready") is True
        and row.get("pcg_setup_instances") == 1
        and row.get("pcg_setup_wire_count_invariant_pass") is True
        and row.get("pcg_mock_prepass_counters_match") is True
        and row.get("pcg_mock_prepass_channel_ledger_digest_match") is True
        and row.get("pcg_mock_prepass_allocation_digest_match") is True
        and row.get("pcg_allocation_hash_match") is True
        and row.get("pcg_response_authorization_burned_before_setup") is True
        and row.get("pcg_burn_on_success_or_abort") is True
        and row.get("pcg_reconnect_retry_resume_allowed") is False
    )
    return common and _c3b_spool_and_lifecycle_valid(row)


def _c3b_resident_cleanup_valid(row: dict[str, Any]) -> bool:
    cleanup = (
        row.get("accelerator_live_device_bytes_after_cleanup"),
        row.get("accelerator_workspace_device_bytes_after_cleanup"),
        row.get("accelerator_resident_device_bytes_after_cleanup"),
        row.get("accelerator_cached_resident_device_bytes_after_cleanup"),
    )
    trimmed = (
        row.get("accelerator_live_device_bytes_after_cache_trim"),
        row.get("accelerator_workspace_device_bytes_after_cache_trim"),
        row.get("accelerator_resident_device_bytes_after_cache_trim"),
        row.get("accelerator_cached_resident_device_bytes_after_cache_trim"),
    )
    return (
        all(_nonnegative_int(value) for value in cleanup + trimmed)
        and cleanup[0] == cleanup[1] + cleanup[2] + cleanup[3]
        and trimmed[0] == trimmed[1] + trimmed[2] + trimmed[3]
        and cleanup[2] == 0
        and trimmed[2] == 0
        and trimmed[3] == 0
    )


def _realpcg_pod_metadata_valid(row: dict[str, Any]) -> bool:
    cloud = row.get("cloud")
    fields = (
        "provider",
        "instance_id",
        "region",
        "image",
        "driver_version",
        "cuda_version",
        "gpu_sku",
        "cpu_model",
        "ram_gib",
        "vcpus",
    )
    return (
        isinstance(cloud, dict)
        and all(isinstance(cloud.get(field), str) and cloud[field].strip() for field in fields)
        and cloud.get("provider") == "RunPod"
        and cloud.get("gpu_sku") == "NVIDIA A100-SXM4-80GB"
        and row.get("threads") == P7B_OFFICIAL_RAYON_THREADS
    )


def _c3b_pod_record_valid(row: dict[str, Any]) -> bool:
    g2 = row.get("c3b_g2")
    communication = (
        row.get("response_communication_envelope_bytes") == 200_000_000
        and row.get("response_communication_observed_bytes")
        == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("response_communication_invariant_pass") is True
        and row.get("p7b_transcript_reference_bytes") == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("p7b_pcs_opening_reference_bytes") == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("p7b_packed_logits_reference_bytes") == 0
        and row.get("p7b_packed_response_reference_bytes")
        == C3B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("p7b_response_communication_no_growth_pass") is True
    )
    fixed = (
        row.get("accelerator_backend") == "cuda-resident"
        and row.get("accelerator_cuda_abi_version") == P7B_CUDA_ABI_VERSION
        and row.get("resident_timing_policy") == P7B_OFFICIAL_RESIDENT_TIMING_POLICY
        and row.get("p7b_gate_profile") == C3B_POD_GATE_PROFILE
        and row.get("p7b_gate_evaluated") is True
        and row.get("p7b_machine_eligible") is True
        and _p7b_git_provenance_valid(row)
        and _realpcg_pod_metadata_valid(row)
        and _c3b_g2_valid(g2, pod=True)
        and communication
        and _c3b_resident_cleanup_valid(row)
    )
    if not fixed:
        return False
    performance = _p7b_sampling_statistics_valid(row) and _p7b_performance_verdict_valid(row)
    expected_g4 = performance and row.get("p7b_all_gates_pass") is True and g2["pass"]
    return performance and row.get("c3b_g4_pass") is expected_g4


def _c3b_cpu_record_valid(row: dict[str, Any]) -> bool:
    return (
        row.get("accelerator_backend") == "cpu"
        and row.get("threads") == 4
        and row.get("c3b_g1_pass") is True
        and row.get("c3b_g4_pass") is None
        and _c3b_g2_valid(row.get("c3b_g2"), pod=False)
    )


def validate_c3b_official_result(path: Path) -> bool:
    """Fail closed on either half of the paired schema-9 C3b verdict."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict) or not _c3b_common_record_valid(raw):
        return False
    if raw.get("accelerator_backend") == "cpu":
        return _c3b_cpu_record_valid(raw)
    if raw.get("accelerator_backend") == "cuda-resident":
        return _c3b_pod_record_valid(raw)
    return False


def _t1_g2_valid(value: Any) -> bool:
    if not isinstance(value, dict):
        return False
    baseline = value.get("baseline_prove_response")
    candidate = value.get("candidate_prove_response")
    if not (
        _c3b_timing_distribution_valid(baseline)
        and _c3b_timing_distribution_valid(candidate)
        and len(baseline["samples_s"]) == 6
        and len(candidate["samples_s"]) == 6
        and _finite_positive(value.get("baseline_s"))
        and _finite_nonnegative(value.get("candidate_s"))
        and _finite_number(value.get("delta_s"))
        and _finite_number(value.get("delta_percent"))
        and value.get("gate_percent") == 5.0
        and _finite_positive(value.get("ceiling_s"))
        and type(value.get("pass")) is bool
        and value.get("timing_policy")
        == "same-process ABBA; one paired warmup + three rounds; protocol-core prove wall"
        and value.get("baseline_source")
        == "frozen C3b boundary-authentication control arm in this binary"
        and _same_number(value["baseline_s"], baseline["median_s"])
        and _same_number(value["candidate_s"], candidate["median_s"])
        and _same_finite_number(value["delta_s"], value["candidate_s"] - value["baseline_s"])
        and _same_finite_number(
            value["delta_percent"], value["delta_s"] / value["baseline_s"] * 100.0
        )
        and _same_number(value["ceiling_s"], value["baseline_s"] * 1.05)
    ):
        return False
    return value["pass"] is (value["candidate_s"] <= value["ceiling_s"])


def _t1_common_record_valid(row: dict[str, Any]) -> bool:
    transcript_labels = row.get("comm_response_by_label")
    pcs_labels = row.get("comm_pcs_by_label")
    pcs_rows = row.get("pcs_commitments")
    reducer_bytes = None
    if isinstance(transcript_labels, dict):
        reducer_bytes = transcript_labels.get("t1_eq_round_corrections", 0) + transcript_labels.get(
            "t1_eq_terminal_correction", 0
        )
    common = (
        row.get("report_schema_version") == T1_REPORT_SCHEMA_VERSION
        and row.get("milestone") in ("T1-G1", "T1-G4")
        and row.get("git_dirty") is False
        and _full_git_sha(row.get("git_sha"))
        and row.get("benchmark_warmup_repetitions", 0) >= 1
        and row.get("benchmark_repetitions", 0) >= 3
        and row.get("t_prefill") == 100
        and row.get("n_decode") == 50
        and row.get("accepted") is True
        and row.get("chunked_accepted") is True
        and row.get("golden_decode_checked") is True
        and row.get("golden_decode_match") is True
        and row.get("gate_flat_cost_per_token") is True
        and _finite_nonnegative(row.get("curve_last_over_first"))
        and row["curve_last_over_first"] <= 1.5
        and row.get("t1_response_gate_bytes") == T1_RESPONSE_GATE_BYTES
        and row.get("t1_response_reference_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("comm_response_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("total_response_download_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("total_response_download_packed_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("t1_auth_correction_gate_bytes") == T1_AUTH_CORRECTION_REFERENCE_BYTES
        and row.get("t1_auth_correction_reference_bytes")
        == T1_AUTH_CORRECTION_REFERENCE_BYTES
        and isinstance(transcript_labels, dict)
        and all(_nonnegative_int(value) for value in transcript_labels.values())
        and sum(transcript_labels.values()) == T1_RESPONSE_REFERENCE_BYTES
        and transcript_labels.get("auth_corrections") == T1_AUTH_CORRECTION_REFERENCE_BYTES
        and reducer_bytes == T1_EQ_REDUCER_TRANSCRIPT_BYTES
        and transcript_labels.get("t1_q_bridge_correction")
        == T1_Q_BRIDGE_CORRECTION_BYTES
        and row.get("t1_eq_reducer_transcript_bytes") == T1_EQ_REDUCER_TRANSCRIPT_BYTES
        and row.get("t1_q_bridge_correction_bytes") == T1_Q_BRIDGE_CORRECTION_BYTES
        and row.get("pcs_opening_bytes_total") == C3B_PCS_OPENING_REFERENCE_BYTES
        and isinstance(pcs_labels, dict)
        and all(_nonnegative_int(value) for value in pcs_labels.values())
        and sum(pcs_labels.values()) == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("pcs_n_queries") == 120
        and isinstance(pcs_rows, list)
        and len(pcs_rows) == 2
        and all(isinstance(item, dict) and item.get("verified") is True for item in pcs_rows)
        and row.get("public_logits_bytes") == 0
        and row.get("public_logits_packed_bytes") == 0
        and row.get("n_weight_claims") == 96
        and row.get("n_embed_claims") == 6
        and row.get("closure_prod_claims") == T1_PROD_CLAIMS
        and row.get("closure_zero_claims") == T1_ZERO_CLAIMS
        and row.get("corr_sub_corrs") == T1_SUB_CORRS
        and row.get("corr_full_corrs") == T1_FULL_CORRS
        and row.get("emult_instances_total") == T1_EMULT_INSTANCES_TOTAL
        and row.get("t1_emult_other_total") == T1_EMULT_OTHER_TOTAL
        and row.get("t1_exact_counter_pass") is True
        and row.get("t1_g3_pass") is True
        and row.get("c3b_transcript_category_sum_pass") is True
        and row.get("c3b_pcs_category_sum_pass") is True
        and row.get("c3b_public_logits_disabled") is True
        and row.get("pcg_backend") == "real"
        and row.get("ggm_prg") == "aes128-mmo"
        and row.get("pcg_production_ready") is True
        and row.get("pcg_setup_instances") == 1
        and row.get("pcg_setup_wire_count_invariant_pass") is True
        and row.get("pcg_mock_prepass_counters_match") is True
        and row.get("pcg_mock_prepass_channel_ledger_digest_match") is True
        and row.get("pcg_mock_prepass_allocation_digest_match") is True
        and row.get("pcg_allocation_hash_match") is True
        and row.get("pcg_response_authorization_burned_before_setup") is True
        and row.get("pcg_burn_on_success_or_abort") is True
        and row.get("pcg_reconnect_retry_resume_allowed") is False
    )
    return common and _c3b_spool_and_lifecycle_valid(row)


def _t1_cpu_record_valid(row: dict[str, Any]) -> bool:
    g2 = row.get("t1_g2")
    return (
        row.get("milestone") == "T1-G1"
        and row.get("accelerator_backend") == "cpu"
        and row.get("threads") == 4
        and _t1_g2_valid(g2)
        and row.get("t1_g1_pass") is g2["pass"]
        and row.get("t1_g4_pass") is None
    )


def _t1_pod_record_valid(row: dict[str, Any]) -> bool:
    communication = (
        row.get("response_communication_envelope_bytes") == 200_000_000
        and row.get("response_communication_observed_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("response_communication_invariant_pass") is True
        and row.get("p7b_transcript_reference_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("p7b_pcs_opening_reference_bytes") == C3B_PCS_OPENING_REFERENCE_BYTES
        and row.get("p7b_packed_logits_reference_bytes") == 0
        and row.get("p7b_packed_response_reference_bytes") == T1_RESPONSE_REFERENCE_BYTES
        and row.get("p7b_response_communication_no_growth_pass") is True
    )
    fixed = (
        row.get("milestone") == "T1-G4"
        and row.get("accelerator_backend") == "cuda-resident"
        and row.get("accelerator_cuda_abi_version") == P7B_CUDA_ABI_VERSION
        and row.get("resident_timing_policy") == P7B_OFFICIAL_RESIDENT_TIMING_POLICY
        and row.get("p7b_gate_profile") == T1_POD_GATE_PROFILE
        and row.get("p7b_gate_evaluated") is True
        and row.get("p7b_machine_eligible") is True
        and _p7b_git_provenance_valid(row)
        and _realpcg_pod_metadata_valid(row)
        and row.get("t1_g1_pass") is None
        and row.get("t1_g2") is None
        and communication
        and _c3b_resident_cleanup_valid(row)
    )
    if not fixed:
        return False
    performance = _p7b_sampling_statistics_valid(row) and _p7b_performance_verdict_valid(row)
    expected_g4 = performance and row.get("p7b_all_gates_pass") is True
    return performance and row.get("t1_g4_pass") is expected_g4


def validate_t1_official_result(path: Path) -> bool:
    """Fail closed on either half of the paired schema-10 T1 verdict."""
    try:
        raw = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(raw, dict) or not _t1_common_record_valid(raw):
        return False
    if raw.get("accelerator_backend") == "cpu":
        return _t1_cpu_record_valid(raw)
    if raw.get("accelerator_backend") == "cuda-resident":
        return _t1_pod_record_valid(raw)
    return False


def _finite_nonnegative(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def _finite_positive(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def _finite_number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def _same_number(left: Any, right: Any) -> bool:
    return _finite_nonnegative(left) and _finite_nonnegative(right) and math.isclose(
        left, right, rel_tol=0.0, abs_tol=1e-12
    )


def _same_finite_number(left: Any, right: Any) -> bool:
    return _finite_number(left) and _finite_number(right) and math.isclose(
        left, right, rel_tol=0.0, abs_tol=1e-12
    )


def _full_git_sha(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 40
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def _full_hex_digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdefABCDEF" for char in value)
    )


def _p7b_git_provenance_valid(row: dict[str, Any]) -> bool:
    before = row.get("git_sha_before_benchmark")
    after = row.get("git_sha_before_serialization")
    return _full_git_sha(before) and before == after and row.get("git_sha") == before


def _p7b_machine_metadata_valid(row: dict[str, Any]) -> bool:
    cloud = row.get("cloud")
    if not isinstance(cloud, dict):
        return False
    fields = (
        "provider",
        "instance_id",
        "region",
        "image",
        "driver_version",
        "cuda_version",
        "gpu_sku",
        "cpu_model",
        "ram_gib",
        "vcpus",
    )
    if not all(isinstance(cloud.get(field), str) and cloud[field].strip() for field in fields):
        return False
    expected = {
        "provider": "RunPod",
        "region": "eur-is-1",
        "image": "Ubuntu 24.04.3 LTS",
        "driver_version": "580.159.04",
        "cuda_version": "12.8",
        "gpu_sku": "NVIDIA A100-SXM4-80GB",
        "cpu_model": "AMD EPYC 7713 64-Core Processor",
        "ram_gib": "1008",
        "vcpus": "255",
    }
    return (
        type(row.get("threads")) is int
        and row["threads"] == P7B_OFFICIAL_RAYON_THREADS
        and all(cloud.get(field) == value for field, value in expected.items())
    )


def _timing_distribution_valid(timing: Any, samples: list[float]) -> bool:
    if not isinstance(timing, dict) or timing.get("samples_s") != samples or not samples:
        return False
    if not all(_finite_nonnegative(sample) for sample in samples):
        return False
    upper_median = sorted(samples)[len(samples) // 2]
    return _same_number(timing.get("median_s"), upper_median)


def _p7b_sampling_statistics_valid(row: dict[str, Any]) -> bool:
    measured = row.get("benchmark_repetitions")
    repetitions = row.get("repetitions")
    if (
        type(measured) is not int
        or measured < 3
        or not isinstance(repetitions, list)
        or len(repetitions) != measured
        or row.get("p7b_timing_statistic") != P7B_TIMING_STATISTIC
        or row.get("p7b_counter_statistic") != P7B_COUNTER_STATISTIC
    ):
        return False
    if any(not isinstance(rep, dict) for rep in repetitions):
        return False
    if [rep.get("repetition") for rep in repetitions] != list(range(1, measured + 1)):
        return False
    prefill_samples = [rep.get("t_prove_prefill_only_s") for rep in repetitions]
    decode_samples = [rep.get("t_prove_decode_marginal_s") for rep in repetitions]
    if not _timing_distribution_valid(row.get("prove_prefill_timing"), prefill_samples):
        return False
    if not _timing_distribution_valid(row.get("prove_decode_marginal_timing"), decode_samples):
        return False
    sessions = [rep.get("accelerator_session") for rep in repetitions]
    if any(not isinstance(session, dict) for session in sessions):
        return False
    syncs = [session.get("synchronizations") for session in sessions]
    sync_wall_s = [session.get("synchronization_s") for session in sessions]
    session_wall_s = [rep.get("t_response_session_wall_s") for rep in repetitions]
    sync_wall_fractions = [rep.get("p7b_sync_wall_fraction") for rep in repetitions]
    reported_sync_wall_s = [rep.get("p7b_sync_wall_s") for rep in repetitions]
    h2d = [session.get("h2d_bytes") for session in sessions]
    if (
        not all(_nonnegative_int(value) for value in syncs + h2d)
        or not all(_finite_nonnegative(value) for value in sync_wall_s)
        or not all(_finite_nonnegative(value) and value > 0 for value in session_wall_s)
        or not all(_finite_nonnegative(value) for value in sync_wall_fractions)
    ):
        return False
    expected_sync_wall_fractions = [
        sync_wall / session_wall
        for sync_wall, session_wall in zip(sync_wall_s, session_wall_s, strict=True)
    ]
    if not all(
        _same_number(observed, expected)
        for observed, expected in zip(
            sync_wall_fractions, expected_sync_wall_fractions, strict=True
        )
    ):
        return False
    if any(value is not None for value in reported_sync_wall_s) and not all(
        _same_number(observed, expected)
        for observed, expected in zip(reported_sync_wall_s, sync_wall_s, strict=True)
    ):
        return False
    absolute_observed = row.get("p7b_sync_wall_absolute_observed_s")
    if absolute_observed is not None and not _same_number(absolute_observed, max(sync_wall_s)):
        return False
    return (
        _same_number(
            row.get("p7b_prefill_core_observed_s"),
            row["prove_prefill_timing"]["median_s"],
        )
        and _same_number(
            row.get("p7b_decode_marginal_observed_s"),
            row["prove_decode_marginal_timing"]["median_s"],
        )
        and row.get("p7b_sync_observed") == max(syncs)
        and _same_number(
            row.get("p7b_sync_wall_fraction_observed"),
            max(expected_sync_wall_fractions),
        )
        and row.get("p7b_h2d_observed_bytes") == max(h2d)
    )


def _p7b_communication_valid(row: dict[str, Any]) -> bool:
    communication = row.get("communication")
    if not isinstance(communication, dict):
        return False
    transcript = communication.get("response_bytes")
    pcs = communication.get("pcs_opening_bytes")
    packed_logits = communication.get("public_logits_packed_bytes")
    observed = row.get("response_communication_observed_bytes")
    if not all(_nonnegative_int(value) for value in (transcript, pcs, packed_logits, observed)):
        return False
    return (
        row.get("response_communication_envelope_bytes")
        == P7B_RESPONSE_COMMUNICATION_ENVELOPE_BYTES
        and row.get("p7b_transcript_reference_bytes") == P7B_TRANSCRIPT_REFERENCE_BYTES
        and row.get("p7b_pcs_opening_reference_bytes") == P7B_PCS_OPENING_REFERENCE_BYTES
        and row.get("p7b_packed_logits_reference_bytes") == P7B_PACKED_LOGITS_REFERENCE_BYTES
        and row.get("p7b_packed_response_reference_bytes")
        == P7B_PACKED_RESPONSE_REFERENCE_BYTES
        and observed == transcript + packed_logits
        and row.get("packed_response_bytes") == observed
        and observed <= P7B_RESPONSE_COMMUNICATION_ENVELOPE_BYTES
        and transcript <= P7B_TRANSCRIPT_REFERENCE_BYTES
        and pcs <= P7B_PCS_OPENING_REFERENCE_BYTES
        and packed_logits <= P7B_PACKED_LOGITS_REFERENCE_BYTES
        and transcript + packed_logits <= P7B_PACKED_RESPONSE_REFERENCE_BYTES
        and row.get("response_communication_invariant_pass") is True
        and row.get("p7b_response_communication_no_growth_pass") is True
    )


def _p7b_performance_verdict_valid(row: dict[str, Any]) -> bool:
    absolute_profile = row.get("p7b_gate_profile") in (
        FASE_D_POD_GATE_PROFILE_V2,
        C3B_POD_GATE_PROFILE,
        T1_POD_GATE_PROFILE,
    )
    thresholds = (
        row.get("p7b_prefill_core_gate_s") == P7B_PREFILL_CORE_GATE_S
        and row.get("p7b_decode_marginal_gate_s") == P7B_DECODE_MARGINAL_GATE_S
        and row.get("p7b_sync_count_gate_retired") is True
        and row.get("p7b_h2d_gate_bytes") == P7B_H2D_GATE_BYTES
        and (
            (
                absolute_profile
                and row.get("p7b_sync_wall_fraction_gate") is None
                and row.get("p7b_sync_wall_absolute_gate_s")
                == FASE_D_POD_SYNC_WALL_ABSOLUTE_GATE_S
            )
            or (
                not absolute_profile
                and row.get("p7b_sync_wall_fraction_gate")
                == P7B_SYNC_WALL_FRACTION_GATE
                and row.get("p7b_sync_wall_absolute_gate_s") is None
            )
        )
    )
    sync_observation = row.get(
        "p7b_sync_wall_absolute_observed_s"
        if absolute_profile
        else "p7b_sync_wall_fraction_observed"
    )
    observations = (
        row.get("p7b_prefill_core_observed_s"),
        row.get("p7b_decode_marginal_observed_s"),
        sync_observation,
        row.get("p7b_h2d_observed_bytes"),
    )
    passes = (
        row.get("p7b_prefill_core_gate_pass"),
        row.get("p7b_decode_marginal_gate_pass"),
        row.get(
            "p7b_sync_wall_absolute_gate_pass"
            if absolute_profile
            else "p7b_sync_wall_fraction_gate_pass"
        ),
        row.get("p7b_h2d_gate_pass"),
    )
    opposite_sync_pass = row.get(
        "p7b_sync_wall_fraction_gate_pass"
        if absolute_profile
        else "p7b_sync_wall_absolute_gate_pass"
    )
    if (
        not thresholds
        or not _finite_nonnegative(observations[0])
        or not _finite_nonnegative(observations[1])
        or not _finite_nonnegative(observations[2])
        or not _nonnegative_int(observations[3])
        or any(type(value) is not bool for value in passes)
        or opposite_sync_pass is not None
        or type(row.get("p7b_all_gates_pass")) is not bool
    ):
        return False
    expected = (
        observations[0] <= P7B_PREFILL_CORE_GATE_S,
        observations[1] <= P7B_DECODE_MARGINAL_GATE_S,
        observations[2]
        <= (
            FASE_D_POD_SYNC_WALL_ABSOLUTE_GATE_S
            if absolute_profile
            else P7B_SYNC_WALL_FRACTION_GATE
        ),
        observations[3] <= P7B_H2D_GATE_BYTES,
    )
    return passes == expected and row.get("p7b_all_gates_pass") is all(expected)


def shape_memory_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for result in results:
        if result.get("milestone") != "P7-shape-memory-sweep":
            continue
        validation = result.get("validation") or {}
        if not validation or not all(validation.values()):
            continue
        rows.append(
            {
                "_mtime": result["_mtime"],
                "source": result["_path"],
                "git_dirty": result.get("git_dirty"),
                "source_resident_result": result.get("source_resident_result"),
                "source_resident_peak_device_bytes": result.get(
                    "source_resident_peak_device_bytes"
                ),
                "source_resident_workspace_after_cleanup_bytes": result.get(
                    "source_resident_workspace_after_cleanup_bytes"
                ),
                "sequence_lengths": result.get("sequence_lengths"),
                "profiles": result.get("profiles"),
                "validation": validation,
                "scope": result.get("scope"),
            }
        )
    rows.sort(key=lambda row: (row["_mtime"], row["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def same_host_native(
    native_profiles: list[dict[str, Any]], integrated: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not integrated:
        return None
    instance_id = (integrated.get("cloud") or {}).get("instance_id")
    if not instance_id:
        return None
    matches = [
        row
        for row in native_profiles
        if row.get("milestone") == "P7-gpu-native-inference"
        and not row.get("git_dirty", True)
        and (row.get("cloud") or {}).get("instance_id") == instance_id
    ]
    return matches[-1] if matches else None


def integrated_same_host_result(
    proof: dict[str, Any] | None, native: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not proof or not native:
        return None
    proof_rho = {
        "prefill": proof["prove_prefill_s"] / native["prefill_s"],
        "decode": proof["prove_decode_marginal_s"] / native["decode_50_s"],
    }
    result: dict[str, Any] = {
        "same_instance": True,
        "native_source": native["source"],
        "proof_source": proof["source"],
        "rho_definition": "protocol-core prover wall / same-host exact native-GPU inference wall",
        "proof_rho": proof_rho,
        "targets": P7_RHO_TARGETS,
        "target_met": {
            phase: proof_rho[phase] <= P7_RHO_TARGETS[phase]
            for phase in ("prefill", "decode")
        },
        "required_speedup_to_target": {
            phase: proof_rho[phase] / P7_RHO_TARGETS[phase]
            for phase in ("prefill", "decode")
        },
        "native_anchor_plus_protocol_core_s": {
            "prefill": native["prefill_s"] + proof["prove_prefill_s"],
            "decode_50": native["decode_50_s"] + proof["prove_decode_marginal_s"],
        },
        "pcs": {
            "commit_offline_s": (proof.get("pcs_commit_timing") or {}).get("median_s"),
            "open_online_s": (proof.get("pcs_open_timing") or {}).get("median_s"),
            "verify_s": (proof.get("pcs_verify_timing") or {}).get("median_s"),
        },
        "pcg": {
            "backend": proof.get("pcg_backend"),
            "setup_offline_s": proof.get("pcg_real_phase_a_total_s"),
            "setup_comm_bytes": proof.get("pcg_setup_comm_bytes"),
            "production_grade": False,
        },
        "verifier_accounted_s": proof.get("verifier_accounted_s"),
        "response_session_wall_s": proof.get("response_session_wall_s"),
    }
    online_response = proof.get("prover_online_accounted_response_s")
    online_decode = proof.get("prover_online_accounted_decode_marginal_s")
    if online_response is not None and online_decode is not None:
        result["online_accounted"] = {
            "definition": "protocol core + PCS opening + final closure exchange; closure contains both local roles",
            "response_s": online_response,
            "decode_marginal_s": online_decode,
            "decode_rho": online_decode / native["decode_50_s"],
        }
    witness_prefill = (proof.get("accelerator_witness") or {}).get("measurement_wall_s")
    witness_response = (proof.get("accelerator_response_witness") or {}).get(
        "measurement_wall_s"
    )
    if witness_prefill is not None and witness_response is not None:
        result["measured_resident_pipeline_s"] = {
            "prefill_inference_plus_protocol_core": witness_prefill
            + proof["prove_prefill_s"],
            "response_inference_plus_online_accounted": (
                witness_response + online_response if online_response is not None else None
            ),
            "response_inference_plus_full_session_wall": (
                witness_response + proof["response_session_wall_s"]
                if proof.get("response_session_wall_s") is not None
                else None
            ),
        }
    return result


def decode_marginal_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        labels = r.get("comm_decode_marginal_by_label")
        if not labels:
            continue
        top = sorted(labels.items(), key=lambda kv: (-kv[1], kv[0]))[:12]
        rows.append(
            {
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "t_prefill": r.get("t_prefill"),
                "n_decode": r.get("n_decode"),
                "comm_decode_marginal_bytes": r.get("comm_decode_marginal_bytes"),
                "comm_decode_bytes_per_token": r.get("comm_decode_bytes_per_token"),
                "label_sum_bytes": sum(labels.values()),
                "top_labels": [{"label": k, "bytes": v} for k, v in top],
            }
        )
    rows.sort(key=lambda x: (x["t_prefill"] or 0, x["n_decode"] or 0, x["source"]))
    return rows


def p7_report(results_dir: Path) -> dict[str, Any]:
    results = load_results(results_dir)
    baseline = select_p6_record(results)
    c1_record = select_c1_record(results)
    packed = select_packed_source(results, baseline)

    public_logits_packed = (
        int(packed["public_logits_packed_bytes"])
        if packed and "public_logits_packed_bytes" in packed
        else int(baseline.get("public_logits_packed_bytes", baseline["public_logits_bytes"]))
    )
    current_packed_download = int(baseline["comm_response_bytes"]) + public_logits_packed

    current_formula = pcs_total(LAYER_PARAMS, 8, EMBED_PARAMS, 6)
    current_measured = int(baseline["pcs_opening_bytes_total"])
    formula_matches = current_formula == current_measured
    mock_pcg = mock_pcg_lower_bounds(results)
    real_pcg = real_pcg_phase_a(results)
    real_pcg_b = real_pcg_phase_b(results)
    gpu_rooflines = gpu_roofline_profiles(results)
    full_gpu_rooflines = [r for r in gpu_rooflines if r["milestone"] == "P7-gpu-roofline"]
    gpu_roofline_record = full_gpu_rooflines[-1] if full_gpu_rooflines else None
    gpu_fused = gpu_fused_epilogue_profiles(results)
    full_gpu_fused = [r for r in gpu_fused if r["milestone"] == "P7-gpu-fused-epilogue"]
    gpu_fused_record = full_gpu_fused[-1] if full_gpu_fused else None
    gpu_logup = gpu_logup_tree_profiles(results)
    full_gpu_logup = [r for r in gpu_logup if r["milestone"] == "P7-gpu-logup-tree"]
    gpu_logup_record = full_gpu_logup[-1] if full_gpu_logup else None
    gpu_logup_rounds = gpu_logup_round_profiles(results)
    full_gpu_logup_rounds = [
        r
        for r in gpu_logup_rounds
        if r["milestone"] == "P7-gpu-logup-rounds" and r["gate_speedup_ge_5_48"]
    ]
    gpu_logup_round_record = full_gpu_logup_rounds[-1] if full_gpu_logup_rounds else None
    gpu_logup_blind_rounds = gpu_logup_blind_round_profiles(results)
    full_gpu_logup_blind_rounds = [
        r
        for r in gpu_logup_blind_rounds
        if r["milestone"] == "P7-gpu-logup-blind-rounds"
        and r["gate_speedup_ge_5_48_and_overhead_le_1_05"]
    ]
    gpu_logup_blind_round_record = (
        full_gpu_logup_blind_rounds[-1] if full_gpu_logup_blind_rounds else None
    )
    gpu_pcs = gpu_pcs_arithmetic_profiles(results)
    full_gpu_pcs = [r for r in gpu_pcs if r["milestone"] == "P7-gpu-pcs-arithmetic"]
    gpu_pcs_record = full_gpu_pcs[-1] if full_gpu_pcs else None
    gpu_blake3 = gpu_blake3_merkle_profiles(results)
    full_gpu_blake3 = [r for r in gpu_blake3 if r["milestone"] == "P7-gpu-blake3-merkle"]
    gpu_blake3_record = full_gpu_blake3[-1] if full_gpu_blake3 else None
    gpu_hybrid = integrated_hybrid_profiles(results)
    full_gpu_hybrid = [
        r
        for r in gpu_hybrid
        if r["milestone"] == "P7-integrated-hybrid" and not r.get("git_dirty", True)
    ]
    gpu_hybrid_record = full_gpu_hybrid[-1] if full_gpu_hybrid else None
    gpu_resident = integrated_resident_profiles(results)
    full_gpu_resident = [
        r
        for r in gpu_resident
        if resident_run_of_record_eligible(r)
    ]
    gpu_resident_record = full_gpu_resident[-1] if full_gpu_resident else None
    shape_memory = shape_memory_profiles(results)
    clean_shape_memory = [row for row in shape_memory if not row.get("git_dirty", True)]
    shape_memory_record = clean_shape_memory[-1] if clean_shape_memory else None
    gpu_native = gpu_native_inference_profiles(results)
    full_gpu_native = [
        r
        for r in gpu_native
        if r["milestone"] == "P7-gpu-native-inference" and not r.get("git_dirty", True)
    ]
    resident_native_record = same_host_native(gpu_native, gpu_resident_record)
    hybrid_native_record = same_host_native(gpu_native, gpu_hybrid_record)
    gpu_native_record = (
        resident_native_record
        or hybrid_native_record
        or (full_gpu_native[-1] if full_gpu_native else None)
    )
    gpu_budget = rho_model(baseline)
    required_prover_gpu_speedup = None
    if gpu_native_record:
        proof_only_budget = {
            "prefill_s": gpu_native_record["prefill_s"] * P7_RHO_TARGETS["prefill"],
            "decode_50_s": gpu_native_record["decode_50_s"] * P7_RHO_TARGETS["decode"],
        }
        if (gpu_native_record.get("baseline") or {}).get("source") == baseline["_path"]:
            relative = gpu_budget["required_relative_prover_vs_native_speedup"]
            native = gpu_native_record["native_gpu_speedup"]
            required_prover_gpu_speedup = {
                phase: relative[phase] * native[phase] for phase in ("prefill", "decode")
            }
    else:
        proof_only_budget = None
    integrated_hybrid_rho = integrated_same_host_result(
        gpu_hybrid_record, hybrid_native_record
    )
    integrated_resident_rho = integrated_same_host_result(
        gpu_resident_record, resident_native_record
    )
    if integrated_hybrid_rho:
        # Preserve the schema consumed by the historical hybrid artifact.
        integrated_hybrid_rho["required_speedup_from_hybrid_to_target"] = (
            integrated_hybrid_rho["required_speedup_to_target"]
        )
        integrated_hybrid_rho["inference_plus_proving_s"] = integrated_hybrid_rho[
            "native_anchor_plus_protocol_core_s"
        ]
    pcg_status = (
        "phase_b_measured_not_production"
        if real_pcg_b
        else "phase_a_measured_mock_stub" if real_pcg else "not_measured_in_local_vm"
    )
    pcg_note = (
        "Real-PCG phase B setup measured, but production_ready is false until WYKW malicious checks and table-derived LPN parameters are closed."
        if real_pcg_b
        else (
        "Real-PCG phase A measured with a mock-stub base VOLE; phase B still needs real base OTs/OT extension/setup communication."
        if real_pcg
        else "P7 final go/no-go still needs a real silent-VOLE setup/expansion measurement for this volume."
        )
    )

    p6_comm = {
        "source": baseline["_path"],
        "packed_logits_source": packed["_path"] if packed else None,
        "comm_prefill_bytes": baseline["comm_prefill_bytes"],
        "comm_decode_marginal_bytes": baseline["comm_decode_marginal_bytes"],
        "comm_decode_bytes_per_token": baseline["comm_decode_bytes_per_token"],
        "pcs_opening_bytes": current_measured,
        "public_logits_raw_bytes": baseline["public_logits_bytes"],
        "public_logits_packed_bytes": public_logits_packed,
        "total_response_download_raw_bytes": int(baseline["comm_response_bytes"])
        + int(baseline["public_logits_bytes"]),
        "total_response_download_packed_bytes": current_packed_download,
    }

    report = {
        "report_schema_version": 4 if gpu_resident_record else 2,
        "milestone": "P7",
        "date": _dt.date.today().isoformat(),
        "git_sha": git(["rev-parse", "--short", "HEAD"]),
        "git_dirty": git_dirty(),
        "machine": f"{platform.system().lower()} {platform.machine()}",
        "cloud": (
            gpu_resident_record.get("cloud")
            if gpu_resident_record
            else gpu_hybrid_record.get("cloud")
            if gpu_hybrid_record
            else baseline.get("cloud")
        ),
        "baseline": {
            "source": baseline["_path"],
            "git_dirty": baseline.get("git_dirty"),
            "cloud": baseline.get("cloud"),
            "accepted": baseline.get("accepted"),
            "t_prefill": baseline.get("t_prefill"),
            "n_decode": baseline.get("n_decode"),
            "rho_prefill_cpu": baseline.get("rho_prefill"),
            "rho_decode_cpu": baseline.get("rho_decode"),
            "prove_response_s": baseline.get("t_prove_response_s"),
            "prove_decode_marginal_s": baseline.get("t_prove_decode_marginal_s"),
            "verify_response_s": baseline.get("t_verify_response_s"),
            "pcs_open_s": baseline.get("pcs_open_total_s"),
            "pcs_verify_s": baseline.get("pcs_verify_total_s"),
            "peak_rss_gb": baseline.get("peak_rss_gb"),
        },
        "rho_history": summarize_rhos(results),
        "communication": p6_comm,
        "c1_communication_reference": (
            {
                "source": c1_record["_path"],
                "git_sha": c1_record["git_sha"],
                "response_transcript_bytes": c1_record["comm_response_bytes"],
                "pcs_opening_bytes": c1_record["pcs_opening_bytes_total"],
                "public_logits_packed_bytes": c1_record["public_logits_packed_bytes"],
                "packed_response_bytes": c1_record["total_response_download_packed_bytes"],
                "identity_seam_alias_values": c1_record["c1_identity_seam_reuse"][
                    "identity_seam_alias_values"
                ],
                "historical_runpod_a100_v1_packed_response_bytes": (
                    P7B_PACKED_RESPONSE_REFERENCE_BYTES
                ),
            }
            if c1_record
            else None
        ),
        "measured_pcs_profiles": measured_pcs_profiles(results, baseline),
        "decode_marginal_profiles": decode_marginal_profiles(results),
        "pcs_formula_check": {
            "matches_p6_measured_bytes": formula_matches,
            "formula_total_bytes": current_formula,
            "measured_total_bytes": current_measured,
            "layer_one_opening": multi_open_breakdown(LAYER_PARAMS, 8),
            "embed_opening": multi_open_breakdown(EMBED_PARAMS, 6),
            "rate": rate(LAYER_PARAMS),
            "relative_distance": distance(LAYER_PARAMS),
            "q200_error_bits": query_error_bits(LAYER_PARAMS),
            "q_for_60_bits": queries_for_bits(LAYER_PARAMS, 60.0),
        },
        "pcs_scenarios": pcs_scenarios(baseline, current_packed_download),
        "gpu_budget_model": gpu_budget,
        "gpu_roofline": {
            "status": "measured_screening_pass" if gpu_roofline_record else "not_measured",
            "run_of_record": gpu_roofline_record,
            "profiles": gpu_rooflines,
            "note": "Historical arithmetic screening; full hybrid integration is measured and the device-resident gate remains open.",
        },
        "gpu_fused_epilogue": {
            "status": "measured_gate_pass" if gpu_fused_record else "not_measured",
            "run_of_record": gpu_fused_record,
            "profiles": gpu_fused,
            "note": "Historical P1-equivalent screening; hybrid proving integration landed, resident witness/proving remains open.",
        },
        "gpu_logup_tree": {
            "status": "measured_gate_pass" if gpu_logup_record else "not_measured",
            "run_of_record": gpu_logup_record,
            "profiles": gpu_logup,
            "note": "Historical lookup-tree screening; rounds and hybrid proving integration are now measured separately.",
        },
        "gpu_logup_rounds": {
            "status": "measured_gate_pass" if gpu_logup_round_record else "not_measured",
            "run_of_record": gpu_logup_round_record,
            "profiles": gpu_logup_rounds,
            "note": "Historical clear-round screening; see blind-round and integrated-hybrid sections for correction plumbing and e2e attribution.",
        },
        "gpu_logup_blind_rounds": {
            "status": "measured_gate_pass" if gpu_logup_blind_round_record else "not_measured",
            "run_of_record": gpu_logup_blind_round_record,
            "profiles": gpu_logup_blind_rounds,
            "note": "Historical blind-round screening; aux leaves and corrections are covered by differential/full hybrid integration, resident buffers remain open.",
        },
        "gpu_pcs_arithmetic": {
            "status": "measured_gate_pass" if gpu_pcs_record else "not_measured",
            "run_of_record": gpu_pcs_record,
            "profiles": gpu_pcs,
            "note": "Historical arithmetic screening; mask rows and hybrid proving integration are covered by the integrated gate.",
        },
        "gpu_blake3_merkle": {
            "status": "measured_gate_pass" if gpu_blake3_record else "not_measured",
            "run_of_record": gpu_blake3_record,
            "profiles": gpu_blake3,
            "note": "Historical gather/hash screening; mask rows and hybrid proving integration are covered by the integrated gate.",
        },
        "integrated_hybrid": {
            "status": (
                "measured_attribution_pass_resident_required"
                if integrated_hybrid_rho
                else "measured_without_same_host_native_anchor"
                if gpu_hybrid_record
                else "not_measured"
            ),
            "run_of_record": gpu_hybrid_record,
            "profiles": gpu_hybrid,
            "same_host_result": integrated_hybrid_rho,
            "note": (
                "Full staged integration preserves correctness, transcript, communication and flat-cost gates, "
                "but H2D/D2H plus CPU residual dominate. This is the attribution gate, not the resident paper result."
            ),
        },
        "integrated_resident": {
            "status": (
                "measured_same_host_targets_pass"
                if integrated_resident_rho
                and all(integrated_resident_rho["target_met"].values())
                else "measured_same_host_targets_fail"
                if integrated_resident_rho
                else "measured_without_same_host_native_anchor"
                if gpu_resident_record
                else "not_measured"
            ),
            "run_of_record": gpu_resident_record,
            "profiles": gpu_resident,
            "same_host_result": integrated_resident_rho,
            "note": (
                "Resident forward, witness and proving share persistent device buffers. "
                "The protocol-core rho remains the preregistered gate; PCS/opening, closures, "
                "verifier, offline commitment and mock-PCG limitations are reported separately "
                "and retained in the measured session wall."
            ),
        },
        "shape_memory_sweep": {
            "status": "analytic_validation_pass" if shape_memory_record else "not_measured",
            "run_of_record": shape_memory_record,
            "profiles": shape_memory,
            "note": (
                "Synthetic formula validation only: GPT-2 is the measured anchor; "
                "Llama-class and gpt-oss rows are not e2e results and project neither "
                "proof time nor proof peak memory."
            ),
        },
        "gpu_native_inference": {
            "status": "measured_exact_golden_pass" if gpu_native_record else "not_measured",
            "run_of_record": gpu_native_record,
            "profiles": gpu_native,
            "required_prover_gpu_speedup_vs_cpu": required_prover_gpu_speedup,
            "proof_only_budget": proof_only_budget,
            "note": "Exact fixed-point full-model prefill and KV decode anchor paired by instance; weights resident, cache-seeding prefill excluded from decode, per-token logits D2H + argmax included.",
        },
        "real_pcg_spike": {
            "status": pcg_status,
            "corr_sub_corrs": baseline.get("corr_sub_corrs"),
            "corr_full_corrs": baseline.get("corr_full_corrs"),
            "mock_pcg_lower_bounds": mock_pcg,
            "real_pcg_phase_a": real_pcg,
            "real_pcg_phase_b": real_pcg_b,
            "note": pcg_note,
        },
        "go_no_go": {
            "local_recommendation": (
                "resident-gates-pass-build-publication-artifact"
                if integrated_resident_rho
                and all(integrated_resident_rho["target_met"].values())
                else "resident-gates-fail-report-result-without-production-claim"
                if integrated_resident_rho
                else "measure-same-host-native-gpu-anchor-for-resident-run"
                if gpu_resident_record
                else "proceed-to-device-resident-prover-integration"
                if integrated_hybrid_rho
                else "measure-same-host-native-gpu-anchor"
                if gpu_hybrid_record
                else "proceed-to-integrated-gpu-prover-measurement"
                if gpu_native_record
                else "proceed-to-proving-path-integration-and-native-gpu-anchor"
                if gpu_logup_blind_round_record
                else "proceed-to-blind-integration-and-native-gpu-anchor"
                if gpu_blake3_record
                else "proceed-to-blake3-merkle-spike"
                if gpu_pcs_record
                else "proceed-to-pcs-hash-spikes"
                if gpu_logup_round_record
                else "proceed-to-logup-rounds-and-pcs-spikes"
                if gpu_logup_record
                else "proceed-to-logup-pcs-kernel-spikes"
                if gpu_fused_record
                else "proceed-to-fused-kernel-spikes"
                if gpu_roofline_record
                else "conditional-go-to-cloud-spikes-only"
            ),
            "summary": (
                "The clean full resident path has a same-host exact native-GPU denominator; "
                "the report retains protocol-core rho, resident inference+proving, full session wall, "
                "PCS/PCG, verifier, communication and memory as separate measured quantities."
                if integrated_resident_rho
                else "Communication, golden decode, verifier and flat-cost gates pass in the full CUDA-hybrid path. "
                "Same-host attribution shows staged transfers and CPU residual dominate by orders of magnitude; "
                "the preregistered resident witness/proving path is required before the final rho go/no-go."
                if integrated_hybrid_rho
                else "Communication is inside the 150-200 MB envelope, but a final rho decision still requires same-host integrated proving and native GPU measurements."
            ),
            "remaining_before_final_go_no_go": (
                []
                if integrated_resident_rho
                else [
                    "device-resident witness consumed directly by the prover without full host materialization",
                    "resident forward/proving share persistent buffers and transfer only protocol messages",
                    "resident 1-warmup/3-repetition full gate passes rho<=10/<=2 with the existing correctness and communication gates",
                ]
                if integrated_hybrid_rho
                else [
                    "same-host native GPU and integrated proving measurements",
                    "device-resident witness/proving path",
                    "golden decode, flat-cost, anti-replay and communication gates",
                ]
            ),
        },
    }
    return report


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for i in range(1, 1000):
        candidate = path.with_name(f"{stem}-{i}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not find unused result path near {path}")


def write_report(report: dict[str, Any], results_dir: Path) -> Path:
    label = f"p7-{report['date']}-{report['git_sha'] or 'unknown'}.json"
    path = unique_path(results_dir / label)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def print_summary(report: dict[str, Any]) -> None:
    comm = report["communication"]
    model = report["gpu_budget_model"]
    print("P7 report")
    print(f"baseline: {report['baseline']['source']} (dirty={report['baseline']['git_dirty']})")
    if comm["packed_logits_source"]:
        print(f"packed logits source: {comm['packed_logits_source']}")
    print()
    print("Communication (MB)")
    print(f"  transcript:          {mb(comm['total_response_download_raw_bytes'] - comm['public_logits_raw_bytes']):8.2f}")
    print(f"  PCS opening:         {mb(comm['pcs_opening_bytes']):8.2f}")
    print(f"  public logits raw:   {mb(comm['public_logits_raw_bytes']):8.2f}")
    print(f"  public logits packed:{mb(comm['public_logits_packed_bytes']):8.2f}")
    print(f"  total raw:           {mb(comm['total_response_download_raw_bytes']):8.2f}")
    print(f"  total packed:        {mb(comm['total_response_download_packed_bytes']):8.2f}")
    print()
    if report.get("measured_pcs_profiles"):
        print("Measured PCS profiles")
        for row in report["measured_pcs_profiles"]:
            packed = row.get("total_response_download_packed_bytes")
            packed_s = f" total={mb(packed):7.2f}" if packed is not None else ""
            print(
                f"  {row['milestone']:<8} Q={row['pcs_n_queries']:<3} "
                f"pcs={mb(row['pcs_opening_bytes_total']):7.2f}{packed_s} "
                f"{row['source']}"
            )
    print()
    pcg = report["real_pcg_spike"].get("mock_pcg_lower_bounds") or []
    if pcg:
        print("Mock-PCG lower bounds")
        for row in pcg:
            print(
                f"  mock total={row['t_total_mock_expansion_s']:.3f}s "
                f"sub={row['corr_sub_corrs']} full={row['corr_full_corrs']} "
                f"{row['source']}"
            )
        print()
    real_pcg = report["real_pcg_spike"].get("real_pcg_phase_a") or []
    if real_pcg:
        print("Real-PCG phase A")
        for row in real_pcg:
            print(
                f"  total={row['t_total_real_expansion_s']:.3f}s "
                f"setup={row['t_setup_stub_s']:.3f}s ggm={row['t_ggm_pprf_s']:.3f}s "
                f"lpn={row['t_lpn_expand_s']:.3f}s check={row['t_consistency_check_s']:.3f}s "
                f"base={row['base_vole']} setup_comm={row['setup_comm_bytes']} B "
                f"{row['source']}"
            )
        print()
    real_pcg_b = report["real_pcg_spike"].get("real_pcg_phase_b") or []
    if real_pcg_b:
        print("Real-PCG phase B")
        for row in real_pcg_b:
            print(
                f"  total={row['t_total_real_expansion_s']:.3f}s "
                f"baseOT={row['t_base_ot_s']:.3f}s otExt={row['t_ot_extension_s']:.3f}s "
                f"ggm={(row['t_ggm_pprf_s'] or 0.0):.3f}s "
                f"lpn={row['t_lpn_expand_s']:.3f}s setup_comm={row['setup_comm_bytes']} B "
                f"production_ready={row['production_ready']} {row['source']}"
            )
        print()
    roofline = report.get("gpu_roofline", {}).get("run_of_record")
    if roofline:
        print("GPU Goldilocks/Fp2 roofline")
        print(
            f"  stream {roofline['stream_gpu_cpu_speedup']:.2f}x, "
            f"{roofline['stream_gpu_bandwidth_gb_s']:.1f} GB/s; "
            f"chain {roofline['chain_gpu_cpu_speedup']:.2f}x, "
            f"{roofline['chain_gpu_fp2_mul_s'] / 1e9:.2f} G Fp2-mul/s "
            f"{roofline['source']}"
        )
        print()
    fused = report.get("gpu_fused_epilogue", {}).get("run_of_record")
    if fused:
        shape_rhos = ", ".join(f"{row['n']}:{row['rho_kernel']:.3f}" for row in fused["shapes"])
        print("GPU fused GEMM-MAC epilogue")
        print(
            f"  weighted rho={fused['weighted_rho_kernel']:.3f}; "
            f"shape rhos [{shape_rhos}] {fused['source']}"
        )
        print()
    logup = report.get("gpu_logup_tree", {}).get("run_of_record")
    if logup:
        print("GPU LogUp fraction-tree build")
        print(
            f"  N={logup['parameters']['n']} CPU={logup['cpu_s']:.3f}s "
            f"GPU={logup['gpu_s']:.4f}s speedup={logup['gpu_cpu_speedup']:.2f}x "
            f"{logup['source']}"
        )
        print()
    logup_rounds = report.get("gpu_logup_rounds", {}).get("run_of_record")
    if logup_rounds:
        print("GPU LogUp general rounds/folds")
        print(
            f"  N={logup_rounds['parameters']['n']} CPU={logup_rounds['cpu_s']:.3f}s "
            f"GPU={logup_rounds['gpu_s']:.4f}s speedup={logup_rounds['gpu_cpu_speedup']:.2f}x "
            f"{logup_rounds['source']}"
        )
        print()
    blind_rounds = report.get("gpu_logup_blind_rounds", {}).get("run_of_record")
    if blind_rounds:
        print("GPU blind LogUp correction plumbing")
        print(
            f"  N={blind_rounds['parameters']['n']} CPU={blind_rounds['cpu_blind_s']:.3f}s "
            f"GPU={blind_rounds['gpu_blind_s']:.4f}s "
            f"speedup={blind_rounds['gpu_cpu_speedup']:.2f}x "
            f"blind/clear={blind_rounds['blind_over_clear']:.3f} "
            f"{blind_rounds['source']}"
        )
        print()
    pcs = report.get("gpu_pcs_arithmetic", {}).get("run_of_record")
    if pcs:
        print("GPU PCS arithmetic")
        print(
            f"  NTT {pcs['ntt']['gpu_cpu_speedup']:.2f}x "
            f"({pcs['ntt']['gpu_s'] * 1e3:.2f} ms); combine_rows "
            f"{pcs['combine_rows']['gpu_cpu_speedup']:.2f}x "
            f"({pcs['combine_rows']['gpu_s'] * 1e3:.2f} ms) {pcs['source']}"
        )
        print()
    blake3 = report.get("gpu_blake3_merkle", {}).get("run_of_record")
    if blake3:
        print("GPU PCS column gather + BLAKE3/Merkle")
        print(
            f"  {blake3['parameters']['rows']}x{blake3['parameters']['cols']} "
            f"Rust={blake3['rust_cpu_s'] * 1e3:.2f} ms "
            f"GPU={blake3['gpu_s'] * 1e3:.2f} ms "
            f"speedup={blake3['gpu_cpu_speedup']:.2f}x {blake3['source']}"
        )
        print()
    native_gpu = report.get("gpu_native_inference", {}).get("run_of_record")
    if native_gpu:
        targets = report["gpu_native_inference"]["required_prover_gpu_speedup_vs_cpu"]
        print("Native fixed-point GPU inference")
        print(
            f"  prefill={native_gpu['prefill_s'] * 1e3:.2f} ms "
            f"({native_gpu['native_gpu_speedup']['prefill']:.2f}x CPU); "
            f"decode50={native_gpu['decode_50_s'] * 1e3:.2f} ms "
            f"({native_gpu['native_gpu_speedup']['decode']:.2f}x CPU) {native_gpu['source']}"
        )
        if targets:
            print(
                f"  required integrated prover speedup vs CPU: "
                f"prefill {targets['prefill']:.2f}x, decode {targets['decode']:.2f}x"
            )
        print()
    hybrid = report.get("integrated_hybrid", {}).get("run_of_record")
    hybrid_rho = report.get("integrated_hybrid", {}).get("same_host_result")
    if hybrid:
        print("Integrated CUDA-hybrid prover")
        print(
            f"  proof prefill={hybrid['prove_prefill_s']:.3f}s; "
            f"decode marginal={hybrid['prove_decode_marginal_s']:.3f}s; "
            f"flat={hybrid['flat_cost_last_over_first']:.3f}; "
            f"packed={mb(hybrid['packed_response_bytes']):.2f} MB {hybrid['source']}"
        )
        if hybrid_rho:
            measured = hybrid_rho["proof_rho"]
            gap = hybrid_rho["required_speedup_from_hybrid_to_target"]
            print(
                f"  same-host proof rho: prefill {measured['prefill']:.2f}, "
                f"decode {measured['decode']:.2f}; resident gap to target "
                f"{gap['prefill']:.2f}x/{gap['decode']:.2f}x"
            )
        print()
    resident = report.get("integrated_resident", {}).get("run_of_record")
    resident_rho = report.get("integrated_resident", {}).get("same_host_result")
    if resident:
        cached_resident = resident.get("accelerator_cached_resident_device_bytes_after_cleanup")
        cached_resident_text = "n/a (schema<4)" if cached_resident is None else f"{cached_resident} B"
        trimmed_cached = resident.get("accelerator_cached_resident_device_bytes_after_cache_trim")
        trimmed_cached_text = "n/a (schema<4)" if trimmed_cached is None else f"{trimmed_cached} B"
        print("Integrated CUDA-resident prover")
        print(
            f"  proof core prefill={resident['prove_prefill_s']:.3f}s; "
            f"decode marginal={resident['prove_decode_marginal_s']:.3f}s; "
            f"online response={resident['prover_online_accounted_response_s']:.3f}s; "
            f"session wall={resident['response_session_wall_s']:.3f}s"
        )
        print(
            f"  flat={resident['flat_cost_last_over_first']:.3f}; "
            f"packed={mb(resident['packed_response_bytes']):.2f} MB; "
            f"workspace after cleanup="
            f"{resident['accelerator_workspace_device_bytes_after_cleanup']} B; "
            f"cached resident after cleanup={cached_resident_text}; "
            f"explicit resident after cleanup="
            f"{resident['accelerator_resident_device_bytes_after_cleanup']} B; "
            f"cached resident after trim={trimmed_cached_text} "
            f"{resident['source']}"
        )
        accelerator_session = resident.get("accelerator_session") or {}
        if "resident_alloc_requests" in accelerator_session:
            print(
                f"  allocator: physical malloc={accelerator_session['allocation_calls']}; "
                f"logical alloc={accelerator_session['resident_alloc_requests']}; "
                f"reuse hits={accelerator_session['resident_reuse_hits']}; "
                f"logical free={accelerator_session['resident_free_requests']}; "
                f"physical free={accelerator_session['physical_free_calls']}"
            )
        if resident_rho:
            measured = resident_rho["proof_rho"]
            print(
                f"  same-host proof rho: prefill {measured['prefill']:.3f} "
                f"({'PASS' if resident_rho['target_met']['prefill'] else 'FAIL'}); "
                f"decode {measured['decode']:.3f} "
                f"({'PASS' if resident_rho['target_met']['decode'] else 'FAIL'})"
            )
            pcs = resident_rho["pcs"]
            print(
                f"  PCS commit offline={pcs['commit_offline_s']:.3f}s; "
                f"open online={pcs['open_online_s']:.3f}s; verify={pcs['verify_s']:.3f}s; "
                f"PCG={resident_rho['pcg']['backend']} (production_grade=false)"
            )
        print()
    shape_sweep = report.get("shape_memory_sweep", {}).get("run_of_record")
    if shape_sweep:
        print("Synthetic shape/memory sweep (not non-GPT e2e)")
        for profile in shape_sweep["profiles"]:
            print(
                f"  {profile['name']:<30} total_i16="
                f"{profile['committed_weight_bytes_i16'] / 1e9:6.2f} GB "
                f"active_i16={profile['active_weight_bytes_i16'] / 1e9:6.2f} GB "
                f"GQA_KV={profile['gqa_kv_fraction_vs_mha']:.3f} "
                f"status={profile['status']}"
            )
        print(f"  {shape_sweep['source']}")
        print()
    decode_profiles = report.get("decode_marginal_profiles") or []
    if decode_profiles:
        print("Decode marginal profiles")
        for row in decode_profiles:
            print(
                f"  {row['milestone']:<8} {row['comm_decode_marginal_bytes']} B "
                f"({row['comm_decode_bytes_per_token']} B/token) {row['source']}"
            )
            for item in row["top_labels"][:5]:
                print(f"    {item['label']:<32} {item['bytes']}")
        print()
    print("PCS scenarios (packed response MB)")
    for row in report["pcs_scenarios"]:
        print(
            f"  {row['name']:<36} pcs={mb(row['pcs_opening_bytes']):7.2f} "
            f"total={mb(row['packed_response_download_bytes']):7.2f}  {row['status']}"
        )
    print()
    req = model["required_relative_prover_vs_native_speedup"]
    print("GPU rho sensitivity")
    print(f"  required relative prover/native speedup: prefill {req['prefill']:.2f}x, decode {req['decode']:.2f}x")
    for row in model["sensitivity"]:
        print(
            f"  rel={row['relative_prover_vs_native_speedup']:>4.1f}x "
            f"rho_prefill={row['rho_prefill']:>5.2f} "
            f"rho_decode={row['rho_decode']:>5.2f}"
        )
    print()
    print(f"recommendation: {report['go_no_go']['local_recommendation']}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    ap.add_argument("--write-json", action="store_true", help="write benchmarks/results/p7-*.json")
    ap.add_argument(
        "--validate-p7b-official",
        type=Path,
        help="fail closed unless one raw JSON is a complete official P7b verdict",
    )
    ap.add_argument(
        "--validate-fase-d-pod-official",
        type=Path,
        help="fail closed unless one raw JSON is a complete fase-D G4 verdict",
    )
    ap.add_argument(
        "--validate-c3b-official",
        type=Path,
        help="fail closed unless one raw JSON is a complete CPU or pod C3b verdict",
    )
    ap.add_argument(
        "--validate-t1-official",
        type=Path,
        help="fail closed unless one raw JSON is a complete CPU or pod T1 verdict",
    )
    ap.add_argument(
        "--validate-x4-v4-cpu",
        type=Path,
        help="fail closed unless one JSON is the exact clean X4 v4 CPU synthetic record",
    )
    ap.add_argument(
        "--validate-x4-v4-migration",
        type=Path,
        help="fail closed unless one JSON is the exact clean X4 v4 GPT-2 migration reference",
    )
    ap.add_argument(
        "--validate-x4-v4-pod",
        type=Path,
        help="fail closed unless one JSON is the exact clean X4 v4 A100 production verdict",
    )
    ap.add_argument(
        "--validate-x4b-local",
        type=Path,
        help="fail closed unless one JSON is the clean X4b local CPU/persisted-opening preflight",
    )
    ap.add_argument(
        "--validate-x4b-pod",
        type=Path,
        help="fail closed unless one JSON is an internally consistent X4b A100 verdict",
    )
    args = ap.parse_args()

    selected_validators = sum(
        value is not None
        for value in (
            args.validate_p7b_official,
            args.validate_fase_d_pod_official,
            args.validate_c3b_official,
            args.validate_t1_official,
            args.validate_x4_v4_cpu,
            args.validate_x4_v4_migration,
            args.validate_x4_v4_pod,
            args.validate_x4b_local,
            args.validate_x4b_pod,
        )
    )
    if selected_validators > 1:
        raise SystemExit("official validators are mutually exclusive")
    if args.validate_p7b_official is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-p7b-official are mutually exclusive")
        if not validate_p7b_official_result(args.validate_p7b_official):
            raise SystemExit("invalid or ineligible official P7b result")
        print(f"valid official P7b result: {args.validate_p7b_official}")
        return
    if args.validate_fase_d_pod_official is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-fase-d-pod-official are mutually exclusive"
            )
        if not validate_fase_d_pod_official_result(args.validate_fase_d_pod_official):
            raise SystemExit("invalid or ineligible official fase-D pod result")
        print(f"valid official fase-D pod result: {args.validate_fase_d_pod_official}")
        return
    if args.validate_c3b_official is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-c3b-official are mutually exclusive")
        if not validate_c3b_official_result(args.validate_c3b_official):
            raise SystemExit("invalid or ineligible official C3b result")
        print(f"valid official C3b result: {args.validate_c3b_official}")
        return
    if args.validate_t1_official is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-t1-official are mutually exclusive")
        if not validate_t1_official_result(args.validate_t1_official):
            raise SystemExit("invalid or ineligible official T1 result")
        print(f"valid official T1 result: {args.validate_t1_official}")
        return
    if args.validate_x4_v4_cpu is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-x4-v4-cpu are mutually exclusive")
        if not validate_x4_v4_cpu_result(args.validate_x4_v4_cpu):
            raise SystemExit("invalid or ineligible X4 v4 CPU synthetic result")
        print(f"valid X4 v4 CPU synthetic result: {args.validate_x4_v4_cpu}")
        return
    if args.validate_x4_v4_migration is not None:
        if args.write_json:
            raise SystemExit(
                "--write-json and --validate-x4-v4-migration are mutually exclusive"
            )
        if not validate_x4_v4_migration_result(args.validate_x4_v4_migration):
            raise SystemExit("invalid or ineligible X4 v4 GPT-2 migration result")
        print(f"valid X4 v4 GPT-2 migration result: {args.validate_x4_v4_migration}")
        return
    if args.validate_x4_v4_pod is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-x4-v4-pod are mutually exclusive")
        if not validate_x4_v4_pod_result(args.validate_x4_v4_pod):
            raise SystemExit("invalid or ineligible X4 v4 A100 production result")
        print(f"valid X4 v4 A100 production result: {args.validate_x4_v4_pod}")
        return
    if args.validate_x4b_local is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-x4b-local are mutually exclusive")
        if not validate_x4b_local_result(args.validate_x4b_local):
            raise SystemExit("invalid or ineligible X4b local preflight result")
        print(f"valid X4b local preflight result: {args.validate_x4b_local}")
        return
    if args.validate_x4b_pod is not None:
        if args.write_json:
            raise SystemExit("--write-json and --validate-x4b-pod are mutually exclusive")
        if not validate_x4b_pod_result(args.validate_x4b_pod):
            raise SystemExit("invalid or inconsistent X4b A100 result")
        print(f"valid X4b A100 result: {args.validate_x4b_pod}")
        return

    report = p7_report(args.results_dir)
    if not report["pcs_formula_check"]["matches_p6_measured_bytes"]:
        raise SystemExit("PCS byte formula does not match the P6 measured opening bytes")
    print_summary(report)
    if args.write_json:
        path = write_report(report, args.results_dir)
        print(f"wrote {path.relative_to(REPO)}")


if __name__ == "__main__":
    main()
