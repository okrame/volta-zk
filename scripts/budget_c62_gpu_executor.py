#!/usr/bin/env python3
"""Exact C6.2 GPU-executor geometry and local resource-admission screen.

This is not a timing result.  It follows the active r19 call path and keeps
historical CUDA measurements out of the pass/fail result.
"""

from __future__ import annotations

import argparse
import copy
import json
import math
from dataclasses import dataclass
from typing import Any


GIB = 1 << 30
MIB = 1 << 20

A100_SXM4_80GB_BYTES = 85_119_205_376
DEVICE_RESERVE_BYTES = 8 * GIB
ENGINEERING_ADMISSION_SECONDS = 12.5
TERMINAL_SECONDS = 15.75

C62_WRAPPER_QUERY_COUNT = 86
C62_WRAPPER_CACHE_OMITTED_LEVELS = 8
C62_STATIC_CACHE_BYTES = 6 * GIB
C62_HOST_STAGED_CACHE_CODEWORD_BYTES = 32 * GIB
C62_RESPONSE_PHASE_LIVE_DEVICE_CAP_BYTES = 32 * GIB

MEASURED_ATTEMPT_PHASES = (
    "cache_precommit",
    "pcg_allocation",
    "response",
    "wrapper",
    "native_whir",
    "compiler_whir",
    "blind_suffix",
    "seal",
)


@dataclass(frozen=True)
class Cohort:
    name: str
    kind: str
    payload_log2: int
    slots: int

    @property
    def coefficient_log2(self) -> int:
        return self.payload_log2 + (1 if self.kind == "witness" else 0)

    @property
    def encoded_log2(self) -> int:
        return self.coefficient_log2 + 3

    @property
    def coefficient_bytes(self) -> int:
        return self.slots * (1 << self.coefficient_log2) * 16

    @property
    def codeword_bytes(self) -> int:
        return self.slots * (1 << self.encoded_log2) * 16

    @property
    def outer_leaf_bytes(self) -> int:
        return (1 << self.encoded_log2) * 32

    @property
    def retained_frontier_bytes(self) -> int:
        retained = 2 * ((1 << self.encoded_log2) >> (C62_WRAPPER_CACHE_OMITTED_LEVELS + 1)) - 1
        return retained * 32


# This is production_c61_native_wrapper_specs(), the exact C6.2 r19 path.
# The hidden-u cohorts in production_c6_wrapper_specs() are not present.
ACTIVE_COHORTS = (
    Cohort("predecessor_cache", "witness", 24, 8),
    Cohort("successor_cache", "witness", 24, 8),
    Cohort("delta_residual", "witness", 23, 8),
    Cohort("auxiliary", "auxiliary", 16, 32),
)


def whir_initial_census(num_variables: int) -> dict[str, int]:
    if num_variables not in (27, 28):
        raise ValueError("C6.2 production WHIR admits only D27/D28")
    message = (1 << num_variables) * 8
    encoded = 2 * message
    merkle = ((2 << num_variables) - 1) * 32
    return {
        "num_variables": num_variables,
        "message_bytes": message,
        "encoded_bytes": encoded,
        "merkle_bytes": merkle,
        "generic_retained_bytes": message + encoded + merkle,
    }


def build_report() -> dict[str, Any]:
    cohorts = [
        {
            "name": cohort.name,
            "kind": cohort.kind,
            "payload_log2": cohort.payload_log2,
            "slots": cohort.slots,
            "coefficient_log2": cohort.coefficient_log2,
            "encoded_log2": cohort.encoded_log2,
            "coefficient_bytes": cohort.coefficient_bytes,
            "codeword_bytes": cohort.codeword_bytes,
            "outer_leaf_bytes": cohort.outer_leaf_bytes,
            "retained_frontier_bytes": cohort.retained_frontier_bytes,
        }
        for cohort in ACTIVE_COHORTS
    ]
    coefficient_bytes = sum(cohort.coefficient_bytes for cohort in ACTIVE_COHORTS)
    codeword_bytes = sum(cohort.codeword_bytes for cohort in ACTIVE_COHORTS)
    frontier_bytes = sum(cohort.retained_frontier_bytes for cohort in ACTIVE_COHORTS)
    ntt_calls = sum(cohort.slots for cohort in ACTIVE_COHORTS)

    successor = ACTIVE_COHORTS[1]
    delta = ACTIVE_COHORTS[2]
    # Predecessor is staged in host RAM. Successor stays resident across the
    # response, which is the largest phase after applying its explicit cap.
    response_phase_peak_device_bytes = (
        C62_STATIC_CACHE_BYTES
        + successor.codeword_bytes
        + C62_RESPONSE_PHASE_LIVE_DEVICE_CAP_BYTES
        + frontier_bytes
    )
    # The response must release and trim its inactive arena before the delta
    # commitment. This phase is smaller even with a full outer-leaf buffer.
    delta_commit_peak_device_bytes = (
        C62_STATIC_CACHE_BYTES
        + successor.codeword_bytes
        + delta.codeword_bytes
        + delta.outer_leaf_bytes
        + frontier_bytes
    )
    planned_peak_device_bytes = max(
        response_phase_peak_device_bytes,
        delta_commit_peak_device_bytes,
    )
    usable_device_bytes = A100_SXM4_80GB_BYTES - DEVICE_RESERVE_BYTES

    d28 = whir_initial_census(28)
    d27 = whir_initial_census(27)
    whir_initial_message = 4 * d28["message_bytes"] + 4 * d27["message_bytes"]
    whir_initial_encoded = 4 * d28["encoded_bytes"] + 4 * d27["encoded_bytes"]
    whir_initial_merkle = 4 * d28["merkle_bytes"] + 4 * d27["merkle_bytes"]

    report: dict[str, Any] = {
        "schema": "volta-c62-gpu-executor-local-screen-v1",
        "active_protocol": "C62FS1/C62JVR1-r19",
        "credit": {
            "provider_time": False,
            "hardware": False,
            "certificate": False,
        },
        "stale_path_guards": {
            "wrapper_profile": "production_c61_native_wrapper_specs",
            "cohort_count": len(ACTIVE_COHORTS),
            "hidden_u_wrapper_cohorts_present": False,
            "independent_primary_secondary_roots": True,
            "persisted_executor_allowed": False,
        },
        "wrapper": {
            "query_count": C62_WRAPPER_QUERY_COUNT,
            "cohorts": cohorts,
            "ntt_calls": ntt_calls,
            "coefficient_bytes": coefficient_bytes,
            "codeword_bytes": codeword_bytes,
            "logical_coefficient_plus_codeword_bytes": coefficient_bytes + codeword_bytes,
            "retained_upper_frontier_bytes": frontier_bytes,
        },
        "whir": {
            "d28_lanes": 4,
            "d27_lanes": 4,
            "d28_one_lane": d28,
            "d27_one_lane": d27,
            "initial_message_bytes": whir_initial_message,
            "initial_encoded_bytes": whir_initial_encoded,
            "initial_merkle_bytes": whir_initial_merkle,
            "generic_all_lane_retained_bytes": (
                whir_initial_message + whir_initial_encoded + whir_initial_merkle
            ),
            "execution_policy": "sequential lanes with compact frontiers",
        },
        "provider_cache": {
            "contents": "fixed D28 model and D27 embedding base encodings only",
            "bytes": C62_STATIC_CACHE_BYTES,
            "preloaded_before_certificate_timer": True,
            "reported_separately": ["build_wall", "preload_wall", "storage", "rss", "vram"],
            "forbidden": ["pcg", "masks", "challenges", "roots", "workload_cache_states"],
        },
        "resource_schedule": {
            "a100_total_bytes": A100_SXM4_80GB_BYTES,
            "device_reserve_bytes": DEVICE_RESERVE_BYTES,
            "usable_device_bytes": usable_device_bytes,
            "response_phase_live_device_cap_bytes": (
                C62_RESPONSE_PHASE_LIVE_DEVICE_CAP_BYTES
            ),
            "host_staged_cache_codeword_bytes": C62_HOST_STAGED_CACHE_CODEWORD_BYTES,
            "response_phase_peak_device_bytes": response_phase_peak_device_bytes,
            "delta_commit_peak_device_bytes": delta_commit_peak_device_bytes,
            "planned_peak_device_bytes": planned_peak_device_bytes,
            "headroom_bytes": usable_device_bytes - planned_peak_device_bytes,
            "analytic_pass": planned_peak_device_bytes <= usable_device_bytes,
            "requires_device_cache_trim_before_delta_commit": True,
        },
        "timing_decision": {
            "engineering_admission_seconds": ENGINEERING_ADMISSION_SECONDS,
            "terminal_seconds": TERMINAL_SECONDS,
            "projected_seconds": None,
            "folding_study_required": None,
            "reason": "production-geometry A100 phase calibration is required",
        },
    }

    assert [row["name"] for row in cohorts] == [
        "predecessor_cache",
        "successor_cache",
        "delta_residual",
        "auxiliary",
    ]
    assert ntt_calls == 56
    assert coefficient_bytes == 10 * GIB + 32 * MIB
    assert codeword_bytes == 80 * GIB + 256 * MIB
    assert coefficient_bytes + codeword_bytes == 90 * GIB + 288 * MIB
    # Four binary frontiers each omit their root-adjacent absent slot, hence
    # four 32-byte subtractions from the round-number MiB expression.
    assert frontier_bytes == 80 * MIB + 64 * 1024 - 4 * 32
    assert whir_initial_message == 12 * GIB
    assert whir_initial_encoded == 24 * GIB
    assert whir_initial_merkle == 96 * GIB - 256
    assert report["resource_schedule"]["analytic_pass"]
    assert report["timing_decision"]["projected_seconds"] is None
    return report


def apply_a100_projection(
    report: dict[str, Any],
    phase_seconds: dict[str, float],
    *,
    byte_identical: bool,
    a100_sxm4_80gb: bool,
) -> dict[str, Any]:
    """Apply one exact phase projection and select the next design action."""

    if set(phase_seconds) != set(MEASURED_ATTEMPT_PHASES):
        raise ValueError("projection must contain the exact measured-attempt phase census")
    if any(
        not isinstance(value, (int, float))
        or not math.isfinite(float(value))
        or value < 0
        for value in phase_seconds.values()
    ):
        raise ValueError("projection phase times must be finite non-negative numbers")
    if not byte_identical or not a100_sxm4_80gb:
        raise ValueError("folding decisions require a byte-identical A100 projection")

    projected = sum(float(phase_seconds[name]) for name in MEASURED_ATTEMPT_PHASES)
    result = copy.deepcopy(report)
    timing = result["timing_decision"]
    timing.update(
        {
            "projected_seconds": projected,
            "folding_study_required": projected > ENGINEERING_ADMISSION_SECONDS,
            "terminal_risk": projected >= TERMINAL_SECONDS,
            "reason": (
                "root-preserving folding study required before a session"
                if projected > ENGINEERING_ADMISSION_SECONDS
                else "exact executor remains the selected path"
            ),
            "phase_seconds": {
                name: float(phase_seconds[name]) for name in MEASURED_ATTEMPT_PHASES
            },
        }
    )
    result["folding_analysis"] = {
        "triggered": projected > ENGINEERING_ADMISSION_SECONDS,
        "required_savings_seconds": max(0.0, projected - ENGINEERING_ADMISSION_SECONDS),
        "immutable_constraints": [
            "independent primary and secondary roots",
            "C62FS1/C62JVR1 typed transcript bindings",
            "soundness and communication gates",
            "byte differential before timing credit",
        ],
        "candidate_order": [
            "increase later-round fold only",
            "increase initial and later fold",
            "reject if strict codec or soundness gate fails",
        ],
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.add_argument(
        "--projection-json",
        type=argparse.FileType("r"),
        help=(
            "exact A100 projection with byte_identical, a100_sxm4_80gb and "
            "phase_seconds fields"
        ),
    )
    args = parser.parse_args()
    report = build_report()
    if args.projection_json is not None:
        projection = json.load(args.projection_json)
        report = apply_a100_projection(
            report,
            projection["phase_seconds"],
            byte_identical=projection["byte_identical"],
            a100_sxm4_80gb=projection["a100_sxm4_80gb"],
        )
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    wrapper = report["wrapper"]
    resources = report["resource_schedule"]
    print(f"C6.2 active wrapper cohorts: {len(wrapper['cohorts'])}")
    print(f"C6.2 wrapper NTT calls:      {wrapper['ntt_calls']}")
    print(f"C6.2 wrapper logical bytes:  {wrapper['logical_coefficient_plus_codeword_bytes']:,}")
    print(f"C6.2 planned device peak:    {resources['planned_peak_device_bytes']:,}")
    print(f"C6.2 device headroom:        {resources['headroom_bytes']:,}")
    print("C6.2 local resource screen:  PASS (no timing/hardware credit)")
    if report["timing_decision"]["projected_seconds"] is not None:
        print(
            "C6.2 folding study:         "
            + ("REQUIRED" if report["timing_decision"]["folding_study_required"] else "not required")
        )


if __name__ == "__main__":
    main()
