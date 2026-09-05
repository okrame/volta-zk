#!/usr/bin/env python3
"""Fail-closed ROWFOLD intake and conditional standard-WHIR screen."""

from __future__ import annotations

import json


def _frozen_profile() -> dict:
    return {
        "carrier_report_present": False,
        "carrier_version": None,
        "carrier_sha256": None,
        "carrier_relation_present": False,
        "carrier_compiler_present": False,
        "fs_order_prefix": ["C0", "rho0", "C1", "rho1", "C2"],
        "commitment_required_after_second_challenge": "C2",
        "standard_whir_initial_domain_cells_control": 2**36,
        "standard_whir_first_fold_arity_control": 16,
        "field_cell_bytes": 8,
        "materialized_o1_cells_control": 2**32,
        "arena_cap_bytes": 6_442_450_944,
        "allowed_source_sweeps": 2,
        "forbidden_work": ["full_codeword", "qN", "N_log_q", "N_log_N"],
    }


PROFILE = _frozen_profile()


class RowfoldDispositionError(ValueError):
    pass


def _expect_exact(actual, expected, label: str) -> None:
    if type(actual) is not type(expected):
        raise RowfoldDispositionError(f"{label}: type differs")
    if isinstance(expected, dict):
        if set(actual) != set(expected):
            raise RowfoldDispositionError(f"{label}: fields differ")
        for key, value in expected.items():
            _expect_exact(actual[key], value, f"{label}.{key}")
    elif isinstance(expected, list):
        if len(actual) != len(expected):
            raise RowfoldDispositionError(f"{label}: length differs")
        for index, (got, want) in enumerate(zip(actual, expected, strict=True)):
            _expect_exact(got, want, f"{label}[{index}]")
    elif actual != expected:
        raise RowfoldDispositionError(f"{label}: value differs")


def validate_profile(profile: dict) -> None:
    _expect_exact(profile, _frozen_profile(), "profile")


def evaluate_candidate(name: str, profile: dict = PROFILE) -> dict:
    validate_profile(profile)
    retained_bytes = profile["materialized_o1_cells_control"] * profile["field_cell_bytes"]

    candidates = {
        "retain": {
            "verdict": "NO-GO",
            "conditional_on": "the carrier materializes O1 or an equivalent 2^32-cell distance-bearing state",
            "retained_cells": profile["materialized_o1_cells_control"],
            "retained_bytes": retained_bytes,
            "arena_excess_bytes": retained_bytes - profile["arena_cap_bytes"],
            "violations": ["arena_cap"],
        },
        "recompute": {
            "verdict": "NO-GO",
            "conditional_on": "the post-rho1 state can only be rebuilt from the packed source",
            "minimum_source_sweeps": 3,
            "full_transform_work": "N_log_N",
            "violations": ["two_source_sweeps", "N_log_N"],
        },
        "selective": {
            "verdict": "NO-GO",
            "conditional_on": "direct per-query evaluation or selector construction",
            "source_work_alternatives": ["qN", "N_log_q"],
            "violations": ["qN", "N_log_q"],
        },
        "local_only": {
            "verdict": "NO-GO",
            "conditional_on": "a local streaming code without a global adaptive distance theorem",
            "global_relative_distance_proved": False,
            "violations": ["global_distance_missing"],
        },
    }
    try:
        return {"name": name, **candidates[name]}
    except KeyError as error:
        raise RowfoldDispositionError(f"unknown disposition: {name}") from error


def early_query_counterexample(queries: int = 357) -> dict:
    """Reject early-query equality testing; NOT an attack on the frozen PCS.

    Honest polynomial is zero. Once sample points are known, a degree-q
    polynomial can agree at all q samples yet claim value one elsewhere.
    The bound below limits only this small executable fixture, not an attacker.
    """
    if type(queries) is not int or not 1 <= queries <= 512:
        raise RowfoldDispositionError("fixture needs 1..512 sample points")
    prime = (1 << 64) - (1 << 32) + 1
    coefficients = [1]
    for point in range(1, queries + 1):
        product = [0] * (len(coefficients) + 1)
        for degree, value in enumerate(coefficients):
            product[degree] = (product[degree] - point * value) % prime
            product[degree + 1] = (product[degree + 1] + value) % prime
        coefficients = product

    def evaluate(point: int) -> int:
        result = 0
        for coefficient in reversed(coefficients):
            result = (result * point + coefficient) % prime
        return result

    target = queries + 1
    scale = pow(evaluate(target), -1, prime)
    coefficients = [coefficient * scale % prime for coefficient in coefficients]
    sample_values = [evaluate(point) for point in range(1, queries + 1)]
    assert not any(sample_values) and evaluate(target) == 1
    return {
        "classification": "restricted-early-query-counterexample",
        "base_field_modulus": prime, "queries": queries,
        "honest_polynomial": [0], "forged_polynomial": coefficients,
        "forged_degree": queries, "minimum_message_dimension": queries + 1,
        "sample_points": list(range(1, queries + 1)),
        "sample_values": sample_values, "claim_point": target,
        "true_claim": 0, "forged_claim": evaluate(target),
        "conditional_on": [
            "sample points are known before the folded-word commitment",
            "degree allowance includes q and the claim point is not sampled",
            "source-to-fold equality is checked only at these sample points",
        ],
        "hash_collision_required": False,
        "attack_on_frozen_correct_order_claimed": False,
        "verdict": "NO-GO_IF_ASSUMPTIONS_HOLD",
    }


def build_report(profile: dict = PROFILE) -> dict:
    validate_profile(profile)
    candidates = [
        evaluate_candidate(name, profile)
        for name in ("retain", "recompute", "selective", "local_only")
    ]
    if any(row["verdict"] != "NO-GO" for row in candidates):
        raise RowfoldDispositionError("a conditional control was admitted")

    return {
        "schema": "volta-c7-d126-rowfold-two-pass-intake-v1",
        "classification": "analytic-assertion-screen",
        "protocol_or_algorithm_credit": False,
        "fs_order_prefix": profile["fs_order_prefix"],
        "commitment_required_after_second_challenge": profile[
            "commitment_required_after_second_challenge"
        ],
        "required_complexity": "C(N,q,h)=c_source*N+P(q,h)",
        "c_source_independent_of": ["N", "q"],
        "carrier_intake": {
            "carrier": "owner-named ROWFOLD",
            "version": profile["carrier_version"],
            "sha256": profile["carrier_sha256"],
            "report_present": profile["carrier_report_present"],
            "relation_present": profile["carrier_relation_present"],
            "compiler_present": profile["carrier_compiler_present"],
            "verdict": "BLOCKED",
        },
        "conditional_standard_whir_screen": {
            "carrier_derivation_present": False,
            "controls_are_exhaustive": False,
            "verdict": "NO-GO_IF_ASSUMPTIONS_HOLD",
            "candidates": candidates,
        },
        "early_query_local_equality_control": early_query_counterexample(),
        "hobbit_construction_4_control": {
            "source": "https://eprint.iacr.org/2025/1214",
            "pdf_sha256": "1fad6172a3299c31c4bc589e0bb3ce03751dbe6ec07dc2f1d97eb19ebfec4972",
            "commit_source_passes": 1,
            "open_source_passes": 2,
            "commit_plus_open_source_passes": 3,
            "current_two_pass_order_verdict": "NO-GO",
            "setup_precommitted_variant": "BLOCKED_NOT_SELECTED",
            "scope": "published schedule, not a Gemma implementation or a universal lower bound",
        },
        "global_gates": {
            "COMPLEXITY_BOUND": "BLOCKED",
            "TWO_HBM_SWEEPS": "BLOCKED",
            "resume_condition": "identified ROWFOLD report or a new/revised PCS with complete relation, proof, and implementation",
        },
    }


if __name__ == "__main__":
    print(json.dumps(build_report(), indent=2, sort_keys=True))
