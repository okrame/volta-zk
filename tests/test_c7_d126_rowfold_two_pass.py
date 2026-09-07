from __future__ import annotations

import copy
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "c7_d126_rowfold_two_pass.py"


def load_module():
    spec = importlib.util.spec_from_file_location("c7_d126_rowfold_two_pass", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_rowfold_intake_is_blocked_and_standard_whir_control_is_conditional() -> None:
    module = load_module()
    report = module.build_report()
    screen = report["conditional_standard_whir_screen"]
    rows = {row["name"]: row for row in screen["candidates"]}

    assert report["classification"] == "analytic-assertion-screen"
    assert report["protocol_or_algorithm_credit"] is False
    assert report["fs_order_prefix"] == ["C0", "rho0", "C1", "rho1", "C2"]
    assert report["commitment_required_after_second_challenge"] == "C2"
    assert module.PROFILE["standard_whir_initial_domain_cells_control"] == 2**36
    assert module.PROFILE["standard_whir_first_fold_arity_control"] == 16
    assert (
        module.PROFILE["standard_whir_initial_domain_cells_control"]
        // module.PROFILE["standard_whir_first_fold_arity_control"]
        == 2**32
    )
    assert rows["retain"]["retained_cells"] == 2**32
    assert rows["retain"]["retained_bytes"] == 34_359_738_368
    assert rows["retain"]["arena_excess_bytes"] == 27_917_287_424
    assert rows["retain"]["violations"] == ["arena_cap"]
    assert rows["recompute"]["minimum_source_sweeps"] == 3
    assert rows["recompute"]["full_transform_work"] == "N_log_N"
    assert rows["selective"]["source_work_alternatives"] == ["qN", "N_log_q"]
    assert rows["local_only"]["global_relative_distance_proved"] is False
    assert report["carrier_intake"]["verdict"] == "BLOCKED"
    assert report["carrier_intake"]["source_identified"] is True
    assert report["carrier_intake"]["version"] == "C7-ROWFOLD-v2 normalised 2026-09-04"
    assert report["carrier_intake"]["proposed_relation_is_admitted"] is False
    identified = report["identified_v2_review"]
    assert identified["verdict"] == "NO-GO_AS_WRITTEN"
    assert identified["source_sweeps_in_pseudocode"] == 2
    assert identified["dense_standard_whir_control_applies_to_v2"] is False
    assert identified["v_plus_ntt_bytes"] == 10_737_418_240
    assert identified["complete_h100_peak_bytes"] is None
    assert screen["carrier_derivation_present"] is False
    assert screen["controls_are_exhaustive"] is False
    assert screen["verdict"] == "NO-GO_IF_ASSUMPTIONS_HOLD"
    assert report["global_gates"]["COMPLEXITY_BOUND"] == "BLOCKED"
    assert report["global_gates"]["TWO_HBM_SWEEPS"] == "BLOCKED"


def test_profile_drift_and_unknown_dispositions_fail_closed() -> None:
    module = load_module()
    drifted = copy.deepcopy(module.PROFILE)
    drifted["arena_cap_bytes"] += 1

    for call in (
        lambda: module.build_report(drifted),
        lambda: module.evaluate_candidate("legacy"),
    ):
        try:
            call()
        except module.RowfoldDispositionError:
            continue
        raise AssertionError("invalid ROWFOLD input was accepted")


def test_early_queries_allow_a_different_valid_low_degree_polynomial() -> None:
    module = load_module()
    for queries in (1, 2, 16, 357):
        row = module.early_query_counterexample(queries)
        prime = row["base_field_modulus"]
        coefficients = row["forged_polynomial"]
        # Independent evaluation, not the producer's Horner implementation.
        def evaluate(point):
            return sum(value * pow(point, degree, prime)
                       for degree, value in enumerate(coefficients)) % prime

        assert len(coefficients) == queries + 1
        assert coefficients[-1] != 0
        assert all(evaluate(point) == 0 for point in row["sample_points"])
        assert evaluate(row["claim_point"]) == 1 != row["true_claim"]
        assert evaluate(0) != 0  # A later independent check can reject it.
        assert row["hash_collision_required"] is False
        assert row["attack_on_frozen_correct_order_claimed"] is False


def test_hobbit_commit_pass_is_not_hidden_in_two_open_passes() -> None:
    control = load_module().build_report()["hobbit_construction_4_control"]
    assert control["commit_source_passes"] + control["open_source_passes"] == 3
    assert control["current_two_pass_order_verdict"] == "NO-GO"
    assert control["setup_precommitted_variant"] == "BLOCKED_NOT_SELECTED"


def test_v2_shared_fold_does_not_determine_row_dependent_eq_claim() -> None:
    p = (1 << 64) - (1 << 32) + 1
    a, b = 3 * pow(4, -1, p) % p, 2 * pow(3, -1, p) % p
    forms = [[(1-a)*(1-b) % p, (1-a)*b % p],
             [a*(1-b) % p, a*b % p]]
    assert sum(map(sum, forms)) % p == 1  # admissible nonzero all-c sum
    weights, difference = [2, 3], [[3, 0], [-2, 0]]
    folded = [sum(weights[i] * difference[i][j] for i in range(2)) % p
              for j in range(2)]
    claim = sum(weights[i] * sum(forms[i][j] * difference[i][j]
                               for j in range(2)) for i in range(2)) % p
    assert folded == [0, 0]
    assert claim == p - 1  # no linear functional of folded can return -1


def test_v2_interactive_clear_chain_allows_two_pair_row_isolation() -> None:
    # Diagnostic of the old interactive privacy claim, NOT an offline-FS attack.
    p = (1 << 64) - (1 << 32) + 1
    rows = [[5, 9, 11, 13], [2, 4, 6, 8], [1, 3, 7, 10]]
    # Two live coefficients, two fixed root masks per row; two +/- cosets.
    w = pow(7, (p-1)//8, p)
    points = [7 * pow(w, i, p) % p for i in (0, 4, 1, 5)]

    def evaluate(row, point):
        return sum(value * pow(point, j, p) for j, value in enumerate(row)) % p

    def opening(weights, point):
        return sum(weight * evaluate(row, point)
                   for weight, row in zip(weights, rows)) % p

    isolated = [(opening([2, 1, 1], x) - opening([1, 1, 1], x)) % p
                for x in points]
    assert isolated == [evaluate(rows[0], x) for x in points]
    matrix = [[pow(x, j, p) for j in range(4)] + [value]
              for x, value in zip(points, isolated)]
    for column in range(4):
        pivot = next(i for i in range(column, 4) if matrix[i][column])
        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        inverse = pow(matrix[column][column], -1, p)
        matrix[column] = [value * inverse % p for value in matrix[column]]
        for i in range(4):
            if i != column:
                factor = matrix[i][column]
                matrix[i] = [(a - factor*b) % p for a, b in
                             zip(matrix[i], matrix[column])]
    assert [matrix[i][-1] for i in range(4)] == rows[0]
    # Applying the same isolation to the report's own q266/root8192 geometry:
    mask_dimension, distinct_per_pair = 8_208_384, 266 * 32
    pairs = mask_dimension // distinct_per_pair + 1
    assert pairs == 965 and 2*pairs == 1930 < 8192
    assert pairs * distinct_per_pair == 8_214_080 > mask_dimension
