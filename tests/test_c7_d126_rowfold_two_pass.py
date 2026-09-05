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
    assert report["carrier_intake"]["version"] is None
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
