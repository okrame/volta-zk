"""Current comparison contract, kept separate from pending G2 test changes."""

import importlib.util
import json
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    "c71_budget", Path(__file__).resolve().parents[1] / "scripts/c7_1_gemma_plan.py")
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def test_unknown_is_unbounded_and_threshold_is_only_an_alarm():
    assert plan.budget_sum({"a": 35, "b": 0}, 35)["alarm"] == "within"
    assert plan.budget_sum({"a": 36, "b": None}, 35)["alarm"] == "exceeded"
    missing = plan.budget_sum({"a": 25, "b": None}, 35)
    assert missing["known_subtotal"] == 25 and missing["total"] is None
    assert missing["missing"] == ["b"] and missing["admission_bound"] == "infinity"
    assert missing["alarm"] == "unresolved"
    for value in (-1, True, "0", float("nan"), float("inf")):
        with pytest.raises(ValueError):
            plan.budget_sum({"bad": value})
    with pytest.raises(ValueError):
        plan.budget_sum({})
    with pytest.raises(ValueError):
        plan.budget_sum({"a": 1e308, "b": 1e308})


def test_one_reference_without_inherited_margins_or_security_credit():
    result = plan.baseline_budget()
    json.dumps(result, allow_nan=False)
    assert not result["credit"] and not result["security_admitted"]
    assert result["complete_baseline_selected"] is None
    assert result["required_lifetime_security_bits_at_least"] == 78
    cases = result["endpoint_cases_not_all_context_certificate_bound"]
    assert [c["old_tokens"] for c in cases] == [0, 3946]
    assert [c["certificate_bytes"]["known_subtotal"] for c in cases] == [25_431_680, 32_407_656]
    assert all(c["certificate_bytes"]["admission_bound"] == "infinity" for c in cases)
    for key in ("complete_weight_reads", "complete_fp_multiplications", "complete_fp3_multiplications",
                "warm_complete_prover_seconds", "complete_verifier_seconds_four_cores",
                "complete_gpu_peak_bytes", "persistent_model_setup_bytes"):
        assert result[key]["total"] is None and result[key]["admission_bound"] == "infinity"
    assert result["complete_weight_reads"]["known_subtotal"] == 3
    assert result["complete_gpu_peak_bytes"]["alarm_at"] < 80_000_000_000
    assert result["arena"]["known_peak_upper_bytes"] == 6_337_778_816
    assert result["arena"]["complete_peak_upper_bound"] == "infinity"
    dense = result["unchanged_dense_reference_screens"]
    assert dense["whir_input_or_ligero_encoded_matrix_lower_bound_bytes"] == 245_578_762_240
    assert not dense["below_reference_gpu_capacity"]
    traffic = result["traffic_comparisons_not_latency_predictions"]
    assert traffic["fifth_read_increment_bytes"] == result["packed_weight_bytes"] == 61_394_690_560
    assert traffic["20GB_host_spill_write_and_one_reread_bytes"] == 40_000_000_000
    assert not result["local_experiment"]["complete_C71_runner_ready"]
