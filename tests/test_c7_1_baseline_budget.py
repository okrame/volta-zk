"""Current comparison contract, kept separate from pending G2 test changes."""

import importlib.util
import json
import math
from fractions import Fraction
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


def test_b1_rejection_preserves_failed_preflight_and_unknown_complete_costs():
    result = plan.baseline_budget()
    assert result["B1_decision"] == "reject_existing_whir_reuse_and_stop"
    assert result["measurement_reuse_priority"] is None
    reuse = result["whir_reuse_assessment"]
    provenance = reuse["provenance"]
    assert provenance["upstream_source_files"] == 96
    assert provenance["modified_source_files"] == provenance["registered_deltas"] == 25
    assert provenance["unregistered_deltas"] == []
    assert provenance["audit_error"] is None and provenance["source_guard_error"] is None
    stopped = result["B1_provenance_at_stop"]
    assert stopped["upstream_source_files"] == 87 and stopped["unregistered_delta_count"] == 10
    assert stopped["audit_error"] == (
        "unregistered vendored source delta: sumcheck/src/strategy.rs")
    assert stopped["source_guard_error"] == (
        "claimless prover must use exactly two claimless sumcheck batches")
    screen = reuse["lifetime_union_screen"]
    assert screen["attempts"] == 1 << 20
    assert screen["bound_bits"] == 55 and screen["single_term_bits_needed_before_FS"] == 98
    assert not screen["is_C71_security_bound"]
    assert reuse["clear_reference_nominal_component_bits"] == 74
    assert reuse["authenticated_reference_nominal_component_bits"] == 75
    fs = reuse["existing_FS_entry"]
    experiment = result["local_experiment"]
    assert not fs["D14_CPU_admitted"] and fs["requires_cuda"]
    assert fs["input_Fp_bytes_by_domain"]["28"] == experiment["execution_limits"]["RSS_bytes"]
    assert fs["available_host_admission_floor_bytes"] > experiment["execution_limits"]["RSS_bytes"]
    assert experiment["input_Fp_bytes_lower_bound"] == 131_072
    assert experiment["complete_runner_command"] is None
    port = result["B2_CPU_Fp3_port"]
    assert port["status"] == "functional_port_complete"
    assert not port["credit"] and not port["security_admitted"]
    assert [case["n"] for case in port["measured_reduced_cases"]] == [48, 128]
    for case in port["measured_reduced_cases"]:
        assert not case["credit"]
        assert case["total_protocol_wire_bytes"] > sum(case["certificate_bytes"])
        assert case["process"]["sampled_peak_process_threads"] <= 2
        assert case["process"]["sampled_peak_RSS_bytes"] <= 2 << 30
        assert case["process"]["wall_seconds"] <= 60
    assert port["complete_work_admission_bound"] == "infinity"
    assert "complete_native_Fp_and_Fp3_work_census" in port["remaining_measurement_contract_at_B2"]
    assert "--n 128 --run" in port["runner_command"]
    for cost in reuse["complete_costs"].values():
        assert cost["total"] is None and cost["admission_bound"] == "infinity"
        assert cost["missing"] == ["unimplemented_complete_matrix_path"]


def test_b3_census_closes_native_counts_but_not_physical_or_security_admission():
    result = plan.baseline_budget()
    census = result["B3_resource_census"]
    assert not census["credit"] and not census["security_admitted"]
    assert not census["complete_measurement_contract"]
    assert census["remaining_measurement_contract"] == ["expanded_array_physical_traffic"]
    assert census["complete_work_admission_bound"] == "infinity"
    assert [case["n"] for case in census["measured_reduced_cases"]] == [48, 128]
    for case in census["measured_reduced_cases"]:
        for key in ("base_products_inclusive", "fp3_products_including_squares"):
            assert case["total"][key] == sum(p[key] for p in case["phase_work"])
        assert len(case["phase_work"]) == len(case["phase_resources"]) == 22
        reduction = sum(p["base_products_inclusive"] for p in case["phase_work"]
                        if p["name"] == "prover_reduction")
        pcs = sum(p["base_products_inclusive"] for p in case["phase_work"]
                  if p["name"] == "prover_pcs")
        assert pcs > reduction
        assert not case["physical_traffic_probe"]["DRAM_traffic_measured"]
    assert "B4" in census["next_goal"]


def test_b4_rejects_nominal_security_using_actual_masked_geometry_and_rank_one_residual():
    result = plan.baseline_budget()
    b4 = result["B4_security_admission"]
    assert b4["status"] == "reject_unchanged_B2_security_reuse"
    assert not b4["credit"] and not b4["security_admitted"]
    assert b4["concrete_secure_profile"] is None
    small, large = b4["proximity"]["cases"]
    assert [small["n"], large["n"]] == [48, 128]
    assert [(o["message_rows"], o["randomness_rows"], o["domain_rows"], o["queries"])
            for o in small["oracles"]] == [
                (2048, 894, 4096, 298), (512, 298, 1024, 298),
                (128, 138, 512, 138), (32, 90, 256, 90)]
    last = large["oracles"][-1]
    assert (last["RS_dimension"], last["domain_rows"], last["queries"]) == (99, 512, 67)
    # 237 is a conservative integer Johnson agreement cap at rate 99/512.
    assert 400 * 236**2 < 441 * 99 * 512 <= 400 * 237**2
    probability = Fraction(math.comb(237, 67), math.comb(512, 67))
    assert Fraction(1, 1 << 83) < probability < Fraction(1, 1 << 82)
    assert 82 < last["distinct_query_term_bits"] < 83
    for case in (small, large):
        assert case["root_query_capacity"] == case["three_attempt_root_queries_upper"] == 894
        assert all(not o["query_term_at_most_2_to_minus_128"] for o in case["oracles"])
        assert all(m["query_term_at_most_2_to_minus_128"] for m in case["mask_groups"])
    lift = b4["lift"]
    assert lift["residual_rank_over_Fp"] == 1
    guess = lift["guess_probability_ideal_nonzero_uniform_Delta"]
    assert Fraction(guess["numerator"], guess["denominator"]) > Fraction(1, 1 << 64)
    fs = b4["FS_lifetime"]
    assert fs["global_adversary_queries"] == 1 << 64 and fs["attempts"] == 1 << 20
    assert fs["soundness_bits"] is fs["malicious_verifier_ZK_bits"] is None
    assert result["complete_baseline_selected"] is None and not result["security_admitted"]


def test_b5_exact_rejection_counts_attempts_and_prepaid_capacity_without_security_credit():
    b5 = plan.baseline_budget()["B5_alignment_admission"]
    assert b5["status"] == "reject_unchecked_nine_sVOLE_as_active_Fp3_converter"
    assert b5["repair_selected"] is None and not b5["security_admitted"] and not b5["credit"]
    error = b5["affine_residual"]["tight_single_check_error"]
    probability = Fraction(error["numerator"], error["denominator"])
    assert probability == Fraction(plan.P**2, plan.P**3 - 1)
    assert probability > Fraction(1, 1 << 64)
    attempts = b5["attempts"]
    assert Fraction(attempts["local_three_slot_success"]) == 3 * probability
    assert Fraction(attempts["hypothetical_2_to_20_attempt_success"]) == (1 << 20) * probability
    assert 43 < attempts["hypothetical_lifetime_bits"] < 44
    assert not attempts["single_attempt_meets_78_bits"]
    assert not attempts["is_complete_FS_lifetime_bound"] and not attempts["FS_multiplier_applied"]
    assert not b5["same_Delta_rechecks"]["independent_security_repetitions"]
    # Derive the remap distribution independently of the report formula.
    q0 = Fraction(plan.P - 1, plan.P**2)
    q1 = Fraction(plan.P + 1, plan.P**2)
    assert q0 + q1 + (plan.P - 2) * Fraction(1, plan.P) == 1
    guessed = b5["runtime_sampling_idealization"]["guess_one_given_nonzero_cubic_Delta"]
    assert Fraction(guessed["numerator"], guessed["denominator"]) == q1 / (1 - q0**3)
    for case, per_attempt in zip(b5["costs"]["rejected_path"], (20, 23)):
        assert case["per_attempt_reserved_fp3"] == per_attempt
        assert case["per_attempt_reserved_raw_svole"] == 9 * per_attempt
        assert case["per_attempt_alignment_payload_prepaid_at_capacity"] == 48 * per_attempt
        assert case["capacity_raw_svole"] == 27 * per_attempt
        assert case["capacity_alignment_wire_bytes"] == 76 + 144 * per_attempt
        assert case["connection_AES_pool_pairs"] == 3
        assert case["connection_AES_and_alignment_wire_bytes"] == (
            case["connection_AES_setup_wire_bytes"] + case["capacity_alignment_wire_bytes"])
        assert not case["aborted_slots_refunded"]
        assert not case["lifetime_capacity_and_root_renewal_implemented"]
    for name, cost in b5["costs"].items():
        if name.startswith("replacement_"):
            assert cost["total"] is None and cost["admission_bound"] == "infinity"
