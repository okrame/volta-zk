"""Current comparison contract, kept separate from pending G2 test changes."""

import importlib.util
import json
import math
from fractions import Fraction
from itertools import product
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
    assert result["required_security_bits_at_least"] == 78
    scope = result['active_goal_scope']
    assert scope == result['B12_lifetime_admission']['active_goal_scope']
    assert scope['model_roots'] == scope['key_epochs'] == scope['capacity_setups'] == 1
    assert scope['terminate_on_error_abort_or_capacity_exhaustion']
    assert scope['discarded_FS_candidates_and_preprocessing_still_count']
    assert scope['same_private_W_for_every_Gemma_operator']
    assert scope['malicious_verifier_ZK_including_view_until_termination']
    assert not scope['complete_prototype_admitted']
    assert {'root_or_capacity_renewal', 'recovery_after_abort', 'restart_or_reopen_composition'} <= set(scope['excluded_goals'])
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


def test_b6_comparison_prices_sacrifices_without_admitting_either_real_port():
    b6 = plan.baseline_budget()["B6_converter_comparison"]
    assert b6["status"] == "reject_both_immediate_ports_pending_base_sVOLE_contract"
    assert b6["port_selected"] is None and not b6["credit"] and not b6["security_admitted"]
    ideal = b6["checked_ideal_interface"]
    probability = Fraction(ideal["conditional_error"])
    assert probability == (Fraction(1, plan.P**2) + Fraction(6, plan.P**2 - 1)) / (
        1 - Fraction(1, (plan.P + 1)**3))
    assert Fraction(ideal["hypothetical_lifetime_converter_error"]) == (1 << 20) * probability
    assert 105 < ideal["hypothetical_lifetime_converter_bits"] < 106
    assert not ideal["complete_lifetime_bound"] and not ideal["FS_multiplier_applied"]
    for case, count in zip(b6["costs"]["capacity_cases"], (60, 69)):
        checked, native, both = case["checked_alignment"], case["native_fp3"], case["both"]
        assert case["capacity_fp3"] == count
        assert checked["capacity_raw_svole_including_sacrifice"] == 9 * count + 6
        assert checked["capacity_sacrificed_svole"] == 6
        # Data/mask differences, common openings, three tags per check,
        # nonce+ack, one context header and three framed messages.
        assert checked["proposed_capacity_wire_bytes_excluding_PCG"] == (
            2 * (3 * count + 2) * 8 + 2 * (8 + 3 * 16) + 64 + 76 + 3 * 9)
        assert checked["extra_wire_over_unchecked_lift"] == 235
        assert native["capacity_data_svole"] == 3 * count
        assert native["alignment_payload_bytes"] == 0
        for option, rbytes, kbytes in ((checked, 24, 16), (native, 32, 24)):
            rows = 9 * count + 6 if option is checked else 3 * count
            assert option["raw_prover_storage_bytes"] == rbytes * rows
            assert option["raw_verifier_storage_bytes"] == kbytes * rows
            assert option["complete_capacity_bytes"]["admission_bound"] == "infinity"
        assert both["retained_prover_storage_bytes"] == 48 * count
        assert both["retained_verifier_storage_bytes"] == 24 * count
        assert not both["aborted_slots_refunded"]
    checked_base, native_base = b6["costs"]["base_L_connection_subtotals"]
    assert [b["COPE_key_choice_OTs"] for b in (checked_base, native_base)] == [384, 192]
    assert [b["COPE_corrections_payload_bytes"] for b in (checked_base, native_base)] == [
        84_516_864, 42_261_504]
    for base in (checked_base, native_base):
        assert not base["credit"] and not base["secure_parameter_estimate"]
        assert base["complete_connection_bytes"]["admission_bound"] == "infinity"
    for key in ("complete_attempt_bytes", "complete_model_setup_and_root_renewal_bytes",
                "complete_work_and_physical_traffic"):
        assert b6["costs"][key]["admission_bound"] == "infinity"


def test_b6_masked_alignment_equations_cancellation_and_privacy_in_ideal_pools():
    # F7 plaintexts and two-coordinate tags: only base scaling is used here.
    # This models the specified converter, not the real OT/AES implementation.
    p = 7
    add = lambda a, b: tuple((x + y) % p for x, y in zip(a, b))
    scale = lambda a, s: tuple(x * s % p for x in a)
    # Two data rows followed by two distinct sacrificed mask rows in each lane.
    r = ((1, 3, 5, 6), (2, 4, 1, 0), (6, 2, 3, 4))
    delta = ((1, 2), (3, 1), (0, 4))
    tags = tuple(tuple(((i + j) % p, (2 * i + j) % p) for j in range(4))
                 for i in range(3))
    keys = tuple(tuple(add(tags[i][j], scale(delta[i], r[i][j])) for j in range(4))
                 for i in range(3))
    differences = tuple(tuple((r[0][j] - r[i][j]) % p for j in range(4))
                        for i in range(3))
    for chi in product(range(p), repeat=2):
        for mask in (2, 3):
            y = (r[0][mask] + sum(c * x for c, x in zip(chi, r[0]))) % p
            for lane in range(3):
                sent = tags[lane][mask]
                key = add(keys[lane][mask], scale(delta[lane], differences[lane][mask]))
                for j, coefficient in enumerate(chi):
                    sent = add(sent, scale(tags[lane][j], coefficient))
                    corrected = add(keys[lane][j], scale(delta[lane], differences[lane][j]))
                    key = add(key, scale(corrected, coefficient))
                assert key == add(sent, scale(delta[lane], y))
                # The ideal malicious-verifier simulator needs only its keys,
                # its own Delta, public differences and the masked opening y.
                assert sent == add(key, scale(delta[lane], -y))

    # Every nonzero two-row alignment error and arbitrary fixed mask errors:
    # each challenge has p solutions, so two independent checks give p^-2.
    vectors = tuple(product(range(p), repeat=2))
    for error in vectors[1:]:
        for mask_errors in vectors:
            counts = [sum((mask_error + sum(c * e for c, e in zip(chi, error))) % p == 0
                          for chi in vectors) for mask_error in mask_errors]
            assert Fraction(math.prod(counts), len(vectors)**2) == Fraction(1, p**2)

    # Independent masks hide both responses for every retained plaintext;
    # reusing one mask would leave only p possible pairs and leak a difference.
    for x in vectors:
        offsets = (x[0], x[1])  # verifier may choose coordinate-selecting challenges
        image = {tuple((m + a) % p for m, a in zip(masks, offsets)) for masks in vectors}
        assert image == set(vectors)
        reused = {((m + offsets[0]) % p, (m + offsets[1]) % p) for m in range(p)}
        assert len(reused) == p


def test_b6_native_combination_and_bootstrap_challenge_gap():
    add = lambda a, b: tuple((x + y) % plan.P for x, y in zip(a, b))
    basis = ((1, 0, 0), (0, 1, 0), (0, 0, 1))
    plaintexts = (3, 5, 7)
    tags = ((11, 13, 17), (19, 23, 29), (31, 37, 41))
    for delta in (*basis, (43, 47, 53)):
        combined_tag = combined_key = (0, 0, 0)
        for r, tag, u in zip(plaintexts, tags, basis):
            key = add(tag, plan.fp3_mul_six(delta, (r, 0, 0)))
            combined_tag = add(combined_tag, plan.fp3_mul_six(u, tag))
            combined_key = add(combined_key, plan.fp3_mul_six(u, key))
        assert combined_key == add(combined_tag, plan.fp3_mul_six(delta, plaintexts))
    source = (Path(__file__).resolve().parents[1] / "rust/volta-pcg/src/phase_b.rs").read_text()
    base_check = source.split("fn run_cope_base_svole(", 1)[1].split("\nfn get_bit(", 1)[0]
    assert "wanted.checked_add(1)" in base_check
    assert 'field_xof(prover_challenge_seed, b"chi", wanted)' in base_check
    assert "put_fp(&mut response, response_r)" in base_check
    # A nonzero residual vector in any extension still vanishes for one Fp
    # coefficient with probability 1/p, regardless of the number of tag limbs.
    assert sum(all(c * e % 7 == 0 for e in (1, 2, 3)) for c in range(7)) == 1


def test_b7_failed_real_premise_stops_baseline_even_when_hybrid_arithmetic_passes():
    report = plan.baseline_budget()
    b7 = report["B7_bootstrap_admission"]
    assert b7["status"] == "failed_OT_premise_baseline_stopped"
    assert b7["baseline_stopped"] and not b7["security_admitted"] and not b7["credit"]
    assert not b7["native_bootstrap_implemented"] and not b7["integration_selected"]
    assert b7["next_goal"] is None  # the failed construction is not reopened by B12
    assert report["next_authorized_goal"].startswith("B12:")
    assert report["active_baseline_status"] == "stopped_after_failed_B7"
    assert report["B2_CPU_Fp3_port"]["status"] == "functional_port_complete"
    assert report["B5_alignment_admission"]["repair_selected"] is None
    # Irreducibility of w^3-u over Fp3: u is not a cube; this is an algebraic
    # screen only, not an implementation of the nine-limb bootstrap.
    def power(a, exponent):
        result = (1, 0, 0)
        while exponent:
            if exponent & 1:
                result = plan.fp3_mul_six(result, a)
            a = plan.fp3_mul_six(a, a)
            exponent //= 2
        return result
    assert power((0, 1, 0), (plan.P**3 - 1) // 3) == (4294967295, 0, 0)
    assert plan.P**(3 * (3 - 1)) >= 1 << (2 * 128)
    candidate = b7["leakage_free_candidate_screen"]
    probability = Fraction(candidate["conditional_hybrid_error_upper"])
    assert probability == Fraction(192**2, plan.P**3) + Fraction(1, 1 << 128)
    lifetime = Fraction(candidate["conditional_2_to_20_setup_error_upper"])
    assert lifetime == (1 << 20) * probability < Fraction(1, 1 << 107)
    assert not candidate["is_runtime_or_complete_lifetime_bound"]
    failed = b7["failed_obligation"]
    assert not failed["point_KDF_binds_session_channel_or_A_B"]
    assert not failed["robustness_definition_2_satisfied"]
    assert failed["timely_decryption_or_direct_composition_proof"] is None
    native = b7["native_counterexample"]
    assert native["wire_bytes_all_tested_instances"] == (
        native["tested_choices"] * 2 * native["wire_bytes_per_channel"]) == 620
    assert not native["is_E2E_attack_or_attack_on_fixed_C71_role_topology"]
    assert not native["relay_uses_honest_seeds_scalars_or_choice"]
    small, large = b7["costs"]["unimplemented_candidate"]
    assert [case["COPE_corrections_payload_bytes"] for case in (small, large)] == [188_928, 126_812_160]
    for case in (small, large):
        assert case["complete_connection_bytes"]["admission_bound"] == "infinity"
    for key, value in b7["costs"].items():
        if key.startswith("complete_"):
            assert value["admission_bound"] == "infinity"
    source = (Path(__file__).resolve().parents[1] / "rust/volta-pcg/src/phase_b.rs").read_text()
    point_kdf = source.split("fn point_key(", 1)[1].split("\nfn xor32(", 1)[0]
    assert "binding" not in point_kdf and "transcript" not in point_kdf
    assert "point.compress()" in point_kdf and "branch as u8" in point_kdf
    assert "fn c71_b7_base_ot_related_seed_relay()" in source
