from __future__ import annotations

import copy
import importlib.util
import sys
from fractions import Fraction
from pathlib import Path

import pytest


def load_budget_module():
    path = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "budget_c7_d126_gemma_static.py"
    )
    spec = importlib.util.spec_from_file_location("budget_c7_d126_gemma_static", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_only_exact_gemma_q357_stacked_profile_is_accepted() -> None:
    budget = load_budget_module()
    expected = budget.expected_profile()
    budget.validate_profile(expected)

    wrong_census = copy.deepcopy(expected)
    wrong_census.update(w_raw_terminals=471, all_terminals=479, reducer_instances=1)
    other_model = copy.deepcopy(expected)
    other_model.update(profile="not-gemma", model="not-gemma")
    ad_hoc = copy.deepcopy(expected)
    ad_hoc["all_terminals"] = 481

    for rejected in (wrong_census, other_model, ad_hoc):
        with pytest.raises(ValueError):
            budget.validate_profile(rejected)

    for key, wrong in (
        ("operational_context_cap", 4_095),
        ("source_metadata_sha256", "0" * 64),
        ("public_layer_scalars_sha256", "0" * 64),
        ("workload_sha256", "0" * 64),
        ("live_tokens", 149),
        ("kv_capacity_tokens", 150),
        ("first_q", 350),
        ("reducer_instances", 1),
        ("q_by_round", (357,) * 8),
    ):
        rejected = copy.deepcopy(expected)
        rejected[key] = wrong
        with pytest.raises(ValueError):
            budget.validate_profile(rejected)

    partial = copy.deepcopy(expected)
    partial.pop("product_triples")
    with pytest.raises(ValueError):
        budget.validate_profile(partial)


def test_gemma_census_and_q357_wire_slice_are_exact_but_not_complete() -> None:
    report = load_budget_module().build_report()
    profile = report["profile"]
    field = report["field"]
    census = report["census"]
    wire = report["wire"]
    artifacts = report["artifacts"]
    workload = report["workload"]

    assert profile["operational_context_cap"] == 4_096
    assert profile["inference_batch_size"] == 1
    assert profile["max_concurrent_responses_on_device"] == 1
    assert artifacts == {
        "source_metadata_sha256": (
            "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2"
        ),
        "public_layer_scalars_sha256": (
            "52c10c73dad7a8a81f937d4954d3b38b6cf38216393793e23571b3c6017d67af"
        ),
        "workload_sha256": (
            "70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b"
        ),
        "all_sha256_verified": True,
    }
    assert workload == {
        "prompt_tokens": 100,
        "decode_tokens": 50,
        "live_tokens": 150,
        "operational_context_cap": 4_096,
        "kv_capacity_tokens": 4_096,
        "live_tokens_distinct_from_capacity": True,
        "live_tokens_within_context_cap": True,
        "kv_allocation_uses_capacity_not_live_tokens": True,
    }
    assert profile["terminal_manifest_blake3"] == (
        Path(__file__).resolve().parents[1]
        / "manifests"
        / "c7-d126-gemma31b-terminals-v1.blake3"
    ).read_text(encoding="ascii").strip()
    assert profile["text_only"] is True
    assert profile["checkpoint_tensor_count"] == 1_188
    assert profile["private_learned_tensor_count"] == 772
    assert profile["public_layer_scalar_count"] == 60
    assert profile["forbidden_vision_bridge_tensor_count"] == 356
    assert profile["shard_00001_file_bytes"] + profile["shard_00002_file_bytes"] == (
        profile["safetensors_metadata_bytes"] + profile["safetensors_framing_bytes"]
    ) == 62_546_338_248
    assert profile["first_q"] == 357
    assert profile["q_by_round"] == (357, 163, 152, 149, 149, 149, 149, 149)
    assert field == {
        "base": "Goldilocks",
        "modulus": (1 << 64) - (1 << 32) + 1,
        "extension": "Fp[u]/(u^3-2)",
        "degree": 3,
        "value_bytes": 24,
        "correction_bytes": 8,
    }
    assert census["w_segments"] == 472
    assert census["text_only"] is True
    assert (
        census["private_learned_tensor_count"]
        + census["public_layer_scalar_count"]
        + census["forbidden_vision_bridge_tensor_count"]
        == census["checkpoint_tensor_count"]
        == 1_188
    )
    assert census["w_raw_terminals"] == 472
    assert census["identity_terminals"] == 8
    assert census["all_terminals"] == 480
    assert census["reducer_instances"] == 0
    assert census["product_triples"] == 480
    assert census["known_fp3_correlations"] == 481
    assert census["known_w_fp3_correlations"] == 473
    assert census["known_base_field_slots"] == 1_443
    assert census["known_challenges_before_base_gkr_and_b_kv"] == 32

    assert wire["q_open"] == 1_417
    assert wire["unstacked_fp_atoms"] == 45_456
    assert wire["opened_leaves"] == 2_834
    assert wire["visible_fp"] == 399_594
    assert wire["merkle_siblings"] == 52_361
    assert wire["verifier_internal_hashes"] == 55_187
    assert wire["verifier_hashes_including_opened_leaves"] == 58_021
    assert wire["fixed_outer_p_to_v_bytes"] == 11_796
    assert wire["fixed_outer_v_to_p_bytes"] == 120
    assert wire["fixed_outer_total_bytes"] == 11_916
    assert wire["offline_fs_w_floor_bytes"] == 4_976_700
    assert wire["w_record_target_105_percent_bytes"] == 5_496_695
    assert wire["w_record_target_105_margin_bytes"] == 519_995
    assert wire["w_record_cap_margin_bytes"] == 1_566_985
    assert wire["w_record_cap_150_percent_bytes"] == 7_852_422
    assert wire["w_record_cap_150_margin_bytes"] == 2_875_722
    assert wire["partial_certificate_bytes"] == 4_977_268
    assert wire["frozen_small_reference_bytes"] == 3_466_188
    assert wire["partial_growth_numerator"] == 4_977_268
    assert wire["partial_growth_denominator"] == 3_466_188
    assert abs(wire["partial_to_frozen_reference_growth"] - 1.435949) < 0.000001
    assert wire["frozen_small_certificate_cap_bytes"] == 30_000_000
    assert wire["frozen_small_reference_within_cap"] is True
    assert wire["gemma_full_certificate_cap_bytes"] == 100_000_000
    assert wire["maximum_full_certificate_growth"] == 3
    assert wire["partial_slice_within_gemma_cap"] is True
    assert wire["partial_slice_within_growth"] is True
    assert wire["four_plane_planning_proxy_bytes"] == 25_482_394
    assert wire["full_certificate_bytes"] is None
    assert wire["status"] == "BLOCKED"
    assert wire["credit"] is False


def test_q357_alternative_one_mask_geometry_is_exact_but_w_only() -> None:
    masks = load_budget_module().build_report()["masks"]

    assert masks["visible_fp_per_attempt"] == 399_594
    assert masks["response_attempt_reservations_per_root"] == 4_096
    assert masks["response_attempt_reservations_include_all_outcomes"] is True
    assert masks["lifecycle_load_reserve_attempt_equivalent_per_root"] == 512
    assert masks["root_epochs"] == 256
    assert masks["response_attempt_lifetime"] == 2**20
    assert masks["mask_cells"] == 1_841_329_152
    assert masks["rootmask_dimension"] == 2_741_852_160
    assert masks["unused_cells"] == 900_523_008
    assert masks["setup_bytes_unchanged"] == 92_587_558_592
    assert masks["setup_hard_ratio"] == "2.10x"
    assert masks["setup_within_hard_ratio"] is True
    assert masks["refreshes"] == 255
    assert masks["generator_bytes_per_root"] == 176_767_598_592
    assert masks["status"] == "BLOCKED"
    assert masks["credit"] is False


def test_h100_conditional_partial_map_fits_but_full_peak_stays_unknown() -> None:
    h100 = load_budget_module().build_report()["h100"]

    assert h100["cap_bytes"] == 80_000_000_000
    assert h100["inference_batch_size"] == 1
    assert h100["max_concurrent_responses_on_device"] == 1
    assert h100["live_tokens"] == 150
    assert h100["kv_capacity_tokens"] == 4_096
    assert h100["kv_allocation_uses_capacity_not_live_tokens"] is True
    assert h100["packed_w_bytes"] == 61_394_690_560
    assert h100["one_kv_arena_bytes"] == 3_690_987_520
    assert h100["one_kv_arena_bytes"] == 450_560 * 2 * 4_096
    assert h100["one_kv_arena_bytes"] != 450_560 * 2 * 150
    assert h100["rowfold_total_arena_cap_bytes"] == 6_442_450_944
    assert h100["rowfold_arena_admission"] == "conditional"
    assert h100["v_product_closure_vector_bytes"] == 480 * 24 == 11_520
    assert h100["v_is_one_physical_allocation"] is True
    assert h100["selected_w_plus_one_kv_bytes"] == 65_085_678_080
    assert h100["conditional_subtotal_if_selected_caps_hold_bytes"] == 71_784_140_544
    assert h100["conditional_subtotal_lt_cap"] is True
    assert h100["conditional_subtotal_headroom_bytes"] == 8_215_859_456
    assert h100["conditional_with_speculative_bytes"] == 73_784_140_544
    assert h100["conditional_with_speculative_lt_cap"] is True
    assert h100["conditional_with_speculative_headroom_bytes"] == 6_215_859_456
    assert h100["peak_allocated_bytes"] is None
    assert h100["missing_live_allocations"]
    assert h100["status"] == "BLOCKED"
    assert h100["credit"] is False


def test_q357_total_allocation_clears_78_but_missing_premises_block_credit() -> None:
    security = load_budget_module().build_report()["security"]

    assert security["q_fs_global"] == 2**64
    assert security["q_fs_multiplier"] == 2**64 + 1
    assert security["response_attempt_lifetime"] == 2**20
    assert security["stacked_product_fixed_prefix_roots"] == 482
    assert security["stacked_product_fixed_prefix_status"] == "PASS"
    assert security["stacked_product_q64_bridge_status"] == "BLOCKED"
    assert sum(security["response_slot_classes"].values()) == 64
    assert abs(security["query_bits"] - 81.641220062103) < 1e-12
    assert abs(security["one_plane_envelope_bits"] - 81.546189488918) < 1e-12
    assert (
        abs(security["stacked_product_q64_budget_bits"] - 119.087110662762)
        < 1e-12
    )
    assert security["base_transformer_gkr_error"] is None
    assert security["base_transformer_gkr_bound"] == (
        "(2^64+1)*sum_c(K_c+sum_i(d_c[i])+n_c+2)/p^3"
    )
    assert security["base_transformer_gkr_qfs_lifetime_factor_once"] is True
    assert security["base_transformer_gkr_single_2^-110_slot_root_ceiling"] == 262_143
    assert (
        security["base_transformer_gkr_operator_compute_2^-86_root_ceiling"]
        == 4_398_046_508_032
    )
    assert security["base_transformer_gkr_emitted_root_numerator"] is None
    assert (
        security["base_transformer_gkr_operator_compute_reserve_already_in_total"]
        is True
    )
    assert Fraction(
        security["base_transformer_gkr_operator_compute_reserved_error_exact"]
    ) == Fraction(1, 2**86)
    assert "already contains" in security[
        "base_transformer_gkr_direct_additional_margin_semantics"
    ]
    direct_ceiling = security[
        "base_transformer_gkr_direct_additional_root_ceiling"
    ]
    assert direct_ceiling == 722_784_653_514_375
    assert security["base_transformer_gkr_status"] == "BLOCKED"
    p3 = ((1 << 64) - (1 << 32) + 1) ** 3
    q64 = (1 << 64) + 1
    for cap_bits, ceiling in (
        (110, security["base_transformer_gkr_single_2^-110_slot_root_ceiling"]),
        (86, security["base_transformer_gkr_operator_compute_2^-86_root_ceiling"]),
    ):
        assert q64 * ceiling * (1 << cap_bits) <= p3
        assert q64 * (ceiling + 1) * (1 << cap_bits) > p3
    current_total = Fraction(security["conditional_total_error_exact"])
    target = Fraction(1, 2**78)
    direct_error = Fraction(q64 * direct_ceiling, p3)
    next_direct_error = Fraction(q64 * (direct_ceiling + 1), p3)
    assert (target - current_total) * p3 // q64 == direct_ceiling
    assert current_total + direct_error < target
    assert current_total + next_direct_error >= target
    assert Fraction(
        security["base_transformer_gkr_direct_additional_error_at_ceiling_exact"]
    ) == direct_error
    assert Fraction(
        security["base_transformer_gkr_direct_remaining_before_exact"]
    ) == target - current_total
    assert Fraction(
        security[
            "base_transformer_gkr_direct_remaining_after_ceiling_exact"
        ]
    ) == target - (current_total + direct_error)
    assert Fraction(
        security["conditional_total_plus_gkr_direct_ceiling_error_exact"]
    ) == current_total + direct_error
    assert security["conditional_total_plus_gkr_direct_ceiling_below_78"] is True
    assert Fraction(
        security["conditional_total_plus_gkr_direct_next_error_exact"]
    ) == current_total + next_direct_error
    assert security["conditional_total_plus_gkr_direct_next_below_78"] is False
    assert security["conditional_total_arithmetic_below_78"] is True
    assert security["realized_security_status"] == "BLOCKED"
    assert abs(security["conditional_total_bits"] - 79.481814299560) < 1e-12
    assert abs(security["dyadic_contract_total_bits"] - 78.955605880640) < 1e-12
    assert (
        0.48437
        < security["dyadic_contract_remaining_78_budget_fraction"]
        < 0.48438
    )
    assert 0.35803 < security["used_78_budget_fraction"] < 0.35804
    assert 0.64196 < security["remaining_78_budget_fraction"] < 0.64197
    assert [row["after"] for row in security["cumulative_margin"]] == [
        "W",
        "B",
        "KV-old",
        "KV-new",
        "stacked-product-Q64-budget",
        "operator_compute",
        "boundary_commitments",
        "predecessor_successor_state",
        "pcs_binding_privacy",
        "extension_mac",
        "sampling_range",
        "serialization_order",
        "hash",
        "production_pcg",
        "state_replay",
        "codec_transcript",
    ]
    assert security["required_unproved_premises"]
    assert security["status"] == "BLOCKED"
    assert security["credit"] is False


def test_two_sweeps_and_source_linear_complexity_remain_uncredited() -> None:
    report = load_budget_module().build_report()
    work = report["source_work"]
    security = report["security"]

    assert work["packed_source_bytes"] == 61_394_690_560
    assert work["required_hbm_sweeps"] == 2
    assert work["required_two_sweep_bytes"] == 122_789_381_120
    assert work["compiled_hbm_sweeps"] is None
    assert work["complexity_required"] == "C(N,q,h)=c_source*N+P(q,h)"
    assert work["compiled_c_source"] is None
    assert work["compiled_P"] is None
    assert work["c_source_independent_of_q_and_N"] is None
    assert work["forbidden_terms"] == ["qN", "N log q", "N log N"]
    assert work["rowfold_report_present"] is False
    assert work["output_pruned_implementation_present"] is False
    assert work["two_hbm_sweeps_status"] == "BLOCKED"
    assert work["complexity_bound_status"] == "BLOCKED"
    assert work["current_direct_qN_path"] == "NO-GO"
    assert work["credit"] is False

    assert security["stacked_product_fixed_prefix_roots"] == 482
    assert security["stacked_product_q64_bridge_status"] == "BLOCKED"
    assert security["base_transformer_gkr_error"] is None
    assert security["status"] == "BLOCKED"
    assert report["verdicts"] == {
        "SECURITY_78": "BLOCKED",
        "SECURITY_84": "NO-GO",
        "FS_Q64": "BLOCKED",
        "MASK_LIFETIME": "BLOCKED",
        "COMPLEXITY_BOUND": "BLOCKED",
        "TWO_HBM_SWEEPS": "BLOCKED",
        "EXACT_WIRE_CENSUS": "BLOCKED",
        "FULL_CERTIFICATE": "BLOCKED",
        "H100_STATIC_FIT": "BLOCKED",
        "D126": "BLOCKED",
    }
    assert report["overall"] == {
        "static_known_slice_consistent": True,
        "admission_pass": False,
        "status": "BLOCKED",
        "credit": False,
    }


def test_runtime_and_complete_proof_estimates_are_frozen_without_credit() -> None:
    planning = load_budget_module().build_report()["planning_estimates"]

    assert planning["warm_resident_model"] is True
    assert (planning["prover_seconds_low"], planning["prover_seconds_high"]) == (
        45.0,
        50.0,
    )
    assert planning["complete_proof_bytes"] == 30_000_000
    assert (
        planning["verifier_four_core_seconds_low"],
        planning["verifier_four_core_seconds_high"],
    ) == (6.4, 8.2)
    assert planning["storage_onboarding_seconds_once"] == 19.186
    assert planning["confidence"] == "low"
    assert planning["measurement_credit"] is False
    assert planning["required_measurements"]
    assert planning["status"] == "BLOCKED"
