from __future__ import annotations

import importlib.util
import itertools
import sys
from decimal import Decimal
from pathlib import Path


def load_wrapper_budget_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "budget_c6_wrapper.py"
    spec = importlib.util.spec_from_file_location("budget_c6_wrapper", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def concrete_frontier(depth: int, opened: tuple[int, ...]) -> int:
    current = set(opened)
    count = 0
    for _ in range(depth):
        for index in current:
            if index ^ 1 not in current:
                count += 1
        current = {index // 2 for index in current}
    return count


def test_frontier_dynamic_program_is_exact_on_small_trees() -> None:
    budget = load_wrapper_budget_module()
    # Exhaust every subset through 16 leaves.  Exhausting depth 5 as well
    # would enumerate all 2**32 subsets and turn this unit test into a
    # multi-hour combinatorial job.
    for depth in range(0, 5):
        leaves = range(2**depth)
        for opened_count in range(1, 2**depth + 1):
            brute = max(
                concrete_frontier(depth, opened)
                for opened in itertools.combinations(leaves, opened_count)
            )
            assert budget.max_merkle_frontier(depth, opened_count) == brute

    depth = 5
    leaves = range(2**depth)
    for opened_count in (1, 2, 3, 29, 30, 31, 32):
        brute = max(
            concrete_frontier(depth, opened)
            for opened in itertools.combinations(leaves, opened_count)
        )
        assert budget.max_merkle_frontier(depth, opened_count) == brute


def test_selected_profile_and_collision_safe_wire_maximum() -> None:
    budget = load_wrapper_budget_module()
    report = budget.build_report()
    capacity = report["capacity"]
    wire = report["wire"]
    chain = wire["one_chain"]

    assert capacity["active_polynomials"] == 64
    assert [cohort["encoded_domain_log2"] for cohort in capacity["cohorts"]] == [
        28,
        27,
        25,
        23,
        19,
    ]
    assert capacity["initial_encoded_symbols"] == 3_573_547_008
    assert capacity["coefficient_symbols"] == 224_395_264
    assert chain["opened_symbols"] == 14_528
    assert chain["outer_siblings"] == 49_052
    assert chain["inner_siblings"] == 0
    assert chain["packed_section_bytes"] == 1_802_646
    assert chain["fold_commitment_bytes"] == 2_266
    assert chain["chain_bytes"] == 1_804_912

    small_rounds = {
        row["domain_log2"]: row
        for row in chain["fold_domain_maxima"]
        if row["domain_log2"] <= 8
    }
    assert [small_rounds[domain]["distinct_half_indices"] for domain in range(3, 9)] == [
        2,
        4,
        8,
        16,
        32,
        64,
    ]


def test_two_repetition_wire_and_setup_stay_inside_frozen_caps() -> None:
    budget = load_wrapper_budget_module()
    report = budget.build_report()
    wire = report["wire"]
    setup = report["setup"]

    assert wire["two_chain_pcs_bytes"] == 3_609_824
    assert wire["non_pcs_allocation_bytes"] == 800_000
    assert wire["base_share_seed_bytes"] == 32
    assert wire["relation_seed_bytes"] == 32
    assert wire["total_residual_seed_bytes"] == 64
    assert wire["challenge_order_incremental_bytes"] == 32
    assert wire["residual_seeds_within_non_pcs_allocation"] is True
    assert wire["pi_final_maximum_bytes"] == 4_409_824
    assert wire["pi_final_headroom_bytes"] == 90_176
    assert wire["complete_response_maximum_bytes"] == 33_586_456
    assert wire["response_headroom_bytes"] == 1_413_544
    assert setup["paired_pcg_setup_bytes"] == 76_742_930
    assert setup["client_params_and_framing_budget_bytes"] == 73_257_070


def test_s86_is_selected_before_benchmark_and_all_events_exceed_128_bits() -> None:
    budget = load_wrapper_budget_module()
    report = budget.build_report()
    soundness = report["soundness"]
    ownership = report["residual_relation_ownership"]

    assert soundness["minimum_literal_128_bit_query_count"] == 85
    assert soundness["selected_query_count"] == 86
    assert soundness["all_events_meet_literal_128_bits"] is True
    assert Decimal(soundness["event_bits"]["wrapper_pcs"]) > Decimal("130.77")
    assert Decimal(soundness["event_bits"]["linear_functional_sumchecks"]) > Decimal(
        "243.35"
    )
    assert Decimal(soundness["event_bits"]["cache_argument"]) > Decimal("191.99")
    assert (
        soundness[
            "residual_sumcheck_degree_rounds_per_complete_proof_repetition"
        ]
        == 91
    )
    assert soundness["delta_root_bound_per_complete_proof_repetition"] == 256
    assert soundness["delta_event_numerator"] == 2**16
    assert Decimal(soundness["event_bits"]["delta_residual"]) > Decimal("239.99")
    assert Decimal(soundness["q121_complete_candidate_bits"]) > Decimal(
        "78.80929487391641"
    )
    assert ownership["proof_repetitions"] == 2
    assert ownership["mac_coordinates_per_complete_relation"] == 2
    assert ownership["terminal_form_kinds_per_coordinate"] == 2
    assert ownership["leaf_table_slots_per_proof_repetition"] == list(range(8))
    assert ownership["auxiliary_table_slots_per_proof_repetition"] == list(range(16))
    assert ownership["table_slots_per_proof_repetition"] == 24
    assert ownership["table_slot_references_across_proof_repetitions"] == 48
    assert ownership["post_root_terminal_challenge_streams"] == 8
    assert ownership["base_share_alpha_streams"] == 2
    assert ownership["atomic_weight_streams"] == 2
    assert ownership["complete_relation_streams"] == 10
    assert ownership["owner_coefficient_symbols_per_proof_repetition"] == 68_157_440
    assert ownership["split_v1_owner_coefficient_symbols"] == 68_157_440
    assert ownership["complete_v2_owner_coefficient_symbols"] == 136_314_880
    assert ownership["additional_owner_coefficient_symbols"] == 68_157_440
    assert ownership["proof_codec_bytes"] == 4_244
    assert ownership["wire_slot_addition_bytes"] == 0


def test_atomic_relation_census_and_claims_before_weights_are_exact() -> None:
    budget = load_wrapper_budget_module()
    relation = budget.build_report()["residual_atomic_relation"]

    assert relation["manifest"] == "C6RLM1"
    assert relation["claims_fixed_before_relation_seed"] is True
    assert relation["source_count"] == 4_975_525
    assert relation["direct_source_count"] == 4_974_852
    assert relation["product_mask_count"] == 673
    assert relation["product_closure_count"] == 673
    assert relation["product_triple_count"] == 22_339
    assert relation["zero_root_count"] == 8_170
    assert relation["leaf_semantic_entries"] == 2**23
    assert relation["auxiliary_semantic_entries"] == 2**15
    assert relation["auxiliary_quadratic_factor_tuples"] == [
        [0, 2],
        [0, 3],
        [1, 2],
        [1, 3],
        [6, 8],
        [6, 9],
        [7, 8],
        [7, 9],
    ]
    assert relation["atomic_outputs_per_repetition"] == {
        "source_grammar": 14_926_575,
        "affine": 4,
        "reverse_outer": 4,
        "raw_copy": 300_748,
        "product": 4_038,
        "zero": 2,
        "leaf_raw_tails": 31_979_441,
        "auxiliary_tails": 223_540,
        "total": 47_434_352,
    }
    assert relation["atomic_outputs_total"] == 94_868_704
    assert relation["terminal_outputs_per_schedule"] == 75_187
    assert relation["terminal_schedules_per_repetition"] == 4
    assert relation["terminal_outputs_per_repetition"] == 300_748
    assert relation["terminal_outputs_total"] == 601_496
    assert relation["coefficient_writes_per_repetition"] == {
        "source_grammar": 29_851_131,
        "affine": 29_853_150,
        "reverse": 20_202_848,
        "raw_copy": 601_496,
        "product": 270_760,
        "zero": 16_340,
        "leaf_raw_tails": 31_979_441,
        "auxiliary_tails": 223_540,
        "total": 112_998_706,
    }
    assert relation["coefficient_writes_total"] == 225_997_412
    assert relation["compiler_equivalent_symbols"] == 547_465_024


def test_time_screen_rejects_x4c_and_keeps_hardware_verdict_open() -> None:
    budget = load_wrapper_budget_module()
    timing = budget.build_report()["time_screen"]

    assert timing["verdict_scope"] == "informative-kernel-roofline-not-end-to-end"
    assert timing["sumcheck_base_equivalent_passes"] == 32
    assert (
        timing["ownership_amendment_additional_coefficient_symbols"] == 68_157_440
    )
    assert timing["atomic_relation_compiler_equivalent_symbols"] == 547_465_024
    assert Decimal(timing["sumcheck_effective_equivalent_passes"]) > Decimal(
        "34.74"
    )
    assert Decimal(timing["sumcheck_effective_equivalent_passes"]) < Decimal(
        "34.75"
    )
    assert (
        timing["ownership_amendment_timing_credit"]
        == "none-before-fused-compiler-benchmark"
    )
    assert (
        timing["atomic_relation_compiler_timing_credit"]
        == "none-before-fused-compiler-benchmark"
    )
    assert Decimal(timing["total_kernel_floor_seconds"]) < Decimal("9")
    assert Decimal(timing["integration_budget_to_20_seconds"]) > Decimal("11")
    assert Decimal(timing["legacy_x4c_total_projection_seconds"]) > Decimal("80")
