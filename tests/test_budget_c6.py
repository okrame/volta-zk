from __future__ import annotations

import importlib.util
import sys
from decimal import Decimal
from pathlib import Path


def load_budget_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "budget_c6.py"
    spec = importlib.util.spec_from_file_location("budget_c6", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_q_contingency_is_selected_before_implementation() -> None:
    budget = load_budget_module()
    report = budget.build_report()
    soundness = report["soundness"]

    assert report["ligero"]["minimum_q_with_wrapper_inventory"] == 121
    assert soundness["q120_complete_meets_floor"] is False
    assert soundness["q121_complete_meets_floor"] is True
    assert Decimal(soundness["q121_ligero_bits"]) > Decimal("79.47274413860918")
    assert Decimal(soundness["q121_complete_bits"]) > Decimal("79.47274413860916")


def test_hidden_fields_and_q121_reproduce_the_frozen_wire_budget() -> None:
    budget = load_budget_module()
    report = budget.build_report()
    ligero = report["ligero"]
    communication = report["communication"]

    assert [tree["u_vector_bytes"] for tree in ligero["trees"]] == [
        13_508_608,
        3_727_360,
    ]
    assert [tree["one_query_bytes"] for tree in ligero["trees"]] == [
        199_124,
        17_844,
    ]
    assert ligero["u_vector_bytes"] == 17_235_968
    assert ligero["q121_increment_bytes"] == 216_968
    assert communication == {
        "c4_anchor_response_bytes": 84_544_352,
        "c4_anchor_pcs_bytes": 43_273_888,
        "removed_direct_auth_correction_bytes": 38_348_720,
        "removed_u_vector_bytes": 17_235_968,
        "retained_q120_bytes": 28_959_664,
        "retained_c6_q121_bytes": 29_176_632,
        "response_cap_bytes": 35_000_000,
        "new_payload_budget_bytes": 5_823_368,
        "final_proof_cap_bytes": 4_500_000,
        "projected_response_at_final_proof_cap_bytes": 33_676_632,
        "response_headroom_at_final_proof_cap_bytes": 1_323_368,
    }


def test_terminal_one_capacity_covers_17_accepts_and_four_aborts() -> None:
    budget = load_budget_module()
    credit = budget.build_report()["setup_and_credit"]

    assert credit["reserved_baseline_slots"] == 21
    assert credit["reserved_raw_correlations"] == 109_949_532
    assert credit["reserved_raw_correlations_per_tape"] == 109_949_532
    assert credit["paired_reserved_raw_correlations"] == 219_899_064
    assert credit["terminal_one_stage3_raw_capacity"] == 110_918_718
    assert credit["remaining_raw_correlations"] == 969_186
    assert credit["remaining_raw_correlations_per_tape"] == 969_186
    assert credit["paired_remaining_raw_correlations"] == 1_938_372
    assert credit["residual_mac_tapes"] == 2
    assert credit["fase_d_setup_bytes"] == 38_371_465
    assert credit["paired_pcg_setup_bytes"] == 76_742_930
    assert credit["remaining_client_parameter_budget_bytes"] == 73_257_070
