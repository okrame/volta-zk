from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_budget_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "budget_moe.py"
    spec = importlib.util.spec_from_file_location("budget_moe", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_existing_logup_tree_formulas_pin_session_amortization() -> None:
    budget = load_budget_module()
    assert budget.lookup_fraction_tree_full_corrs(10, 1) == 173
    assert budget.lookup_fraction_tree_full_corrs(10, 2) == 175
    assert budget.table_fraction_tree_full_corrs(8) == 114
    assert budget.table_fraction_tree_full_corrs(16) == 354


def test_x2b_corrected_proxy_keeps_the_original_symmetric_band() -> None:
    budget = load_budget_module()
    config = budget.x123_synthetic()
    workload = budget.Workload(7, 0)
    k1 = budget.model_report(config, workload, 1)["correlations"]
    k2 = budget.model_report(config, workload, 2)["correlations"]

    assert k1["full_field_planning_proxy"] == 12_462
    assert k2["full_field_planning_proxy"] == 12_482
    assert k1["full_field_proxy_terms"] == {
        "tablebank_logup_masks": 11_336,
        "blind_sumcheck_round_masks": 644,
        "hadamard_round_and_terminal_masks": 243,
        "fresh_scalar_claim_masks": 131,
        "local_and_shared_product_masks": 64,
        "pcs_claim_and_component_zero_masks": 44,
        "t1_eq_reducer_and_q_bridge_masks": 0,
    }
    assert k2["full_field_proxy_terms"]["t1_eq_reducer_and_q_bridge_masks"] == 20
    assert k1["acceptance_ratio"] == {"min": 0.8, "max": 1.2}
    assert k2["acceptance_ratio"] == {"min": 0.8, "max": 1.2}


def test_corrected_proxy_postdicts_independent_closed_records_exactly() -> None:
    budget = load_budget_module()
    rows = budget.reference_full_correlation_postdictions()

    assert rows["x1_clean_6be165f"]["predicted"] == 4_714
    assert rows["gpt2_c1_clean_2a3d731"]["predicted"] == 176_880
    assert rows["gpt2_t1_closed_b14577e"]["predicted"] == 181_933
    assert all(row["exact"] for row in rows.values() if isinstance(row, dict) and "exact" in row)


def test_x0_full_field_projections_are_propagated_without_changing_other_counts() -> None:
    budget = load_budget_module()
    report = budget.build_report(
        [budget.gpt_oss_20b(), budget.llama_8b()],
        budget.Workload(100, 50),
        4,
    )
    moe = report["models"]["gpt-oss-20b"]
    dense = report["models"]["llama-class-8b-dense"]

    assert moe["correlations"]["full_field_planning_proxy"] == 2_858_312
    assert dense["correlations"]["full_field_planning_proxy"] == 462_339
    assert moe["lookups"]["logical_total"] == 417_267_938
    assert moe["lookups"]["padded_total"] == 687_568_448
    assert dense["lookups"]["logical_total"] == 408_291_250
    assert dense["lookups"]["padded_total"] == 586_362_944
