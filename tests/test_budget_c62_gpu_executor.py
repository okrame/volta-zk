from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


def load_budget_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "budget_c62_gpu_executor.py"
    spec = importlib.util.spec_from_file_location("budget_c62_gpu_executor", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_active_r19_geometry_excludes_stale_hidden_u_wrapper_cohorts() -> None:
    report = load_budget_module().build_report()
    guards = report["stale_path_guards"]
    wrapper = report["wrapper"]

    assert report["active_protocol"] == "C62FS1/C62JVR1-r19"
    assert guards == {
        "wrapper_profile": "production_c61_native_wrapper_specs",
        "cohort_count": 4,
        "hidden_u_wrapper_cohorts_present": False,
        "independent_primary_secondary_roots": True,
        "persisted_executor_allowed": False,
    }
    assert [cohort["name"] for cohort in wrapper["cohorts"]] == [
        "predecessor_cache",
        "successor_cache",
        "delta_residual",
        "auxiliary",
    ]
    assert wrapper["ntt_calls"] == 56
    assert wrapper["coefficient_bytes"] == 10_770_972_672
    assert wrapper["codeword_bytes"] == 86_167_781_376
    assert wrapper["logical_coefficient_plus_codeword_bytes"] == 96_938_754_048
    assert wrapper["retained_upper_frontier_bytes"] == 83_951_488


def test_eight_active_whir_lanes_and_provider_cache_are_exact() -> None:
    report = load_budget_module().build_report()
    whir = report["whir"]
    cache = report["provider_cache"]

    assert whir["d28_lanes"] == 4
    assert whir["d27_lanes"] == 4
    assert whir["initial_message_bytes"] == 12 * 2**30
    assert whir["initial_encoded_bytes"] == 24 * 2**30
    assert whir["initial_merkle_bytes"] == 96 * 2**30 - 256
    assert whir["generic_all_lane_retained_bytes"] == 132 * 2**30 - 256
    assert cache["bytes"] == 6 * 2**30
    assert cache["preloaded_before_certificate_timer"] is True
    assert "masks" in cache["forbidden"]
    assert "workload_cache_states" in cache["forbidden"]


def test_bounded_schedule_fits_but_cannot_claim_local_timing_credit() -> None:
    report = load_budget_module().build_report()
    resources = report["resource_schedule"]
    timing = report["timing_decision"]

    assert resources["analytic_pass"] is True
    assert resources["response_phase_live_device_cap_bytes"] == 32 * 2**30
    assert resources["response_phase_peak_device_bytes"] == 75_245_879_168
    assert resources["delta_commit_peak_device_bytes"] == 62_360_977_280
    assert resources["planned_peak_device_bytes"] == 75_245_879_168
    assert resources["headroom_bytes"] == 1_283_391_616
    assert resources["host_staged_cache_codeword_bytes"] == 32 * 2**30
    assert resources["requires_device_cache_trim_before_delta_commit"] is True
    assert timing == {
        "engineering_admission_seconds": 12.5,
        "terminal_seconds": 15.75,
        "projected_seconds": None,
        "folding_study_required": None,
        "reason": "production-geometry A100 phase calibration is required",
    }
    assert report["credit"] == {
        "provider_time": False,
        "hardware": False,
        "certificate": False,
    }


def test_stale_production_runner_fails_before_attempt_material() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "rust"
        / "volta-bench"
        / "src"
        / "bin"
        / "c62_whir_fiat_shamir_record.rs"
    ).read_text()
    preflight = source.split("fn preflight(args: &Args)", 1)[1]
    prove = source.split("fn prove(args: &Args)", 1)[1]

    preflight_stop = preflight.index("if !C62_GPU_PERFORMANCE_ELIGIBLE_EXECUTOR")
    preflight_clean_tree = preflight.index("git_sha_clean()?")
    stop = prove.index("if !C62_GPU_PERFORMANCE_ELIGIBLE_EXECUTOR")
    clean_tree = prove.index("git_sha_clean()?")
    reserve = prove.index(".reserve_attempt(")
    assert preflight_stop < preflight_clean_tree
    assert stop < clean_tree < reserve
    assert 'C62_GPU_EXECUTOR_PROFILE: &str = "C6SPR11-persisted-functional-only"' in source
    assert "const C62_GPU_PERFORMANCE_ELIGIBLE_EXECUTOR: bool = false" in source


def test_exact_a100_projection_automatically_triggers_folding_above_12_5s() -> None:
    module = load_budget_module()
    phases = {name: 1.0 for name in module.MEASURED_ATTEMPT_PHASES}
    phases["native_whir"] = 5.6
    projected = module.apply_a100_projection(
        module.build_report(),
        phases,
        byte_identical=True,
        a100_sxm4_80gb=True,
    )

    assert projected["timing_decision"]["projected_seconds"] == 12.6
    assert projected["timing_decision"]["folding_study_required"] is True
    assert projected["timing_decision"]["terminal_risk"] is False
    assert projected["folding_analysis"]["triggered"] is True
    assert abs(projected["folding_analysis"]["required_savings_seconds"] - 0.1) < 1e-12
    assert "independent primary and secondary roots" in projected["folding_analysis"][
        "immutable_constraints"
    ]


def test_projection_rejects_nonidentical_or_incomplete_evidence() -> None:
    module = load_budget_module()
    phases = {name: 1.0 for name in module.MEASURED_ATTEMPT_PHASES}

    try:
        module.apply_a100_projection(
            module.build_report(),
            phases,
            byte_identical=False,
            a100_sxm4_80gb=True,
        )
    except ValueError as error:
        assert "byte-identical A100" in str(error)
    else:
        raise AssertionError("nonidentical evidence must not drive the folding decision")

    phases.pop("seal")
    try:
        module.apply_a100_projection(
            module.build_report(),
            phases,
            byte_identical=True,
            a100_sxm4_80gb=True,
        )
    except ValueError as error:
        assert "exact measured-attempt phase census" in str(error)
    else:
        raise AssertionError("incomplete phase evidence must be rejected")
