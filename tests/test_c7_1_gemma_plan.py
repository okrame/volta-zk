"""Small C7.1 accounting/algebra checks; no weights, compiler or GPU."""

import importlib.util
import math
import random
from pathlib import Path

import pytest


spec = importlib.util.spec_from_file_location(
    "c7_1_gemma_plan", Path(__file__).resolve().parents[1] / "scripts/c7_1_gemma_plan.py")
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def test_existing_paired_fold_diagnostic():
    plan.self_check()


def test_capacity_root_and_failure_boundaries():
    for root in (256, 4096):
        before = plan.lifecycle_counts(root, root_slots=root)
        after = plan.lifecycle_counts(root, failed_attempts=1, root_slots=root)
        assert before["mask_root_refreshes_after_first_used"] == 0
        assert after["mask_root_refreshes_after_first_used"] == 1
        assert after["accepted_pairs"] == root  # aborted attempt isn't an answer
        assert after["model_setups"] == after["connection_setups"] == 1
        assert after["capacity_setups"] == before["capacity_setups"] + 1
        lifetime = plan.lifecycle_counts(1 << 20, capacity_slots=31, root_slots=root)
        assert lifetime["reserved_slots"] == 1 << 20
        assert lifetime["mask_roots_touched"] == (1 << 20) // root
    counts = plan.lifecycle_counts(1, capacity_slots=300, root_slots=256)
    assert counts["mask_roots_touched"] == 1
    assert counts["mask_roots_needed_for_reserved_capacity"] == 2
    for arguments in ((0,), (True,), (-1,), (1, -1), (1 << 20, 1), (1, 0, 0)):
        with pytest.raises(ValueError):
            plan.lifecycle_counts(*arguments)


def test_costs_are_charged_at_their_frequency_and_unknown_is_not_zero():
    counts = plan.lifecycle_counts(256, 1)
    # Synthetic unit costs only, not Gemma estimates or measurements.
    costs = {"model_setup": 100, "resident_load": 20, "connection_setup": 10,
             "capacity_setup": 3, "mask_root_prepare": 7, "response_attempt": 5}
    assert plan.total_cost(counts, costs) == 100 + 20 + 10 + 9*3 + 2*7 + 257*5
    assert plan.total_cost(counts, {**costs, "mask_root_prepare": None}) is None
    for invalid in (-1, math.nan, math.inf, True, "0"):
        with pytest.raises(ValueError):
            plan.total_cost(counts, {**costs, "mask_root_prepare": invalid})
    with pytest.raises(ValueError):
        plan.total_cost(counts, {})


def test_single_conversation_never_silently_truncates_or_resets():
    schedule = plan.conversation_lengths([(100, 50)] * 27)
    assert schedule[0]["old_kv_tokens"] == 0
    assert schedule[-1]["new_kv_tokens"] == 4050
    with pytest.raises(ValueError):
        plan.conversation_lengths([(100, 50)] * 28)
    assert plan.conversation_lengths([(4095, 1)])[-1]["new_kv_tokens"] == 4096
    with pytest.raises(ValueError):
        plan.conversation_lengths([(0, 50)])


def test_int16_decomposition_exhaustive_and_exact_dot_products():
    for x in range(-32768, 32768):
        low, high = plan.split_i16(x)
        assert 0 <= low <= 255 and -128 <= high <= 127
        assert x == low + 256*high
    edges = [-32768, -32767, -257, -256, -255, -129, -128, -1,
             0, 1, 127, 128, 255, 256, 32766, 32767]
    for a in edges:
        for b in edges:
            assert plan.limb_dot([a], [b]) == a*b
    for length in (1, 31, 32, 33, 511, 512, 513, 21504):
        a = [edges[i % len(edges)] for i in range(length)]
        b = [edges[(7*i+3) % len(edges)] for i in range(length)]
        assert plan.limb_dot(a, b) == sum(x*y for x, y in zip(a, b))
    for value in (-32769, 32768, 1.0, True):
        with pytest.raises(ValueError):
            plan.split_i16(value)
    with pytest.raises(ValueError):
        plan.limb_dot([1], [])


def test_symbolic_stream_work_matches_explicit_loop_counts():
    for n in (1, 2, 4, 8, 16, 32, 64):
        for block in (1, 2, 4, 8, 16, 32, 64):
            if block > n:
                continue
            counts = {"block_inner_products_fp3_mul": 0,
                      "cross_inner_products_fp3_mul": 0,
                      "paired_updates_fp3_mul": 0,
                      "second_pass_mle_fp3_mul": 0}
            for i in range(n // block):
                for _ in range(block):
                    counts["block_inner_products_fp3_mul"] += 1
                    if i:
                        counts["cross_inner_products_fp3_mul"] += 2
                        counts["paired_updates_fp3_mul"] += 2
                width = block
                while width > 1:
                    counts["second_pass_mle_fp3_mul"] += width
                    width //= 2
            expected = plan.streaming_work(n, block)
            assert all(counts[k] == expected[k] for k in counts)
            assert sum(counts.values()) == expected["subtotal_fp3_mul_before_sumchecks_forms_masks_pcs"]
    for arguments in ((0, 1), (3, 1), (4, 3), (2, 4), (True, 1)):
        with pytest.raises(ValueError):
            plan.streaming_work(*arguments)


def test_six_product_fp3_matches_independent_polynomial_multiplication():
    rng = random.Random(7104)
    values = [(0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1),
              (plan.P-1,)*3, (1, 2, 3)]
    values += [tuple(rng.randrange(plan.P) for _ in range(3)) for _ in range(24)]
    for a in values:
        for b in values:
            coefficients = [0] * 5
            for i in range(3):
                for j in range(3):
                    coefficients[i+j] += a[i]*b[j]
            coefficients[0] += 2*coefficients[3]
            coefficients[1] += 2*coefficients[4]
            expected = tuple(x % plan.P for x in coefficients[:3])
            assert plan.fp3_mul_six(a, b) == expected
    for value in ((1, 2), (1, 2, plan.P), (True, 0, 0)):
        with pytest.raises(ValueError):
            plan.fp3_mul_six(value, (0, 0, 0))


def test_gemma_report_keeps_requirements_separate_from_complete_results():
    report = plan.report()
    assert report["four_packed_proof_source_reads_bytes"] == 245_578_762_240
    assert report["authorized_max_proof_source_passes"] == 4
    assert report["required_security_bits_strictly_greater_than"] == 78
    bounds = report["int16_limb_diagnostic"]
    assert bounds["lo_lo_i32_abs_bound"] < 2**31
    assert bounds["lo_hi_i32_abs_bound"] < 2**31
    assert bounds["hi_hi_i32_abs_bound"] < 2**31
    assert bounds["recombined_i64_abs_bound"] < min(2**63, plan.P // 2)
    assert bounds["cuda_kernel_implemented"] is False
    assert report["model_setup_delta_independence_required"] is True
    for key in ("complete_certificate_bytes", "complete_h100_peak_bytes",
                "complete_security_bits", "warm_prover_seconds", "four_core_verifier_seconds"):
        assert report[key] is None
