"""Small C7.1 accounting/algebra checks; no weights, compiler or GPU."""

import importlib.util
import json
import math
import random
from collections import Counter
from fractions import Fraction
from itertools import combinations, product
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


def test_hobbit_carrier_screen_is_only_a_conditional_payload_and_work_count():
    screen = plan.hobbit_carrier_screen(1 << 35, 1 << 24, 357)
    assert screen["credit"] is False
    assert screen["split_mask_column_payload_fp_bytes"] == 11_698_176
    assert screen["split_mask_column_payload_fp3_bytes"] == 35_094_528 > 35_000_000
    assert screen["linear_screen_conditions_not_physical_fit"] is True
    assert screen["compact_b_log2_b_work_units_not_complete_work"] <= 1 << 35
    assert screen["queried_column_cells_per_half"] <= 1 << 35
    probability = screen["reused_mask_fixed_coordinate_exposure_probability"]
    assert Fraction(probability["numerator"], 2*probability["denominator"]) > Fraction(1, 2**78)
    assert not plan.hobbit_carrier_screen(1, 1, 1)["linear_screen_conditions_not_physical_fit"]
    assert not plan.hobbit_carrier_screen(64, 4, 1)["linear_screen_conditions_not_physical_fit"]
    assert not plan.hobbit_carrier_screen(64, 32, 1)["linear_screen_conditions_not_physical_fit"]
    assert not plan.hobbit_carrier_screen(64, 8, 9)["linear_screen_conditions_not_physical_fit"]
    for arguments in ((0, 1, 1), (3, 1, 1), (4, 3, 1), (2, 4, 1),
                      (True, 1, 1), (4, 2, 0), (4, 2, 5), (4, 2, True)):
        with pytest.raises(ValueError):
            plan.hobbit_carrier_screen(*arguments)


def test_split_mask_root_reuse_leaks_despite_disjoint_queries_within_each_proof():
    # Enumerate actual legal query pairs, not a simulation or chosen FS tape.
    for domain, q in ((4, 1), (4, 2), (6, 2)):
        subsets = list(map(frozenset, combinations(range(domain), q)))
        pairs = [(a, b) for a in subsets for b in subsets if a.isdisjoint(b)]
        exposed = sum(0 in a1 and 0 in b2
                      for a1, _ in pairs for _, b2 in pairs)
        assert Fraction(exposed, len(pairs)**2) == Fraction(q, domain)**2
    # One nonzero code-coordinate functional w over F7. Individually uniform;
    # joint views recover w for EVERY mask. Fresh masks remove this attack.
    for w in (0, 1):
        masked = [(w + rho) % 7 for rho in range(7)]
        assert sorted(masked) == list(range(7))
        assert {(a - rho) % 7 for a, rho in zip(masked, range(7))} == {w}
        renewed_views = {((w + rho1) % 7, rho2)
                         for rho1 in range(7) for rho2 in range(7)}
        assert renewed_views == {(a, b) for a in range(7) for b in range(7)}


def test_private_bit_codec_has_no_power_of_two_block_fitting_both_caps():
    n, live, q = 1 << 35, 30_697_345_280, 357
    screens = [plan.private_hobbit_bit_screen(n, live, 1 << bits, q)
               for bits in range(35 + 1) if q <= 4*(1 << bits)]
    assert all(s["credit"] is False for s in screens)
    assert not any(s["passes_only_necessary_certificate_and_arena_bounds"]
                   for s in screens)
    at_limit = plan.private_hobbit_bit_screen(n, live, 1 << 27, q)
    assert at_limit["two_dense_fp3_fold_buffers_bytes"] == 6_442_450_944
    assert at_limit["dense_leaf_bit_correction_bytes"] == 46_792_704
    assert at_limit["full_live_rows_only_bit_correction_bytes"] == 41_674_752
    first_small = next(s for s in screens
                       if s["full_live_rows_only_bit_correction_bytes"] <= 35_000_000)
    assert first_small["carrier_block_cells"] == 1 << 28
    assert first_small["two_dense_fp3_fold_buffers_bytes"] == 12_884_901_888
    assert first_small["retained_full_column_tree_bytes_if_used"] + 2*live == 130_114_167_264
    assert 130_114_167_264 > 128_928_850_176
    # It is a scoped exclusion, not an always-false placeholder.
    assert plan.private_hobbit_bit_screen(8, 7, 2, 1)[
        "passes_only_necessary_certificate_and_arena_bounds"]
    for args in ((0, 1, 1, 1), (3, 2, 1, 1), (4, 4, 3, 1),
                 (4, 4, 8, 1), (4, 0, 2, 1), (4, 5, 2, 1),
                 (4, True, 2, 1), (4, 4, 2, True), (4, 4, 2, 9)):
        with pytest.raises(ValueError):
            plan.private_hobbit_bit_screen(*args)


def test_private_verifier_mac_identity_simulator_and_altered_product():
    # Exhaustive F7 algebra, C7.1 sign convention m = k + Delta*x.
    # Not a test of hash/PCS soundness, FS, or the real correlation generator.
    p = 7
    for a in range(p):
        for b in range(p):
            for c in range(p):
                ma, mb, mc, kr = 2, 3, 4, 5
                a0, a1 = ma*mb % p, (a*mb + b*ma - mc) % p
                roots = 0
                for delta in range(p):
                    ka, kb, kc = ((m - delta*x) % p
                                  for m, x in ((ma, a), (mb, b), (mc, c)))
                    residual = (ka*kb + delta*kc - a0 + delta*a1) % p
                    assert residual == delta*delta*(a*b-c) % p
                    roots += residual == 0
                    if c != a*b % p:
                        continue
                    real = set()
                    for r in range(p):
                        mr = (kr + delta*r) % p
                        msg = ((a0 + mr) % p, (a1 + r) % p)
                        assert (ka*kb + delta*kc + kr - msg[0] + delta*msg[1]) % p == 0
                        real.add(msg)
                    simulated = {((ka*kb + delta*kc + kr + delta*s) % p, s)
                                 for s in range(p)}
                    assert real == simulated
                if c != a*b % p:
                    assert roots == 1  # Delta=0; not a lifetime soundness bound


def test_grouped_arithmetic_hash_screen_counts_states_paths_and_gkr():
    s = plan.private_hobbit_arithmetic_hash_screen(1 << 35, 1 << 24, 357)
    assert s["credit"] is False
    assert s["chain_groups_of_six"] == 342  # final group has two live row slots
    assert s["private_hash_calls_without_inner_pcs_or_anchor"] == 131_376
    assert s["padded_permutation_instances"] == 1 << 18  # not 2^17
    assert s["base_input_corrections"] == 1_293_772
    assert s["base_input_correction_bytes"] == 10_350_176
    assert s["power_gkr_extension_corrections"] == 6574
    assert s["hash_payload_bytes_before_framing_and_other_components"] == 10_508_024
    assert s["anchor_base_corrections_upper"] == 86_544
    assert s["anchor_correction_bytes_upper"] == 692_352
    assert s["hash_and_anchor_payload_bytes_before_framing_and_other_components"] == 11_200_376
    assert s["hash_trace_and_four_fold_tables_bytes"] == 1_442_840_576
    assert s["boundary_plaintexts_and_tags_bytes"] == 41_400_704
    assert s["setup_six_code_rows_and_chain_digests_bytes"] == 5_368_709_120
    assert s["retained_full_column_tree_bytes"] == 4_294_967_264
    assert s["setup_hash_permutations_before_anchor"] == 23_018_340_351
    assert s["queried_hash_sbox_multiplications_before_gkr"] == 78_825_600
    assert s["hash_sumcheck_fp3_mul_upper_before_public_forms_and_mac"] == 13_086_291_360
    assert s["clear_hash_reduction_error_numerator_not_fs_or_mac"] == 5784
    for n in (1, 2, 4, 8, 16, 32):
        for block in (1 << bits for bits in range(n.bit_length())):
            small = plan.private_hobbit_arithmetic_hash_screen(n, block, 1)
            groups = list(range(0, n // block, 6))
            depth = (4*block).bit_length() - 1
            assert small["private_hash_calls_without_inner_pcs_or_anchor"] == len(groups) + depth
            assert small["base_input_corrections"] == n//block + 4*len(groups) + 8*depth + 4
    for args in ((0, 1, 1), (3, 1, 1), (4, 3, 1), (2, 4, 1),
                 (True, 1, 1), (4, 2, 0), (4, 2, 9), (4, 2, True)):
        with pytest.raises(ValueError):
            plan.private_hobbit_arithmetic_hash_screen(*args)


def test_power_round_adjoint_sumcheck_and_single_input_endpoint():
    # Two independent four-lane permutations, not a Poseidon implementation.
    # The proof identity must work for ANY public linear layer and constants.
    rng = random.Random(7127)
    p, width, size = plan.P, 4, 8
    matrix = [[rng.randrange(p) for _ in range(width)] for _ in range(width)]
    constants = [rng.randrange(p) for _ in range(width)]
    x = [rng.randrange(p) for _ in range(size)]
    output_point, coins = [2, 3, 5], [7, 11, 13]
    weights = [plan.mle([int(i == j) for i in range(size)], output_point)
               for j in range(size)]
    for partial in (False, True):
        c = [constants[i % width] if not partial or i % width == 0 else 0
             for i in range(size)]
        selector = [int(not partial or i % width == 0) for i in range(size)]
        nonlinear = [(v + s*(pow(v, 7, p)-v)) % p
                     for v, s in zip(((v+k) % p for v, k in zip(x, c)), selector)]
        y = [sum(matrix[k][j]*nonlinear[base+j] for j in range(width)) % p
             for base in range(0, size, width) for k in range(width)]
        adjoint = [sum(weights[base+k]*matrix[k][j] for k in range(width)) % p
                   for base in range(0, size, width) for j in range(width)]

        def integrand(point):
            a, xx, cc, s = [plan.mle(table, point)
                            for table in (adjoint, x, c, selector)]
            z = (xx + cc) % p
            return a*(z + s*(pow(z, 7, p)-z)) % p

        def partial_sum(prefix):
            return sum(integrand(prefix + list(tail))
                       for tail in product((0, 1), repeat=3-len(prefix))) % p

        claim = plan.mle(y, output_point)
        assert claim == partial_sum([])
        assert (claim + 1) % p != partial_sum([])  # altered output claim
        degree = 9 if partial else 8
        for i in range(3):
            prefix = coins[:i]
            assert claim == (partial_sum(prefix + [0]) + partial_sum(prefix + [1])) % p
            samples = [partial_sum(prefix + [t]) for t in range(degree+2)]
            for _ in range(degree+1):
                samples = [(b-a) % p for a, b in zip(samples, samples[1:])]
            assert samples == [0]
            claim = partial_sum(prefix + [coins[i]])
        assert claim == integrand(coins)  # exactly ONE X(coins), no new PCS


def test_partial_power_round_really_needs_degree_nine():
    # A(t)=X(t)=S(t)=t, C(t)=0 gives t^9-t^3+t^2. An eight-degree
    # schema would be unsound as a claimed upper bound, not an optimization.
    p = plan.P
    samples = [(t**9 - t**3 + t**2) % p for t in range(11)]
    for _ in range(9):
        samples = [(b-a) % p for a, b in zip(samples, samples[1:])]
    assert samples == [math.factorial(9) % p]*2
    assert (samples[1]-samples[0]) % p == 0


def test_anchor_ripple_adder_gate_identity_and_canonical_word_boundary():
    for a, b, carry in product((0, 1), repeat=3):
        g = a*b
        t = a+b-2*g
        h = t*carry
        low, high = t+carry-2*h, g+h
        assert low in (0, 1) and high in (0, 1)
        assert low + 2*high == a+b+carry
    # One product at the low bit, two for each remaining bit. No claimed
    # BLAKE3 KAT: only its arithmetic gate-count construction is checked.
    assert 1 + 2*31 == 63
    for value in (0, 1, plan.P-1, plan.P, (1 << 64)-1):
        bits = [(value >> i) & 1 for i in range(64)]
        equal, less = 1, 0
        for i in reversed(range(64)):
            term = equal*(1-bits[i])  # one product per bit
            if (plan.P >> i) & 1:
                less += term
                equal -= term
            else:
                equal = term
        assert less == int(value < plan.P)
        assert equal == int(value == plan.P)


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


def test_bounded_rs_fft_generator_forms_and_transpose_use_same_order():
    p = plan.P
    for bits in range(1, 27):
        domain = 1 << bits
        root = pow(7, (p-1)//domain, p)
        assert pow(root, domain, p) == 1
        assert pow(root, domain//2, p) == p-1
    for width in (1, 2, 4, 8, 16, 32, 64):
        domain = 4*width
        root = pow(7, (p-1)//domain, p)
        values = [(13*j*j+7) % p for j in range(width)]
        actual = plan.small_goldilocks_fft(values + [0]*(domain-width))
        expected = [sum(x*pow(root, j*k, p) for j, x in enumerate(values)) % p
                    for k in range(domain)]
        assert actual == expected
        point = list(range(2, width.bit_length()+1))
        for k in (0, 1, domain-1):
            t = pow(root, k, p)
            assert plan.rs_generator_mle(t, point) == plan.mle(
                [pow(t, j, p) for j in range(width)], point)
        # Forward FFT, not inverse; repetitions in an auxiliary linear form
        # ADD coefficients even though actual query sets have distinct indices.
        indices, coefficients = [0, 1, 1, domain-1], [2, 3, 5, 7]
        sparse = [0]*domain
        for k, a in zip(indices, coefficients):
            sparse[k] += a
        form = plan.small_goldilocks_fft(sparse)[:width]
        assert plan.dot(values, form) == sum(a*actual[k] for k, a in zip(indices, coefficients)) % p
        assert plan.small_goldilocks_fft(actual) == [domain*values[0] % p] + [
            domain*(values[domain-j] if j > domain-width else 0) % p
            for j in range(1, domain)]
    for values in ([], [0]*3, [0]*512, [True], [-1], [p]):
        with pytest.raises(ValueError):
            plan.small_goldilocks_fft(values)


def test_recursive_rs_batched_forms_keep_both_outer_folds_then_one_inner_fold():
    p, width, rows = plan.P, 4, 4
    source = [[11+i*i+3*j for j in range(width)] for i in range(rows)]
    row_point, random_point, column_point = [2, 5], [7, 11], [13, 17]
    target = [plan.mle([int(i == j) for j in range(width)], column_point)
              for i in range(width)]
    first = [plan.mle([row[j] for row in source], row_point) for j in range(width)]
    second = [plan.mle([row[j] for row in source], random_point) for j in range(width)]
    root = pow(7, (p-1)//(4*width), p)
    indices, sigma = [1, 6, 11], 19
    g_code, observed = [0]*width, 0
    for k, index in enumerate(indices):
        form = [pow(root, index*j, p) for j in range(width)]
        column = [plan.dot(row, form) for row in source]
        a = pow(sigma, 2*k+1, p)
        g_code = plan.combine(g_code, form, a)
        observed += a*plan.mle(column, row_point) + a*sigma*plan.mle(column, random_point)
    public_form = plan.combine(target, g_code, 1) + [sigma*x % p for x in g_code]
    claim = (plan.dot(first, target)+observed) % p
    assert plan.dot(first+second, public_form) == claim
    assert plan.dot(second+first, public_form) != claim  # lane order matters
    for selector in (0, 1, 23):
        v = [29, 31]
        compact_form = ((1-selector)*plan.mle(target, v)
                        +(1-selector+sigma*selector)*plan.mle(g_code, v)) % p
        assert plan.mle(public_form, v+[selector]) == compact_form
    # The resident recursion folds BOTH X and g in its row coordinate.
    # This is a partial-sumcheck endpoint identity, not a full PCS test.
    folded_x = [(a+37*(b-a)) % p for a, b in zip(first, second)]
    folded_g = [(a+37*(b-a)) % p for a, b in zip(public_form[:width], public_form[width:])]
    assert plan.dot(folded_x, folded_g) == sum(
        plan.mle([first[j], second[j]], [37])*plan.mle(
            [public_form[j], public_form[width+j]], [37]) for j in range(width)) % p
    altered = list(folded_x)
    altered[0] = (altered[0]+1) % p
    assert plan.dot(altered, folded_g) != plan.dot(folded_x, folded_g)


def test_rs_proximity_is_not_exact_root_well_formedness():
    # Exact tiny RS code, not a hash/PCS execution. A one-symbol corruption
    # has the SAME unique nearest message, but is not its exact encoding.
    p, domain, width = 17, 8, 2
    root = pow(3, (p-1)//domain, p)
    code = [[sum(c*pow(root, i*j, p) for j, c in enumerate(coefficients)) % p
             for i in range(domain)] for coefficients in product(range(p), repeat=width)]
    assert min(sum(v != 0 for v in word) for word in code[1:]) == 7
    original = code[37]
    corrupted = list(original)
    corrupted[0] = (corrupted[0]+1) % p
    distances = [sum(a != b for a, b in zip(word, corrupted)) for word in code]
    assert min(distances) == 1 and distances.count(1) == 1
    assert corrupted not in code
    subsets = list(combinations(range(domain), 3))
    accepts = sum(all(corrupted[i] == original[i] for i in subset) for subset in subsets)
    assert Fraction(accepts, len(subsets)) == Fraction(5, 8)


def test_recursive_rs_component_counts_and_fixed_cap_are_not_complete_credit():
    s = plan.recursive_rs_opening_screen(1 << 35, 1 << 24, 357)
    assert s["credit"] is False
    assert [level["resident_cells"] for level in s["levels"]] == [2**25, 2**20, 2**15, 2**10]
    assert [level["queries"] for level in s["levels"]] == [357, 357, 357, 128]
    assert s["terminal_private_extension_cells"] == 32
    assert s["private_hash_calls_including_recursion"] == 169_679
    assert s["padded_permutation_instances"] == 2**18
    assert s["base_corrections_including_anchor_upper"] == 1_725_160
    assert s["extension_corrections_including_partial_sumchecks"] == 6634
    assert s["fresh_extension_correlations_including_product_mask"] == 6635
    assert s["component_payload_before_framing_and_other_components"] == 13_960_568
    assert s["model_setup_known_arrays_bytes"] == 5_637_144_576
    assert s["proof_known_arrays_conservative_union_bytes"] == 6_070_425_696
    assert s["all_inner_trees_bytes"] == 277_094_272
    assert s["outer_source_fft_butterflies"] == 1_786_706_395_136
    for n in (1 << 35, 1 << 55, 1 << 75):
        fixed = plan.recursive_rs_opening_screen(n, 1 << 24, 357)
        assert fixed["outer_source_fft_butterflies"] == 52*n
    for args in ((1 << 35, 1 << 25, 357), (64, 8, 9), (1 << 89, 1 << 24, 357)):
        with pytest.raises(ValueError):
            plan.recursive_rs_opening_screen(*args)


def test_a3_public_query_sampler_is_distinct_uniform_and_fails_closed():
    # Enumerate each pair of accepted residues. Partial Fisher-Yates gives
    # each ordered pair of distinct indices exactly once, not a multiset.
    outcomes = Counter(tuple(plan.a3_query_indices(4, 2, [a, b]))
                       for a in range(4) for b in range(3))
    assert outcomes == Counter({(a, b): 1 for a in range(4) for b in range(4) if a != b})
    assert plan.a3_query_indices(4, 4, iter(())) == [0, 1, 2, 3]
    assert plan.a3_query_indices(1, 1, iter(())) == [0]
    maximal = (1 << 64)-1
    assert plan.a3_query_indices(3, 1, [maximal]*3+[1]) == [1]
    with pytest.raises(ValueError, match="rejection limit"):
        plan.a3_query_indices(3, 1, [maximal]*4+[1])
    with pytest.raises(ValueError, match="truncated"):
        plan.a3_query_indices(4, 2, [0])
    for word in (-1, 1 << 64, True):
        with pytest.raises(ValueError):
            plan.a3_query_indices(4, 1, [word])
    for args in ((0, 1), (4, 5), (1 << 27, 1), (512, 358), (True, 1)):
        with pytest.raises(ValueError):
            plan.a3_query_indices(*args, [])
    for remaining in (3, 127, 4093, (1 << 26)-1):
        cutoff = (1 << 64) - (1 << 64) % remaining
        assert cutoff % remaining == 0
        assert 0 <= (1 << 64)-cutoff < remaining
    s = plan.a3_challenge_screen()
    assert s["extension_challenge_elements"] == 718
    assert s["base_challenge_coordinates"] == 2154
    assert s["random_query_indices"] == 1428
    assert s["max_u64_draws_per_attempt"] == 14_328
    assert s["max_u64_draws_for_response_slots_only"] == 15_023_996_928
    assert Fraction(s["honest_exhaustion_bound_numerator"],
                    s["honest_exhaustion_bound_denominator"]) < Fraction(1, 2**96)
    assert s["exhaustion_is_rejection_not_false_acceptance"]
    assert not s["credit"] and not s["complete_honest_fs_query_census"]


def test_ideal_mac_simulation_uses_actual_prefix_challenges_without_programming():
    # A tiny message-distribution test, NOT an E2E or cryptographic hash.
    # A fixed oracle may already be fully known to V*. Privacy does not
    # require its challenges to be uniform (soundness certainly does).
    p, k0, kc0, kt0, kr = 5, 1, 2, 3, 4
    tapes = list(product(range(p), repeat=4))
    for oracle in (lambda prefix: 0,
                   lambda prefix: sum((i+1)*(v+1)**2 for i, v in enumerate(prefix)) % p):
        for delta in range(p):
            def public_keys(d0, dc, dt):
                a = oracle((42, d0))
                return a, (k0-delta*(d0+a)) % p, (kc0-delta*dc) % p, (kt0-delta*dt) % p

            simulated = Counter()
            for d0, dc, dt, m1 in tapes:
                a, kx, kc, kt = public_keys(d0, dc, dt)
                chi = oracle((43, d0, dc, dt))
                m0 = (chi*(kx*kx+delta*kc)+kr+delta*m1) % p
                eta = oracle((44, d0, dc, dt, m0, m1))
                mz = eta*(kt-kc) % p
                simulated[(d0, a, dc, dt, chi, m0, m1, eta, mz)] += 1
            for witness in range(p):
                real = Counter()
                for u0, uc, ut, mask in tapes:
                    d0 = (witness-u0) % p
                    a = oracle((42, d0))
                    x = (witness+a) % p  # depends on an earlier FS response
                    c = x*x % p
                    dc, dt = (c-uc) % p, (c-ut) % p
                    mx, mc, mt = (k0+delta*u0) % p, (kc0+delta*uc) % p, (kt0+delta*ut) % p
                    chi = oracle((43, d0, dc, dt))
                    m0 = (chi*mx*mx+kr+delta*mask) % p
                    m1 = (chi*(2*x*mx-mc)+mask) % p
                    eta = oracle((44, d0, dc, dt, m0, m1))
                    mz = eta*(mt-mc) % p  # duplicate c wire, true zero residual
                    real[(d0, a, dc, dt, chi, m0, m1, eta, mz)] += 1
                assert real == simulated
                # Aborting on a public prefix cannot distinguish the views.
                for length in (1, 4, 7):
                    def project(distribution):
                        result = Counter()
                        for view, mass in distribution.items():
                            result[view[:length]] += mass
                        return result
                    assert project(real) == project(simulated)
    # NoPeek is necessary: x=w*u is invalid for the uniform-correction
    # argument. It distinguishes w=1 from w=0 despite a uniform fresh u.
    assert Counter((0*u-u) % p for u in range(p)) != Counter((1*u-u) % p for u in range(p))


def test_fixed_hash_circuit_is_not_an_independent_random_oracle():
    # Excludes a proposed HYBRID, not the actual hash or A3 construction.
    fixed = (2, 4)
    oracles = list(product(range(7), repeat=2))
    assert Fraction(sum(h[0] == fixed[0] for h in oracles), len(oracles)) == Fraction(1, 7)
    assert Fraction(sum(h == fixed for h in oracles), len(oracles)) == Fraction(1, 49)


def test_w_cut_counts_include_aliases_terminal_absorption_and_old_context():
    initial = plan.cut_witness_screen()
    assert initial["matrix_accumulator_cells"] == 647_475_200
    assert initial["weighted_norm_product_cells"] == 314_145_024
    assert initial["embedding_cells"] == 806_400
    assert initial["checkpoint_scalar_cells"] == 962_426_624
    assert initial["checkpoint_storage_bytes"] == 5_143_044_096
    assert initial["arena_bytes_after_checkpoint_only"] == 1_299_406_848
    assert initial["all_i64_matrix_storage_bytes_with_same_other_cuts"] == 6_437_994_496
    assert initial["rectangular_attention_cells_per_plane"] == 31_248_000
    for old in (150, 3900, 3946):
        screen = plan.cut_witness_screen(old)
        assert screen["checkpoint_storage_bytes"] == initial["checkpoint_storage_bytes"]
        assert screen["rectangular_attention_cells_per_plane"] == 31_248_000 + 288_000*old
    assert plan.cut_witness_screen(3900)["three_attention_planes_alone_exceed_arena"]
    assert plan.cut_witness_screen(3946)["three_retained_i16_attention_planes_only_bytes"] == 7_006_176_000
    assert not plan.cut_witness_screen(0, 4095, 1)["checkpoint_only_fits_arena"]
    assert not initial["credit"] and initial["complete_proof_w_passes"] is None
    for args in ((True,), (-1,), (3947,), (0, 0, 50), (0, 100, 0), (4096, 1, 1)):
        with pytest.raises(ValueError):
            plan.cut_witness_screen(*args)
    arrays = plan.report()["candidate_cut_opening_arrays"]
    assert arrays["ephemeral_outer_b_tree_bytes"] == 268_435_424
    assert arrays["b_plus_prehash_known_arrays_and_outer_tree_bytes"] == 5_730_163_408
    assert arrays["post_release_known_arrays_and_outer_tree_bytes"] == 1_308_539_600
    assert not arrays["credit"] and arrays["excludes_caller_kv_pcg_and_runtime"]
    # This simultaneous subset is already too large, unlike an upper-bound
    # union that merely fails to establish a feasible physical schedule.
    assert initial["checkpoint_storage_bytes"] + 2*24*(1 << 25) == 6_753_656_832


def test_i48_storage_preserves_exact_accumulators_not_a_field_codec():
    bound = 21_504*32768**2
    assert bound < 1 << 45 and 2*bound < plan.P
    assert plan.cut_witness_screen()["max_i16_dot_abs_bound"] == bound
    for value in (-bound, -32768**2, -1, 0, 1, 32768**2, bound):
        packed = value.to_bytes(6, "little", signed=True)
        assert int.from_bytes(packed, "little", signed=True) == value
        residue = value % plan.P
        assert (residue if residue <= plan.P//2 else residue-plan.P) == value
    for value in (-(1 << 47)-1, 1 << 47):
        with pytest.raises(OverflowError):
            value.to_bytes(6, "little", signed=True)


def test_cut_replay_never_reads_weights_and_mutations_violate_cut_equalities():
    # Synthetic DAG identity only: neither a Gemma implementation nor E2E.
    # Lambdas accessing weights=None would fail if replay touched W.
    weights = ((2, -3), (4, 5), (-2, 3), (7, -1))

    def execute(w, supplied=None):
        recorded, residuals = {}, []

        def cut(key, expression):
            value = expression() if supplied is None else supplied[key]
            recorded[key] = value
            if w is not None:
                residuals.append(value-expression())
            return value

        x = [cut(("embed", i), lambda i=i: w[0][i]) for i in range(2)]
        raw_k = cut(("dot", 0), lambda: sum(x[i]*w[1][i] for i in range(2)))
        raw_v = raw_k  # alias BEFORE weighted K normalization
        statistic = 1 + sum(v*v for v in x)  # W-free nonlinear input
        weighted = [cut(("norm", i), lambda i=i: x[i]*w[2][i]) for i in range(2)]
        norm = [round(Fraction(v, statistic)) for v in weighted]
        append = (raw_k + norm[0], raw_v*raw_v + norm[1])
        kv = (11, -13, *append)  # no overwritten/evicted prefix
        free_value = sum(kv) + sum(v*v for v in norm)
        raw_out = cut(("out", 0), lambda: free_value*w[3][0] + norm[0]*w[3][1])
        return (round(Fraction(raw_out, 8)), kv), recorded, residuals

    output, checkpoint, residuals = execute(weights)
    assert not any(residuals)
    replay, same, _ = execute(None, checkpoint)
    assert replay == output and same == checkpoint
    for key in checkpoint:
        bad = {**checkpoint, key: checkpoint[key]+1}
        assert any(execute(weights, bad)[2])  # even if rounding hides output change
    # Ties-to-even is retained at the declared point, never moved across W.
    assert [round(Fraction(v, 2)) for v in (-3, -1, 1, 3)] == [-2, 0, 0, 2]


def test_stacked_matrix_fold_requires_only_one_weight_scan_for_fixed_output_point():
    x = [[3*t + k*k - 5 for k in range(8)] for t in range(2)]
    w = [[7*j - k + j*k for k in range(8)] for j in range(4)]
    c = [[plan.dot(row, weight) for weight in w] for row in x]
    rt, rj, rk = [11], [13, 17], [19, 23, 29]
    # One pass over W builds W_bar; no query-dependent W forms are scanned.
    x_bar = [plan.mle([row[k] for row in x], rt) for k in range(8)]
    w_bar = [plan.mle([row[k] for row in w], rj) for k in range(8)]
    assert plan.mle(sum(c, []), rj+rt) == plan.dot(x_bar, w_bar)
    assert plan.mle(w_bar, rk) == plan.mle(sum(w, []), rk+rj)
    assert plan.mle(x_bar, rk) == plan.mle(sum(x, []), rk+rt)
    # The final inner point is an input to this link, not a future coin
    # that a preceding reduction/PCS scan can silently know.
    assert plan.mle(w_bar, rk) != plan.mle(w_bar, [rk[0]+1, *rk[1:]])


def test_dyadic_layout_covers_non_power_of_two_weights_exactly_once():
    for rows in range(1, 14):
        for cols in range(1, 14):
            tiles = plan.dyadic_weight_layout([(rows, cols), (5,)])
            owners, physical = {}, set()
            for tensor, row, col, height, width, offset in tiles:
                assert row % height == col % width == offset % (height*width) == 0
                for i in range(height):
                    for j in range(width):
                        key = (tensor, row+i, col+j)
                        address = offset+i*width+j
                        assert key not in physical and address not in owners
                        physical.add(key)
                        owners[address] = key
            assert set(owners) == set(range(rows*cols+5))
            assert physical == ({(0, i, j) for i in range(rows) for j in range(cols)}
                                | {(1, 0, j) for j in range(5)})
    s = plan.report()["dyadic_weight_layout_screen"]
    assert s["tiles"] == 3156
    assert s["live_cells_without_per_axis_padding"] == 30_697_345_280
    assert s["virtual_padded_domain_cells"] == 1 << 35
    assert s["counterfactual_fully_axis_padded_cells"] == 63_386_332_160
    assert not s["credit"] and s["changes_model_commitment_layout_and_profile_digest"]
    for shapes in ([(0,)], [(True, 2)], [(2, 3, 4)], [()]):
        with pytest.raises(ValueError):
            plan.dyadic_weight_layout(shapes)


def test_arbitrary_row_fold_form_evaluator_matches_dense_table():
    rng = random.Random(7105)
    for block in (1, 2, 4, 8, 16):
        for rows in (1, 2, 4, 8):
            n = rows*block
            alpha = [rng.randrange(plan.P) for _ in range(rows)]
            u = [rng.randrange(plan.P) for _ in range(block.bit_length()-1)]
            for bits in range(n.bit_length()):
                size = 1 << bits
                point = [rng.randrange(plan.P) for _ in range(bits)]
                for offset in range(0, n, size):
                    form = [0]*n
                    for index in range(size):
                        form[offset+index] = math.prod(
                            r if (index >> i) & 1 else 1-r for i, r in enumerate(point)) % plan.P
                    dense_fold = [sum(alpha[i]*form[i*block+j] for i in range(rows)) % plan.P
                                  for j in range(block)]
                    assert plan.folded_cube_form(offset, point, alpha, u) == plan.mle(dense_fold, u)
    for args in ((1, [2], [3, 4], [5]), (4, [], [3, 4], [5]), (-1, [], [3], [])):
        with pytest.raises(ValueError):
            plan.folded_cube_form(*args)
    # Compose physical tensor MLEs with the virtual tile map, including
    # unequal non-power-of-two axes and a vector. No padded weight copy.
    tiles = plan.dyadic_weight_layout([(5, 3), (7,)])
    points = [([2, 3, 5], [7, 11]), ([], [13, 17, 19])]
    alpha, u, dense, actual = [23+i for i in range(8)], [31, 37], [0]*32, 0
    def basis(index, point):
        return math.prod(r if (index >> i) & 1 else 1-r for i, r in enumerate(point)) % plan.P
    for tensor, row, col, height, width, offset in tiles:
        rj, rk = points[tensor]
        hj, hk = height.bit_length()-1, width.bit_length()-1
        coefficient = basis(row >> hj, rj[hj:])*basis(col >> hk, rk[hk:]) % plan.P
        actual += coefficient*plan.folded_cube_form(offset, rk[:hk]+rj[:hj], alpha, u)
        for i in range(height):
            for j in range(width):
                dense[offset+i*width+j] = basis(row+i, rj)*basis(col+j, rk) % plan.P
    expected = plan.mle([sum(alpha[i]*dense[4*i+j] for i in range(8)) % plan.P
                         for j in range(4)], u)
    assert actual % plan.P == expected


def test_fused_paired_fold_checks_the_same_fold_without_a_new_weight_evaluation():
    rows = [[(i+2)*(j+3) % plan.P for j in range(8)] for i in range(4)]
    forms = [[(i*i+1)*(j+5) % plan.P for j in range(8)] for i in range(4)]
    # Arbitrary/adaptive-form alpha is NOT replaced by an EQ vector.
    coins = [0, 7, 19]
    f, g, sums, _, claim = plan.paired_fold(rows, forms, coins)
    alpha = [1, *coins]
    a = [11, 13]
    rho = [math.prod(r if (i >> k) & 1 else 1-r for k, r in enumerate(a)) % plan.P
           for i in range(4)]
    f2 = [sum(rho[i]*rows[i][j] for i in range(4)) % plan.P for j in range(8)]
    assert sum(sums) % plan.P == sum(plan.dot(x, y) for x, y in zip(rows, forms)) % plan.P
    assert claim == plan.dot(f, g)
    encoded = [plan.small_goldilocks_fft(row + [0]*24) for row in rows]
    enc_f = plan.small_goldilocks_fft(f+[0]*24)
    enc_f2 = plan.small_goldilocks_fft(f2+[0]*24)
    indices = [2, 7, 21]
    y1 = [plan.dot(alpha, [row[k] for row in encoded]) for k in indices]
    y2 = [plan.dot(rho, [row[k] for row in encoded]) for k in indices]
    assert y1 == [enc_f[k] for k in indices] and y2 == [enc_f2[k] for k in indices]
    u, sigma = [17, 23, 29], 31
    eq_u = [math.prod(r if (j >> i) & 1 else 1-r for i, r in enumerate(u)) % plan.P
            for j in range(8)]
    roots = [pow(7, ((plan.P-1)//32)*k, plan.P) for k in indices]
    code_form = [sum(pow(sigma, 2*k+1, plan.P)*pow(t, j, plan.P)
                     for k, t in enumerate(roots)) % plan.P for j in range(8)]
    public_form = [(x+y) % plan.P for x, y in zip(eq_u, code_form)] + [sigma*x % plan.P for x in code_form]
    endpoint = plan.mle(f, u)
    z = (endpoint + sum(pow(sigma, 2*k+1, plan.P)*v1 + pow(sigma, 2*k+2, plan.P)*v2
                        for k, (v1, v2) in enumerate(zip(y1, y2)))) % plan.P
    assert z == plan.dot(f+f2, public_form)
    assert (z+1) % plan.P != plan.dot(f+f2, public_form)  # forged same-wire endpoint
    s = plan.paired_rs_opening_screen(1 << 35, 1 << 24, 357)
    assert s["weight_source_reads_for_fused_opening_only"] == 2
    assert s["additional_extension_corrections"] == 4168
    assert s["additional_extension_challenges"] == 2071
    assert s["component_payload_before_framing_and_caller"] == 14_060_600
    assert s["extension_correlations_including_shared_product_mask"] == 10_803
    assert s["paired_reduction_interactive_error_numerator"] == 4142
    assert not s["credit"] and s["complete_prover_weight_reads"] is None


def test_arbitrary_fold_does_not_deterministically_establish_proximity():
    p = 17
    def enc(message):
        return [(message[0]+message[1]*t) % p for t in range(8)]
    w = [(2, 3), (5, 7)]
    oracle = [enc(row) for row in w]
    oracle[0][0] = (oracle[0][0]+1) % p  # one corrupt column, d=7
    for alpha in ((0, 0), (1, 0), (0, 1), (4, 9)):
        honest = tuple(sum(alpha[i]*w[i][j] for i in range(2)) % p for j in range(2))
        folded_oracle = [sum(alpha[i]*oracle[i][k] for i in range(2)) % p for k in range(8)]
        for bad in product(range(p), repeat=2):
            if bad != honest:
                assert sum(x != y for x, y in zip(enc(bad), folded_oracle)) >= 7-1
    # alpha=(1,0) respects A4's fixed alpha[0]=1 but hides an arbitrary
    # second row. This excludes a deterministic proximity inference, not
    # a new probabilistic argument exploiting the distribution of beta.
    malformed = [(i*i) % p for i in range(8)]
    assert min(sum(x != y for x, y in zip(enc(m), malformed))
               for m in product(range(p), repeat=2)) >= 6
    assert [(1*0+0*x) % p for x in malformed] == enc((0, 0))


def test_p0_covers_named_weights_cut_offsets_and_terminal_absorption():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           "manifests/c7-d126-gemma31b-source-metadata-v1.json").read_bytes())
    tensors = [t for t in metadata["tensors"] if t["disposition"] == "private_text"]
    cohorts = plan.gemma_weight_cohorts(tensors)
    assert len(cohorts) == 773
    assert len({c["weight_key"] for c in cohorts}) == 772
    assert Counter(c["kind"] for c in cohorts) == {"matrix": 411, "norm": 361, "lookup": 1}
    cells = size = 0
    for i, c in enumerate(cohorts):
        assert (c["ordinal"], c["cut_cell_offset"], c["cut_byte_offset"]) == (i, cells, size)
        cells += c["rows"]*c["columns"]
        size += c["rows"]*c["columns"]*c["cut_scalar_bytes"]
    assert cells == 962_426_624 and size == 5_143_044_096
    by_op = {(c["layer"], c["operation"]): c for c in cohorts}
    assert (5, "v_source") not in by_op and (0, "v_source") in by_op
    assert by_op[5, "q_norm"]["rows"] == 150*32
    assert by_op[5, "k_norm"]["rows"] == 150*4
    assert by_op[0, "k_norm"]["rows"] == 150*16
    assert by_op[5, "q_norm"]["input_stage"] == "replay_i16_output"
    assert by_op[0, "input_rms"]["input_producer"] == {"layer": None, "operation": "embedding_scale"}
    assert by_op[5, "input_rms"]["input_producer"] == {"layer": 4, "operation": "layer_scalar_mul"}
    assert by_op[None, "final_rms"]["rows"] == 149
    assert by_op[None, "final_rms"]["row_schedule"] == "except_terminal_absorb"
    assert by_op[None, "lm_head"]["rows"] == 50
    assert by_op[None, "lm_head"]["row_schedule"] == "decisions"
    assert by_op[None, "embedding_lookup"]["rows"] == 150
    assert by_op[None, "lm_head"]["weight_key"] == by_op[None, "embedding_lookup"]["weight_key"]
    # A missing tensor, duplicate, extra global V or wrong dimension cannot
    # quietly shrink or rewire the proof statement.
    extra_v = {"name": "model.language_model.layers.5.self_attn.v_proj.weight", "shape": [2048, 5376]}
    for bad in (tensors[:-1], tensors+[tensors[0]], tensors+[extra_v],
                [{**tensors[0], "shape": [262144, 5375]}, *tensors[1:]]):
        with pytest.raises(ValueError):
            plan.gemma_weight_cohorts(bad)
    for args in ((0, 50), (100, False), (4096, 1)):
        with pytest.raises(ValueError):
            plan.gemma_weight_cohorts(tensors, *args)


def test_p0_accounting_never_treats_missing_input_links_as_completed():
    s = plan.report()["weight_cohort_screen"]
    assert s["cohort_manifest_sha256"] == "43d880822ed615cdab694ed08a8faef7119c704d58e230cc0c2875f1d694cba6"
    assert s["cut_dyadic_tiles"] == 6947
    assert s["sumcheck_rounds"] == 9586
    assert s["sumcheck_extension_coefficients"] == 32871
    assert s["extension_corrections_before_other_circuits"] == 35960
    assert s["message_bytes_before_framing_and_shared_closures"] == 863040
    assert s["extension_challenges_before_A4_and_link_batches"] == 25892
    assert s["fixed_oracle_interactive_error_numerator"] == 39591
    assert s["weight_batch_interactive_error_numerator"] == 773
    assert s["compact_operand_vectors_bytes"] == 300_646_400
    assert s["known_b_tree_vectors_scratch_and_messages_union_bytes"] == 5_714_441_824
    assert s["private_product_equations"] == s["w_free_input_evaluation_obligations"] == 772
    assert s["cut_output_evaluation_obligations"] == 773
    assert s["w_dependent_subsystem_source_reads_with_A4"] == 3
    assert s["complete_prover_weight_reads"] is None
    assert not s["credit"] and not s["non_w_input_links_or_range_proofs_compiled"]


def test_broadcast_norm_reduction_has_degree_three_and_same_input_endpoint():
    # Three tokens, two heads: flatten token/head with head fastest. The
    # physical scale vector is shared, not replicated six times in W.
    p, rows, width, domain = plan.P, 6, 5, 8
    x = [[(r+2)*(d+1)-7 for d in range(width)]+[0]*3 for r in range(rows)]
    x += [[0]*domain for _ in range(2)]
    w = [2, -3, 5, -7, 11, 0, 0, 0]
    c = [[v*w[d] % p for d, v in enumerate(row)] for row in x]
    rr, rd, coins = [2, 3, 5], [7, 11, 13], [17, 19, 23]
    xbar = [plan.mle([row[d] for row in x], rr) for d in range(domain)]
    def kernel(a, b):
        return math.prod((1-u)*(1-v)+u*v for u, v in zip(a, b)) % p
    def integrand(point):
        return kernel(rd, point)*plan.mle(xbar, point)*plan.mle(w, point) % p
    def partial_sum(prefix):
        return sum(integrand(prefix+list(tail))
                   for tail in product((0, 1), repeat=3-len(prefix))) % p
    claim = plan.mle(sum(c, []), rd+rr)
    assert claim == partial_sum([])
    assert (claim+1) % p != partial_sum([])
    for i, coin in enumerate(coins):
        prefix = coins[:i]
        assert claim == (partial_sum(prefix+[0])+partial_sum(prefix+[1])) % p
        samples = [partial_sum(prefix+[t]) for t in range(5)]
        for _ in range(4):
            samples = [(b-a) % p for a, b in zip(samples, samples[1:])]
        assert samples == [0]
        claim = partial_sum(prefix+[coin])
    xe, we = plan.mle(sum(x, []), coins+rr), plan.mle(w, coins)
    assert xe == plan.mle(xbar, coins)
    assert claim == kernel(rd, coins)*xe*we % p
    assert we != plan.mle(w, rd)  # output point is not the final W point
    # One-bit X=W=z and output coordinate 2 gives (3z-1)z^2.
    samples = [(3*t-1)*t*t % p for t in range(4)]
    for _ in range(3):
        samples = [(b-a) % p for a, b in zip(samples, samples[1:])]
    assert samples == [18]  # a degree-two schema cannot represent it


def test_embedding_lookup_is_one_linear_claim_with_duplicates_and_last_token():
    vocab, hidden, tokens = 8, 4, [2, 5, 2]
    embedding = [[(j+2)*(k*k+1)-3 for k in range(hidden)] for j in range(vocab)]
    rt, rh = [7, 11], [13, 17]
    weights = [math.prod(r if (t >> i) & 1 else 1-r for i, r in enumerate(rt)) % plan.P
               for t in range(4)]
    rows = [embedding[t] for t in tokens]+[[0]*hidden]
    claim = plan.mle(sum(rows, []), rh+rt)
    aggregate = Counter()
    for t, token in enumerate(tokens):
        aggregate[token] += weights[t]
    assert len(aggregate) == 2
    expected = sum(a*plan.mle(embedding[token], rh) for token, a in aggregate.items()) % plan.P
    assert claim == expected
    skipped_terminal = sum(weights[t]*plan.mle(embedding[token], rh)
                           for t, token in enumerate(tokens[:-1])) % plan.P
    assert skipped_terminal != claim
    # Rebinding to a different matrix changes the required A4 functional.
    changed = [list(row) for row in embedding]
    changed[2][0] += 1
    assert sum(a*plan.mle(changed[token], rh) for token, a in aggregate.items()) % plan.P != claim
