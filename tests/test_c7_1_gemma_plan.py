"""Small C7.1 accounting/algebra/DAG checks; no weights, native build or GPU."""

import importlib.util
import json
import math
import random
import runpy
from collections import Counter
from fractions import Fraction
from itertools import combinations, permutations, product
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
    assert s["chain_groups"] == 342  # final group has two live row slots
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
    assert s["setup_code_rows_and_chain_digests_bytes"] == 5_368_709_120
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


@pytest.mark.parametrize('width', (4, 32))
def test_power_round_adjoint_sumcheck_and_single_input_endpoint(width):
    # Two independent permutations, not a Poseidon implementation/KAT.
    # The proof identity must work for ANY public linear layer and constants.
    rng = random.Random(7127)
    p, size = plan.P, 2*width
    bits = size.bit_length()-1
    matrix = [[rng.randrange(p) for _ in range(width)] for _ in range(width)]
    constants = [rng.randrange(p) for _ in range(width)]
    x = [rng.randrange(p) for _ in range(size)]
    output_point, coins = list(range(2, bits+2)), list(range(11, bits+11))
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
                       for tail in product((0, 1), repeat=bits-len(prefix))) % p

        claim = plan.mle(y, output_point)
        assert claim == partial_sum([])
        assert (claim + 1) % p != partial_sum([])  # altered output claim
        degree = 9 if partial else 8
        for i in range(bits):
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


def test_public_parameter_tape_is_finite_canonical_and_has_no_nonce_retry():
    def block(*words):
        return b''.join(x.to_bytes(8, 'little') for x in words)
    p = plan.P
    tapes = [block(p, (1 << 64)-1, p+1, i) for i in range(287)]
    assert plan.wide_hash_public_parameters(tapes) == tuple(range(287))
    # First accepted proposal wins; later bytes cannot choose a different key.
    tapes[0] = block(p-1, 1, 2, 3)
    assert plan.wide_hash_public_parameters(tapes)[0] == p-1
    tapes[-1] = block(p, p, p, p)
    assert plan.wide_hash_public_parameters(tapes) is None
    for malformed in (tapes[:-1], tapes+[bytes(32)], [bytes(31)]+tapes[1:],
                      [bytearray(32)]+tapes[1:], iter(tapes)):
        with pytest.raises(ValueError):
            plan.wide_hash_public_parameters(malformed)
    descriptor = b'fixed pre-profile, not root/salt/session/nonce'
    addresses = [b'C71A5K01'+len(descriptor).to_bytes(8, 'little')+descriptor+i.to_bytes(4, 'little')
                 for i in range(287)]
    assert len(set(addresses)) == 287
    assert all(len(x) == 20+len(descriptor) for x in addresses)
    s = plan.wide_hash_parameter_screen()
    assert s['canonical_constant_vector_bytes'] == 2296
    assert s['public_parameter_rom_output_bytes'] == 9184
    assert s['maximum_u64_proposals'] == 1148
    exhaustion = Fraction(s['setup_exhaustion_union_bound_numerator'],
                          s['setup_exhaustion_union_bound_denominator'])
    assert 0 < exhaustion < Fraction(287, 1 << 128) < Fraction(1, 1 << 119)
    denominator = s['comparison_gen_bit_density_ratio_denominator_per_coordinate']
    low = Fraction(s['comparison_gen_bit_min_density_ratio_numerator_per_coordinate'], denominator)
    high = Fraction(s['comparison_gen_bit_max_density_ratio_numerator_per_coordinate'], denominator)
    assert 1 < (high/low)**287 < 1+Fraction(1, 1 << 86)
    assert not s['credit'] and s['complete_security_bits'] is None


def test_random_parameter_embedding_couples_the_whole_public_tape_not_just_the_key():
    # Two coordinates, two proposals, small field p=3 in four possible words.
    # Exact finite version of A5-P's reduction, NOT a hash-security test.
    p, space, coordinates, tries = 3, 4, 2, 2
    tapes = list(product(range(space), repeat=coordinates*tries))
    keys = list(product(range(p), repeat=coordinates))

    def decode(tape):
        result, positions = [], []
        for i in range(coordinates):
            offset = i*tries
            accepted = next((j for j in range(tries) if tape[offset+j] < p), None)
            if accepted is None:
                return None
            result.append(tape[offset+accepted])
            positions.append(offset+accepted)
        return tuple(result), positions

    real, embedded = Counter(), Counter()
    for tape in tapes:
        decoded = decode(tape)
        real[None if decoded is None else (decoded[0], tape)] += 1
        for independent_key in keys:
            if decoded is None:
                embedded[None] += 1
            else:
                programmed = list(tape)
                for pos, value in zip(decoded[1], independent_key):
                    programmed[pos] = value
                assert decode(programmed)[0] == independent_key
                embedded[independent_key, tuple(programmed)] += 1
    assert embedded == Counter({record: len(keys)*mass for record, mass in real.items()})
    assert Fraction(real[None], len(tapes)) == Fraction(31, 256)
    assert Counter({key: sum(mass for record, mass in real.items()
                             if record is not None and record[0] == key) for key in keys}) == Counter({key:25 for key in keys})
    # Taking the first proposal modulo p would not have this distribution.
    assert Counter(x % p for x in range(space)) == Counter({0:2, 1:1, 2:1})
    # A strictly finite comparison key generator (NOT the actual decoder):
    # each coordinate uses its first proposal mod p only if all proposals
    # fail. Its distribution dominates s times the independent uniform key.
    bit_keys = Counter()
    for tape in tapes:
        key = tuple(next((x for x in tape[i*tries:(i+1)*tries] if x < p), tape[i*tries] % p)
                    for i in range(coordinates))
        bit_keys[key] += 1
    assert min(bit_keys.values()) == 25 and max(bit_keys.values()) == 36
    bit_embedded = Counter()
    for key, mass in bit_keys.items():
        for tape in tapes:
            decoded = decode(tape)
            if decoded is not None:
                programmed = list(tape)
                for pos, value in zip(decoded[1], key):
                    programmed[pos] = value
                bit_embedded[key, tuple(programmed)] += mass
    # Denominators are 256^2 vs 256: R_success >= (225/256)*real_success
    # for EVERY success predicate on valid records, not just one chosen test.
    assert all(bit_embedded[record] >= 225*mass for record, mass in real.items() if record is not None)
    # Free oracle-dependent advice can store a collision after learning a
    # fixed-address parameter. Charging only later ROM queries misses it.
    families = list(product(range(2), repeat=3))
    advice = [next((i,j) for i,j in combinations(range(3), 2) if h[i] == h[j]) for h in families]
    assert all(h[i] == h[j] for h, (i,j) in zip(families, advice))
    assert sum(h[0] == h[1] for h in families) == len(families)//2
    # A free descriptor/nonce changes the distribution through key grinding.
    assert Fraction(sum(0 in pair for pair in product(range(3), repeat=2)), 9) == Fraction(5, 9) > Fraction(1, 3)
    # Nor does output-only salting turn a fixed weak function into a CR family.
    assert all((0 % 3 + key) % 3 == (3 % 3 + key) % 3 for key in range(3))


def test_wide_hash_matrix_candidate_irreducibility_period_limit_and_branch_counterexample():
    # Independent exact field checks, no dependency on a local Cargo checkout.
    p, d = plan.P, plan.WIDE_HASH_INTERNAL_D
    assert len(d) == len(set(d)) == 32 and all(0 < x < p-1 for x in d)
    screen = plan.wide_hash_parameter_screen()
    assert screen['nominated_internal_matrix_grain_candidate'] == 20
    assert screen['internal_matrix_checked_minimal_polynomial_powers'] == 64
    assert screen['external_matrix_branch_number_at_width_32'] == 10
    assert screen['public_linear_and_round_parameter_bytes_if_materialized_as_u64'] == 2680
    assert screen['matrix_check_is_not_security_of_the_hash_family']
    assert screen['complete_security_bits'] is None and not screen['credit']

    def trim(a):
        a = [x % p for x in a]
        while a and a[-1] == 0:
            a.pop()
        return a

    def remainder(a, b):
        a = trim(a)
        while len(a) >= len(b):
            scale, offset = a[-1]*pow(b[-1], -1, p) % p, len(a)-len(b)
            for j, x in enumerate(b):
                a[offset+j] = (a[offset+j]-scale*x) % p
            a = trim(a)
        return a

    def mul(a, b):
        c = [0]*(len(a)+len(b)-1)
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                c[i+j] += x*y
        return trim(c)

    def power(a, n, f):
        result = [1]
        while n:
            if n & 1:
                result = remainder(mul(result, a), f)
            a = remainder(mul(a, a), f)
            n //= 2
        return result

    def characteristic(diagonal):
        g = [1]
        for x in diagonal:
            g = mul(g, [-x, 1])
        return [(g[i]-(i+1)*g[i+1]) % p for i in range(32)]+[1]  # g - g'

    f = characteristic(d)
    assert f[0] == 14437940495880588463 and f[31] == 7786252787259156851
    x, frobenius = [0, 1], [0, 1]
    for i in range(1, 33):
        frobenius = power(frobenius, p, f)
        if i == 16:
            xp16 = frobenius
    assert frobenius == x
    # Rabin: 2 is the ONLY prime divisor of degree 32.
    difference = xp16[:]
    difference[1] = (difference[1]-1) % p
    a, b = f, trim(difference)
    while b:
        a, b = b, remainder(a, b)
    assert len(a) == 1  # gcd = a nonzero constant
    # F_{p^16} contains every proper subfield of F_{p^32}.
    a, b = [1], [1]
    for j in range(1, 65):
        a, b = remainder(mul(a, x), f), remainder(mul(b, xp16), f)
        assert a != b  # minpoly(M_I^j) remains irreducible of degree 32
    bad = list(d)
    bad[1] = bad[0]
    assert remainder(characteristic(bad), [-bad[0] % p, 1]) == []
    # No claim for all powers: every invertible finite-field matrix has finite order.

    m4 = ((5, 7, 1, 3), (4, 6, 1, 1), (1, 3, 5, 7), (1, 1, 4, 6))

    def small_det(matrix):
        n = len(matrix)
        return sum((-1)**sum(pi[i] > pi[j] for i in range(n) for j in range(i+1, n))
                   * math.prod(matrix[i][pi[i]] for i in range(n))
                   for pi in permutations(range(n))) % p

    for size in range(1, 5):
        for rows in combinations(range(4), size):
            for cols in combinations(range(4), size):
                assert small_det([[m4[i][j] for j in cols] for i in rows]) != 0
    assert small_det(m4) == p-64
    delta = [1, 0, 0, 0, p-1]+[0]*27
    image = plan.wide_hash_external_layer(delta)
    assert sum(x != 0 for x in delta)+sum(x != 0 for x in image) == 10
    assert image[:4] == [5, 4, 1, 1] and image[4:8] == [p-5, p-4, p-1, p-1]
    assert image[8:] == [0]*24  # extrapolating t/4 + 4 = 12 is FALSE

    # Solve K*delta=e_31. K has rows e_0^T M_I^j: first 31 observations vanish.
    def internal(v):
        return [(sum(v)+a*b) % p for a, b in zip(d, v)]

    rows, row = [], [1]+[0]*31
    for i in range(32):
        rows.append(row+[int(i == 31)])
        row = internal(row)  # M_I is symmetric
    for col in range(32):
        pivot = next(i for i in range(col, 32) if rows[i][col])
        rows[col], rows[pivot] = rows[pivot], rows[col]
        inv = pow(rows[col][col], -1, p)
        rows[col] = [x*inv % p for x in rows[col]]
        for i in range(32):
            if i != col:
                scale = rows[i][col]
                rows[i] = [(a-scale*b) % p for a, b in zip(rows[i], rows[col])]
    delta = [row[-1] for row in rows]
    left = list(range(32))
    right = [(x+y) % p for x, y in zip(left, delta)]
    for c in range(31):
        assert left[0] == right[0]
        left[0], right[0] = pow((left[0]+c) % p, 7, p), pow((right[0]+c) % p, 7, p)
        left, right, delta = internal(left), internal(right), internal(delta)
        assert [(y-x) % p for x, y in zip(left, right)] == delta
    assert (right[0]-left[0]) % p == 1  # 32nd observation activates the S-box


def test_wide_hash_synthetic_kat_dense_reference_and_canonical_boundaries():
    # Generated by pinned Plonky3 reference with kappa_i=i, NOT the A5-P ROM key.
    p, state, constants = plan.P, list(range(32)), list(range(287))
    expected = [
        2665971768509308906, 6842097402474080602, 5470101337659384119, 2205913928992772001,
        5484641930518151673, 3003498818228073874, 763028910431323474, 4716417881938479838,
        7746404534393955240, 8721651053263051862, 12171701283354057907, 11430837445711909102,
        8185038382918746106, 2409673755423059383, 14639823799181174848, 14546259947285653708,
        13021138035883737359, 14439965376961823857, 7932940684373949274, 9477509535063134328,
        10202911114514439456, 7256095367710001545, 15455058043354457906, 8927775922309459168,
        12282831415944952094, 2189809614173084429, 11726017790252760537, 4776001327380632967,
        16332459765949663076, 9591128959984053757, 12560354539468325398, 16264724296215543856,
    ]
    assert plan.wide_hash_permutation(state, constants) == expected
    m4 = ((5, 7, 1, 3), (4, 6, 1, 1), (1, 3, 5, 7), (1, 1, 4, 6))
    external = [[(1+int(i//4 == j//4))*m4[i % 4][j % 4] for j in range(32)] for i in range(32)]
    internal = [[1+(plan.WIDE_HASH_INTERNAL_D[i] if i == j else 0) for j in range(32)]
                for i in range(32)]

    def dense(matrix, v):
        return [sum(a*b for a, b in zip(row, v)) % p for row in matrix]

    rng = random.Random(7132)
    for v in (state, [0]*32, [p-1]*32, [rng.randrange(p) for _ in range(32)]):
        rcs = constants if v == state else [rng.randrange(p) for _ in range(287)]
        u = dense(external, v)
        for offset in range(0, 128, 32):
            u = dense(external, [pow((x+c) % p, 7, p) for x, c in zip(u, rcs[offset:offset+32])])
        for c in rcs[128:159]:
            u = dense(internal, [pow((u[0]+c) % p, 7, p)]+u[1:])
        for offset in range(159, 287, 32):
            u = dense(external, [pow((x+c) % p, 7, p) for x, c in zip(u, rcs[offset:offset+32])])
        assert plan.wide_hash_permutation(v, rcs) == u
    assert math.gcd(7, p-1) == 1 and pow(7, -1, p-1) == 10540996611094048183
    for index in (0, 128, 159, 286):
        altered = constants[:]
        altered[index] += 1
        assert plan.wide_hash_permutation(state, altered) != expected
    for bad in (state[:-1], [True]+state[1:], [-1]+state[1:], [p]+state[1:], iter(state)):
        with pytest.raises(ValueError):
            plan.wide_hash_permutation(bad, constants)
    for bad in (constants[:-1], [True]+constants[1:], [-1]+constants[1:], [p]+constants[1:], None):
        with pytest.raises(ValueError):
            plan.wide_hash_permutation(state, bad)
    assert state == list(range(32)) and constants == list(range(287))


def test_sampled_round_fixed_trails_are_markov_but_not_collision_or_adaptive_bounds():
    # Exhaust all 11^4 keys of a two-lane/two-full-round toy, not the A5 hash.
    p, exponent = 11, 3
    vectors = list(product(range(p), repeat=2))

    def linear(v):
        return ((v[0]+v[1]) % p, (v[0]+2*v[1]) % p)

    def inverse_linear(v):
        return ((2*v[0]-v[1]) % p, (-v[0]+v[1]) % p)

    def round_fn(v, key):
        return linear(tuple(pow((x+c) % p, exponent, p) for x, c in zip(v, key)))

    def difference(left, right):
        return tuple((y-x) % p for x, y in zip(left, right))

    ddt = {(a, b): sum((pow(x+a, exponent, p)-pow(x, exponent, p)) % p == b
                       for x in range(p)) for a in range(p) for b in range(p)}
    assert max(ddt[a, b] for a in range(1, p) for b in range(p)) == exponent-1
    assert all(ddt[0, b] == (p if b == 0 else 0) for b in range(p))
    histogram = Counter()
    for first_key in vectors:
        left, right = round_fn((0, 0), first_key), round_fn((1, 0), first_key)
        d1 = difference(left, right)
        for second_key in vectors:
            d2 = difference(round_fn(left, second_key), round_fn(right, second_key))
            histogram[d1, d2] += 1

    # The complete joint law equals the product of per-round DDT counts.
    expected = Counter()
    for d1, d2 in product(vectors, repeat=2):
        eta1, eta2 = inverse_linear(d1), inverse_linear(d2)
        count = ddt[1, eta1[0]]*ddt[0, eta1[1]]*ddt[d1[0], eta2[0]]*ddt[d1[1], eta2[1]]
        if count:
            expected[d1, d2] = count
            assert 1+sum(x != 0 for x in d1) >= 3  # two-round branch number
    assert histogram == expected and sum(histogram.values()) == p**4
    assert len(histogram) == 216
    fixed_trail_max = Fraction(max(histogram.values()), p**4)
    assert fixed_trail_max == Fraction(2, p)**3 == Fraction(8, 1331)
    # Truncate to one lane: summing different paths is NOT a single path.
    collision = Fraction(sum(count for (_, out), count in histogram.items() if out[0] == 0), p**4)
    assert collision == Fraction(12, 121) > fixed_trail_max
    # The SAME public key is reused; repeating an event does not square its probability.
    repeated = Fraction(sum(count for (_, out), count in histogram.items()
                            if out[0] == 0 and out[0] == 0), p**4)
    assert repeated == collision > collision**2
    # After seeing a one-round toy key, invert two chosen outputs sharing lane 0.
    # This exploits the toy's unrestricted inputs, NOT A5's framed/capacity-zero inputs.
    inverse_exponent = pow(exponent, -1, p-1)
    for key in vectors:
        inputs = [tuple((pow(z, inverse_exponent, p)-c) % p
                        for z, c in zip(inverse_linear(out), key)) for out in ((0, 0), (0, 1))]
        assert inputs[0] != inputs[1]
        assert [round_fn(v, key) for v in inputs] == [(0, 0), (0, 1)]
    s = plan.wide_hash_fixed_trail_screen()
    assert s['disjoint_consecutive_full_round_pairs'] == 4
    assert s['active_full_sboxes_lower_bound'] == 40
    assert s['removing_one_full_round_per_half_leaves_pairs'] == 2
    bound = Fraction(s['fixed_trail_probability_bound_numerator'], s['fixed_trail_probability_bound_denominator'])
    assert bound == Fraction(6, plan.P)**40 < Fraction(1, 1 << 2456)
    assert s['fixed_trail_negative_log2_bound_floor'] == 2456
    assert Fraction(6, plan.P)**20 < Fraction(1, 1 << 1228)
    assert s['requires_input_pair_and_characteristic_fixed_before_public_parameters']
    assert s['requires_independent_uniform_constants_at_distinct_round_positions']
    assert not s['repeated_hash_evaluations_have_independent_keys']
    assert not s['bounds_collision_hulls_or_post_parameter_input_search']
    assert not s['changes_nominated_rounds_or_component_resource_counts']
    assert not s['credit'] and s['complete_security_bits'] is None


def test_wide_hash_recounts_anchor_recursion_and_known_memory_without_security_credit():
    report = plan.report()
    w = report['wide_hash_rs_screen']
    assert w['nominated_width_full_partial_rounds'] == [32, 8, 31]
    assert w['digest_space_cardinality'] == plan.P**8 < 2**512
    assert w['salt_space_cardinality'] == plan.P**4 < 2**256
    assert w['private_hash_calls_including_anchor_and_recursion'] == 113571
    assert w['base_corrections_including_salt'] == 1982028
    assert w['power_gkr_extension_corrections'] == 8599
    assert w['extension_corrections_including_partial_sumchecks'] == 8659
    assert w['private_component_payload_before_framing_and_caller'] == 16064112
    assert w['public_anchor_bytes_each_time_sent_not_in_private_payload'] == 64
    assert w['hash_trace_and_four_fold_tables_bytes'] == 1744830464
    assert w['tiled_commit_source_traversals'] == 32  # ModelSetup, not warm proof
    assert w['tiled_commit_native_fft_butterflies'] == 1664*(1 << 35)
    assert w['tiled_commit_scratch_before_source_and_retained_cache_bytes'] == 1107296256
    wide_paired_w = (w['private_component_payload_before_framing_and_caller']
                    +report['paired_rs_opening_screen']['component_payload_before_framing_and_caller']
                    -report['recursive_rs_opening_screen']['component_payload_before_framing_and_other_components'])
    assert wide_paired_w == 16164144
    # The two high lane bits select exactly the first eight of 32 outputs.
    outputs = [i*i+3*i for i in range(64)]
    assert plan.mle(outputs, [2, 3, 5, 0, 0, 7]) == plan.mle(outputs[:8]+outputs[32:40], [2, 3, 5, 7])
    arena = 6442450944
    assert w['literal_full_row_group_encoder_bytes'] == 9932111872 > arena
    resident = report['packed_weight_bytes']+report['kv_capacity_i16_bytes']+arena
    assert resident+w['full_outer_tree_bytes'] == 80118063552 > 80000000000
    assert resident+w['outer_internal_only_tree_bytes'] < 80000000000
    assert w['prehash_known_arrays_union_bytes'] == 4913099184 < arena
    assert w['post_source_and_tree_release_hash_known_union_bytes'] == 1808670992 < arena
    # A2 remains unchanged; a wide candidate is not a parameter-only upgrade.
    assert report['recursive_rs_opening_screen']['component_payload_before_framing_and_other_components'] == 13960568
    for old, wide, payload, peak in zip(report['auxiliary_witness_screens'],
            report['wide_hash_witness_screens'], (10402496, 15706688), (6374913144, 6404645880)):
        assert wide['same_source_layout_sha256'] == old['layout_sha256']
        assert wide['private_paired_pcs_payload_before_public_anchor_framing_and_caller'] == payload
        assert wide['commit_source_traversals'] == 16
        assert wide['commit_native_fft_butterflies'] == 800*old['source_padded_byte_cells']
        assert wide['query_reconstructed_columns_upper'] == 5712
        assert wide['query_extra_group_and_digest_bytes'] == 822528
        assert wide['compact_c1_cache_bytes'] == 67108800
        phases = [value for key, value in wide.items() if key.endswith('_union_before_full_replay_runtime')]
        assert max(phases) == peak < arena
        assert not wide['source_reader_all_gamma_forms_and_full_liveness_compiled']
        assert wide['complete_certificate_bytes'] is None and not wide['credit']
    assert not w['matrix_constants_hash_security_and_full_profile_instantiated']
    assert w['complete_security_bits'] is None
    for args in ((3, 1, 1), (1 << 26, 1 << 25, 357), (16, 4, 5),
                 (True, 1, 1), (1 << 64, 1 << 24, 357)):
        with pytest.raises(ValueError):
            plan.wide_hash_rs_screen(*args)


def test_joint_w_kv_recount_excludes_separate_codec_but_not_complete_feasibility():
    report = plan.report()
    w = report['wide_hash_rs_screen']['private_component_payload_before_framing_and_caller']
    w += 24*report['paired_rs_opening_screen']['additional_extension_corrections']
    # Most favorable KV block in the entire admitted power-of-two range.
    choices = []
    for bits in range(9, 25):
        s = plan.wide_hash_rs_screen(1 << 31, 1 << bits, 357)
        a = plan.paired_rs_opening_screen(1 << 31, 1 << bits, 357)
        choices.append((s['private_component_payload_before_framing_and_caller']
                        +24*a['additional_extension_corrections'], bits))
    assert min(choices) == (6192480, 24)
    # Remove three duplicate closures even before charging any caller/anchor.
    assert w+15706688+2*min(choices)[0]-3*72 == 44255576 > 35000000
    assert 44255576-24*(2*8599+2*8217) == 43448408 > 35000000
    for screen, counts in zip(report['wide_hash_witness_screens'],
            ((108932, 1892544, 15546576, 8918768, 66911, 26071328),
             (124438, 2154924, 17645616, 14232128, 77963, 33749040))):
        joint = screen['joint_w_kv_candidate']
        a, b = joint['weight_and_state_opening'], joint['auxiliary_opening']
        calls, inputs, wa, sigma, caller, total = counts
        assert a['private_hash_calls_including_anchors_and_one_recursion'] == calls
        assert a['base_corrections_including_salts'] == inputs
        assert a['extension_corrections_including_paired_sumchecks'] == 16923
        assert a['fresh_extension_correlations_including_product_mask'] == 16924
        assert a['joint_rows'] == 4096
        assert a['paired_reduction_interactive_error_numerator'] == 8238
        assert a['private_component_payload_before_framing_and_caller'] == wa
        assert b['private_component_payload_before_framing_and_caller'] == sigma
        assert joint['known_caller_extension_corrections'] == caller
        assert (a['fresh_extension_correlations_including_product_mask']
                +b['fresh_extension_correlations_including_product_mask']+caller-1
                == (94214 if screen['old_tokens'] == 0 else 107696))
        assert wa+sigma-72+24*caller+a['public_anchor_bytes_if_all_resent']+64 == total
        assert joint['known_partial_payload_with_all_anchors_and_one_shared_closure'] == total
        assert joint['remaining_bytes_before_uncompiled_gamma_framing_refresh'] == 35000000-total
        assert not joint['inherits_previous_memory_peaks']
        assert not a['full_root_compilation_caller_and_liveness_proved'] and not a['credit']
        assert screen['complete_certificate_bytes'] is None
    # A singleton reproduces exactly the deduplicated A5+A4 count.
    s = plan.wide_hash_rs_screen(1 << 31, 1 << 24, 357, True)
    a = plan.paired_rs_opening_screen(1 << 31, 1 << 24, 357)
    assert plan.wide_hash_joint_opening_screen([1 << 31], 1 << 24, 357)[
        'private_component_payload_before_framing_and_caller'] == (
            s['private_component_payload_before_framing_and_caller']
            +24*a['additional_extension_corrections']) == 4611360
    for sources in ([], [8]*4, [True], [12], [2], [1 << 64]):
        with pytest.raises(ValueError):
            plan.wide_hash_joint_opening_screen(sources, 4, 3)
    with pytest.raises(ValueError):
        plan.wide_hash_rs_screen(16, 4, 3, 1)


def test_joint_state_cache_schedule_accounts_for_b_barrier_and_reconstruction():
    report = plan.report()
    required_phases = {'commit_new_kv', 'commit_sigma', 'p0_compact_operands',
        'seed_reducer', 'k1_append', 'k1_view_router', 't1_one_layer', 'rne_link',
        'rne_top', 'range', 'opening_first_pass', 'compact_c1_commit',
        'compact_c1_sumcheck', 'opening_query', 'sigma_tail_after_b_release',
        'joint_w_kv_after_sigma_release', 'hash_after_compact_release'}
    for screen, expected in zip(report['wide_hash_witness_screens'],
            ((1, 6288651520, 6268344096, 4999717632, 99762080),
             (2, 6330273152, 6331657600, 5066691712, 129825536))):
        s = screen['joint_w_kv_candidate']['known_state_cache_schedule']
        states, commit_kv, commit_c1, joint, records = expected
        phases = s['arena_phases_bytes_before_uncompiled_reader_gamma_runtime']
        assert set(phases) == required_phases
        assert s['state_cache_count'] == states
        assert s['kv_cache_bytes_each'] == 64*((8*(1 << 24) >> 8)-1) == 33554368
        assert s['sigma_cache_bytes'] == 64*((8*(1 << 23) >> 5)-1) == 134217664
        assert phases['commit_new_kv'] == commit_kv
        assert phases['compact_c1_commit'] == commit_c1
        assert phases['joint_w_kv_after_sigma_release'] == joint
        assert s['known_authenticated_record_bytes_after_b_release'] == records
        assert s['known_phase_max_bytes'] == max(phases.values()) == max(commit_kv, commit_c1)
        assert s['arena_remaining_before_uncompiled_reader_gamma_runtime'] == 6442450944-max(phases.values()) > 0
        assert s['state_and_joint_descriptor_bytes'] == 7680*states+144
        assert s['early_state_root_record_bytes'] == 384*states
        assert s['new_state_commit_source_visits'] == 32
        state_cells = screen['joint_w_kv_candidate']['weight_and_state_opening']['source_cells'][-1]
        assert s['new_state_commit_native_fft_butterflies'] == 32*52*state_cells
        assert s['accepted_state_rebuild_visits_if_cache_missing'] == (32 if states == 2 else 0)
        assert s['query_expanded_kv_columns_each_upper'] == 256*357 == 91392
        assert s['query_expanded_sigma_columns_upper'] == 32*357 == 11424
        assert s['query_kv_group_digest_buffer_bytes_one_at_a_time'] == 144*91392 == 13160448
        assert s['query_local_kv_hash_calls_each_upper'] == ([182427] if states == 1 else [1279131]*2)
        assert s['requires_last_b_consumer_before_joint_opening']
        assert s['complete_gamma_liveness'] is None and not s['credit']
        # Neither a second scratch nor the full W/KV opening can coexist with B.
        assert joint+report['cut_witness_screens'][0]['checkpoint_storage_bytes'] > 6442450944
        assert not screen['joint_w_kv_candidate']['inherits_previous_memory_peaks']
    last = report['wide_hash_witness_screens'][-1]['joint_w_kv_candidate']['known_state_cache_schedule']
    assert last['literal_sigma_c1_with_height4_and_state_caches_bytes'] == 6465875328 > 6442450944
    assert last['arena_remaining_before_uncompiled_reader_gamma_runtime'] == 110793344
    envelope = last['all_context_known_array_envelope']
    assert envelope['old_lengths_checked'] == 3947
    assert envelope['max_qk_dyadic_rectangles_per_layer'] == 494
    assert envelope['maximizing_old_lengths'] == [3945]
    assert envelope['descriptor_delta_above_capacity_bytes'] == 96000
    assert envelope['rne_top_additional_rq_form_bytes'] == 23040
    assert envelope['known_phase_max_upper_bytes'] == 6331753600
    assert envelope['arena_remaining_before_uncompiled_reader_gamma_runtime'] == 110697344
    assert not envelope['credit']
    # Verify the nonmonotone corner with the actual layout, not bit counts alone.
    path = Path(__file__).resolve().parents[1]/'manifests/c7-d126-gemma31b-source-metadata-v1.json'
    metadata = json.loads(path.read_text())
    cohorts = plan.gemma_weight_cohorts([t for t in metadata['tensors'] if t['disposition'] == 'private_text'])
    almost = plan.wide_hash_witness_screen(cohorts, 3945)['joint_w_kv_candidate']['known_state_cache_schedule']
    assert almost['known_phase_max_bytes'] == 6331752400 > last['known_phase_max_bytes']
    assert all(value <= envelope['arena_phase_upper_bytes'][phase]
               for phase, value in almost['arena_phases_bytes_before_uncompiled_reader_gamma_runtime'].items())
    assert report['packed_weight_bytes']+report['kv_capacity_i16_bytes']+report['wide_hash_rs_screen'][
        'outer_internal_only_tree_bytes']+6442450944 == 75823096256


def test_accepted_kv_tree_reconstruction_ignores_physical_tail_but_not_prefix_tampering():
    # Two padded planes of different width share the SAME backing row arrays.
    backing = [[[100*plane+10*row+col for col in range(width)] for row in range(5)]
               for plane, width in enumerate((4, 2))]
    def source(length, leak_tail=False):
        padded = 1 << (length-1).bit_length()
        values = []
        for plane in backing:  # decreasing cube volume, aligned offsets
            width = len(plane[0])
            assert len(values) % (width*padded) == 0
            values.extend(x for row in range(padded) for x in (
                plane[row] if row < length or leak_tail and row < min(padded, len(plane)) else [0]*width))
        return values+[0]*((1 << (len(values)-1).bit_length())-len(values))
    def tree(values):
        rows = [plan.small_goldilocks_fft(values[i:i+4]+[0]*12) for i in range(0, len(values), 4)]
        levels = [[('leaf', j, tuple(row[j] for row in rows)) for j in range(16)]]
        while len(levels[-1]) > 1:
            a, h = levels[-1], len(levels)
            levels.append([('node', h, j, a[2*j], a[2*j+1]) for j in range(len(a)//2)])
        return levels
    accepted_source, accepted_tree = source(3), tree(source(3))
    accepted_cache = {(h, j): value for h in range(2, 5) for j, value in enumerate(accepted_tree[h])}
    assert len(accepted_source) == 32 and len(source(5)) == 64
    # A speculative append changes the candidate but never accepted padding.
    candidate_before = tree(source(5))[-1][0]
    backing[0][3][0] += 1
    assert source(3) == accepted_source and tree(source(3))[-1] == accepted_tree[-1]
    assert tree(source(5))[-1][0] != candidate_before
    assert tree(source(3, leak_tail=True))[-1] != accepted_tree[-1]
    for query in range(16):
        start = (query >> 2) << 2
        lower = tree(source(3))[0][start:start+4]
        for h in (1, 2):
            lower = [('node', h, (start >> h)+j, lower[2*j], lower[2*j+1])
                     for j in range(len(lower)//2)]
        assert lower[0] == accepted_cache[2, query >> 2]
    # Reusing that cache after overwriting an accepted prefix is invalid.
    backing[0][0][0] += 1
    assert tree(source(3))[2][0] != accepted_cache[2, 0]


def test_deduplicated_merkle_frontier_matches_all_paths_and_tight_node_bound():
    # Collision-free symbolic nodes test wiring/counts, not A5 hash security.
    for d in range(1, 4):
        domain = 1 << d
        tree = {(0, j): ('leaf', j) for j in range(domain)}
        for h in range(1, d+1):
            for j in range(domain >> h):
                tree[h, j] = ('node', h, j, tree[h-1, 2*j], tree[h-1, 2*j+1])
        for q in range(1, domain+1):
            largest = 0
            for selected in combinations(range(domain), q):
                parents = {(h, j >> h) for j in selected for h in range(1, d+1)}
                leaves = {(0, j) for j in selected}
                frontier = {(h-1, 2*j+c) for h, j in parents for c in (0, 1)}-parents-leaves
                assert len(frontier) == len(parents)+1-q
                largest = max(largest, len(parents))
                wires = {key: tree[key] for key in parents | leaves | frontier}
                def check(values):
                    return (values[d, 0] == tree[d, 0] and all(values[h, j] == (
                        'node', h, j, values[h-1, 2*j], values[h-1, 2*j+1]) for h, j in parents))
                assert check(wires)
                # Every path edge is present through the same node handle.
                for leaf in selected:
                    assert all((h, (leaf >> h)^1) in wires for h in range(d))
                for keys in (parents, leaves, frontier):
                    if keys:
                        bad = dict(wires)
                        bad[min(keys)] = ('tamper',)
                        assert not check(bad)
            assert largest == sum(min(q, domain >> h) for h in range(1, d+1))
    # Bit-reversed prefixes attain every height bound simultaneously.
    for q in (1, 2, 3, 7, 17, 357, 512):
        selected = [int(f'{i:09b}'[::-1], 2) for i in range(q)]
        parents = {(h, j >> h) for j in selected for h in range(1, 10)}
        assert len(parents) == sum(min(q, 512 >> h) for h in range(1, 10))


def test_stacked_sources_share_folds_but_keep_source_roles_and_padding():
    rng, block = random.Random(20260917), 4
    sources = [[rng.randrange(plan.P) for _ in range(n)] for n in (16, 4, 8)]
    screen = plan.wide_hash_joint_opening_screen([len(s) for s in sources], block, 3)
    assert screen['source_order'] == [0, 2, 1]
    assert screen['source_offsets'] == [0, 24, 16]
    n = screen['joint_padded_source_cells']
    joined, form = [0]*n, [0]*n
    points = [[rng.randrange(plan.P) for _ in range(len(s).bit_length()-1)] for s in sources]
    weights = [2, 3, 5]
    claims = [plan.mle(s, r) for s, r in zip(sources, points)]
    for source, r, coefficient, offset in zip(sources, points, weights, screen['source_offsets']):
        joined[offset:offset+len(source)] = source
        form[offset:offset+len(source)] = [coefficient*math.prod(
            x if j >> i & 1 else 1-x for i, x in enumerate(r)) % plan.P for j in range(len(source))]
    assert plan.dot(joined, form) == plan.dot(claims, weights)
    rows = [joined[i:i+block] for i in range(0, n, block)]
    forms = [form[i:i+block] for i in range(0, n, block)]
    coins = [rng.randrange(plan.P) for _ in rows[1:]]
    f, g, sums, _, folded_claim = plan.paired_fold(rows, forms, coins)
    assert sum(sums) % plan.P == plan.dot(claims, weights)
    u, alpha = [7, 11], [1, *coins]
    assert plan.mle(g, u) == sum(coefficient*plan.folded_cube_form(offset, r, alpha, u)
        for coefficient, offset, r in zip(weights, screen['source_offsets'], points)) % plan.P
    assert folded_claim == plan.dot(f, g)
    rho = [math.prod(x if j >> i & 1 else 1-x for i, x in enumerate([13, 17, 19])) % plan.P
           for j in range(len(rows))]
    # The same selected column contains each separately anchored row segment.
    encoded = [plan.small_goldilocks_fft(row+[0]*(3*block)) for row in rows]
    for coefficients in (alpha, rho):
        folded = [sum(c*row[i] for c, row in zip(coefficients, rows)) % plan.P for i in range(block)]
        target = plan.small_goldilocks_fft(folded+[0]*(3*block))
        assert all(target[j] == sum(c*row[j] for c, row in zip(coefficients, encoded)) % plan.P
                   for j in range(4*block))
    # Dropping the old segment or swapping roles is not an opening of the tuple.
    anchors = [tuple(plan.small_goldilocks_fft(s[i:i+block]+[0]*(3*block)))
               for s in sources for i in range(0, len(s), block)]
    assert len(anchors) == 7 and len(set(anchors)) == 7
    old_offset = screen['source_offsets'][1]
    bad = joined.copy()
    bad[old_offset] = (bad[old_offset]+1) % plan.P
    assert plan.dot(bad, form) != plan.dot(joined, form)
    assert plan.small_goldilocks_fft(bad[old_offset:old_offset+block]+[0]*(3*block)) != list(anchors[4])
    assert joined[28:] == [0]*4  # public virtual rows, not unconstrained input


def test_output_tiled_encoder_and_pruned_tree_keep_the_same_positions():
    # Symbolic node tuples, NOT a cryptographic hash. No field security/KAT.
    block, rows, tile = 8, 13, 8
    domain, group = 4*block, 10
    source = [[17*i+3*j for j in range(block)] for i in range(rows)]
    native = [plan.small_goldilocks_fft(row+[0]*(3*block)) for row in source]

    def leaf(j, column):
        digest = ('zero',)*8
        for start in range(0, rows, group):
            words = column[start:start+group]
            frame = (*digest, *words, *([0]*(group-len(words))),
                     start//group, len(words), 0x43373501, j, rows, block, *([0]*8))
            assert len(frame) == 32 and frame[-8:] == (0,)*8
            digest = tuple(('output', lane, frame) for lane in range(8))
        return digest

    def parent(left, right, height, index):
        return (height, index, left, right)

    leaves = [leaf(j, [row[j] for row in native]) for j in range(domain)]
    full, level = [leaves], leaves
    while len(level) > 1:
        level = [parent(level[2*j], level[2*j+1], len(full), j) for j in range(len(level)//2)]
        full.append(level)
    for drop in range(1, domain.bit_length()):
        # Tiles must include whole retained-bottom subtrees.
        local_tile = max(tile, 1 << drop)
        cache, visits = {}, 0
        for first in range(0, domain, local_tile):
            columns = [[] for _ in range(local_tile)]
            for row in source:
                encoded = plan.small_goldilocks_fft(row+[0]*(3*block))
                for j in range(local_tile):
                    columns[j].append(encoded[first+j])
            visits += 1  # one full source traversal, not rows separate visits
            current = [leaf(first+j, column) for j, column in enumerate(columns)]
            for height in range(1, local_tile.bit_length()):
                current = [parent(current[2*j], current[2*j+1], height, (first >> height)+j)
                           for j in range(len(current)//2)]
                if height >= drop:
                    cache.update({(height, (first >> height)+j): value for j, value in enumerate(current)})
        height = local_tile.bit_length()-1
        current = [cache[height, j] for j in range(domain//local_tile)]
        while len(current) > 1:
            height += 1
            current = [parent(current[2*j], current[2*j+1], height, j) for j in range(len(current)//2)]
            cache.update({(height, j): value for j, value in enumerate(current)})
        assert visits == domain//local_tile
        assert len(cache) == (2*domain >> drop)-1
        assert all(value == full[h][j] for (h, j), value in cache.items())
        for j in range(domain):
            first = (j >> drop) << drop
            selected = [leaf(k, [row[k] for row in native]) for k in range(first, first+(1 << drop))]
            for h in range(1, drop+1):
                selected = [parent(selected[2*k], selected[2*k+1], h, (first >> h)+k)
                            for k in range(len(selected)//2)]
            assert selected[0] == cache[drop, j >> drop]
    # Index/domain tags are part of the relation, not free MAC inputs.
    assert leaf(0, [row[0] for row in native]) != leaf(1, [row[0] for row in native])


def test_ibcs_template_cube_root_loss_excludes_only_the_256bit_bound():
    first, large, wider = plan.report()['ibcs_rewinding_screens']
    for s in (first, large, wider):
        assert not s['credit'] and s['complete_security_bits'] is None
        assert not s['full_compiler_constants_relation_hash_assumptions_and_fs_instantiated']
        assert s['sampler_runs_at_selected_tolerance'] == 1 << 126
    assert first['template_minimum_integer_output_bits_to_beat_tolerance'] == 355
    assert large['template_minimum_integer_output_bits_to_beat_tolerance'] == 483
    assert first['optimistic_rewinder_circuit_size_bits'] == 126
    assert large['optimistic_rewinder_circuit_size_bits'] == 190
    assert not first['best_template_interactive_error_below_2_neg_78']
    assert not large['best_template_interactive_error_below_2_neg_78']
    assert wider['best_template_interactive_error_below_2_neg_78']  # NOT protocol credit
    # Exact rational certificate of the GLOBAL minimum, no floating-point gate.
    for k in (Fraction(1,1 << 204),Fraction(1,1 << 76),Fraction(1,7),Fraction(3)):
        for e in (Fraction(1,1 << 100),Fraction(1,7),Fraction(1,2),Fraction(2)):
            f = e+k/e**2
            assert (4*f**3-27*k)*e**6 == (e**3-2*k)**2*(4*e**3+k) >= 0
    k = Fraction(1,1 << 204)  # L=2^26, unit t, output space 2^256
    assert 27*k > 4*Fraction(1,1 << 78)**3
    # A 512-bit ENVELOPE could clear this screen, not the missing hash/FS proofs.
    k = Fraction(1,1 << 332)  # L=2^26, t=2^64
    e = Fraction(1,1 << 101)
    assert e+k/e**2 < Fraction(1,1 << 100)
    # Expected work cannot replace strict work inside a birthday square.
    # With probability 1/16, make 16 queries to a random map into 256 values.
    probability_run = Fraction(1,16)
    collision = 1-math.prod(Fraction(256-j,256) for j in range(16))
    mean_queries = probability_run*16
    assert mean_queries == 1
    assert probability_run*collision > mean_queries**2/256
    for args in ((0,0),(256,-1),(256,True),(256,0,0)):
        with pytest.raises(ValueError):
            plan.ibcs_rewinding_screen(*args)


def test_private_projection_counts_include_base_commitment_but_not_direct_message_sampling():
    cases = ((1 << 35, 1 << 24, 71438465, 6, 44, 16384, 1102836761344, 30996),
             (1 << 33, 1 << 23, 35719169, 5, 38, 12288, 276540436480, 18612),
             (1 << 34, 1 << 23, 35719169, 5, 38, 16384, 551418343424, 30912))
    for n, block, length, roots, direct, symbol_bytes, dense, words in cases:
        s = plan.private_projection_compilation_screen(n, block, 357)
        assert s['total_committed_symbols'] == length
        assert s['commitment_boundaries_requiring_sampling'] == roots
        assert s['maximum_committed_symbols'] == 4*block
        assert s['maximum_symbol_bytes'] == symbol_bytes
        assert s['dense_extracted_oracles_bytes_not_honest_prover_storage'] == dense
        assert s['direct_sumcheck_messages'] == direct
        assert s['direct_sumcheck_extension_coefficients'] == 3*direct
        assert s['direct_paired_extension_values'] == 2*(n//block)-1
        assert s['direct_final_evaluation_extension_values'] == 1
        assert s['direct_extension_values'] == 2*(n//block)+3*direct
        assert s['direct_plaintext_bytes_in_projection_only'] == 24*(2*(n//block)+3*direct)
        wide = plan.wide_hash_rs_screen(n, block, 357)
        assert s['clear_vc_hash_calls_per_sample_by_boundary'] == [
            l['hash_calls']+int(i == 0) for i, l in enumerate(wide['levels'])]+[
                (3*wide['terminal_private_extension_cells']+9)//10]
        assert sum(s['clear_vc_hash_calls_per_sample_by_boundary']) == wide['private_hash_calls_including_anchor_and_recursion']
        assert s['public_challenge_u64_upper_before_private_hash'] == words
        assert s['committed_oracles'][-1]['symbols'] == s['committed_oracles'][-1]['queries'] == 1
        assert s['sampler_filters_by_direct_clear_vc_check_not_wrapper_acceptance']
        assert s['rewind_clones_entire_dealer_and_prover_state']
        assert not s['main_execution_wrapper_error_multiplied_by_rewinds']
        assert not s['changes_real_record_order_or_correlation_reuse_rules']
        assert not s['full_root_oracle_fs_and_model_relation_instantiated']
        assert not s['credit'] and s['complete_security_bits'] is None
        assert s['static_source_lifetime']['total_symbol_slots'] == length
    life = plan.private_projection_compilation_screen(1 << 35, 1 << 24, 357, 1 << 20)['static_source_lifetime']
    assert life['source_symbols_sampled_at_one_boundary'] == 1 << 26
    assert life['recursive_symbol_slots'] == 4329601*(1 << 20)
    assert life['recursive_sampling_boundaries'] == 5*(1 << 20)
    assert life['total_symbol_slots'] == (1 << 26)+4329601*(1 << 20)
    assert life['maximum_attempts_in_each_source_continuation'] == life['attempts'] == 1 << 20
    for args in ((plan.P, 1 << 24, 357), (1 << 35, 1 << 25, 357), (64, 8, 9),
                 (64, 8, 1, 0), (64, 8, 1, (1 << 20)+1), (64, 8, 1, True)):
        with pytest.raises(ValueError):
            plan.private_projection_compilation_screen(*args)


def test_ideal_projection_clones_masks_and_filters_clear_openings_not_wrapper_acceptance():
    # Tiny ideal-dealer model, not a test/assumption that a real MAC is forgeable.
    p, delta, mask, tag = 5, 2, 1, 4
    committed = ((mask+1) % p, 3)  # prefix may depend on a FUTURE preprocessed mask
    key = (tag-delta*mask) % p
    snapshot = (committed, mask, tag, key, 0)

    def resume(state, coin):
        values, u, mu, ku, consumed = state
        assert consumed == 0  # one slot in each individual branch
        if coin == 2:
            return None, (*state[:4], 1)  # abort remains a sample, not resampled away
        value = (values[coin]+int(coin == 1)) % p
        correction = (value-u) % p
        decoded = (correction+u) % p
        assert mu == (ku-delta*correction+delta*decoded) % p
        return (coin, correction, decoded, decoded == values[coin]), (*state[:4], 1)

    records = [resume(snapshot, c)[0] for c in range(3)]
    assert records[0][-1] and not records[1][-1] and records[2] is None
    assert snapshot == (committed, mask, tag, key, 0)  # forks did not advance the main branch
    with pytest.raises(AssertionError):
        resume(resume(snapshot, 0)[1], 0)  # NOT a legal runtime retry with the same slot
    # Rerandomizing an unconsumed dealer mask while retaining the prover state is wrong.
    q, correction, decoded, valid = records[1]
    assert not valid and decoded != committed[q]
    assert (correction+0) % p == committed[q]  # wrong mask would falsely validate this answer
    assert sum((correction+u) % p == decoded for u in range(p)) == 1
    # A REAL new attempt gives the prover the fresh mask too, preserving the same value.
    assert all(((committed[0]-u) % p+u) % p == committed[0] for u in range(p))

    bad_main = missing = bad_or_missing = 0
    for main, first, second in product(range(3), repeat=3):
        record = records[main]
        # Deliberately give the toy wrapper an error on coin 1; only MAIN error is charged.
        wrapper_accepts = record is not None
        sampled = [records[c] for c in (first, second)]
        known = {r[0]: r[2] for r in sampled if r is not None and r[3]}
        main_error = wrapper_accepts and not record[3]
        miss = wrapper_accepts and record[3] and record[0] not in known
        bad_main += main_error
        missing += miss
        bad_or_missing += main_error or miss
        assert 1 not in known  # invalid clear openings NEVER enter the extracted oracle
    assert Fraction(bad_main, 27) == Fraction(1, 3)
    assert Fraction(missing, 27) == Fraction(1, 3)*Fraction(2, 3)**2
    assert Fraction(bad_or_missing, 27) == Fraction(13, 27)
    # No global conditioning on valid MAC/checker executions across all sampled branches.
    assert bad_or_missing == bad_main+missing


def test_salted_root_vc_disagreement_lifts_to_a_concrete_hash_collision():
    # Weak six-word toy hash so every collision-lifting branch is reachable.
    # This tests the REDUCTION, not collision resistance or A5's numerical security.
    p = 7

    def opening(column, sibling, salt):
        trace = []

        def call(frame):
            output = sum((i+1)*x for i, x in enumerate(frame)) % p
            trace.append((frame, output))
            return output

        prev = 0
        for group, value in enumerate(column):
            prev = call((1, 0, group, prev, value, 0))
        root = call((2, 0, 0, prev, sibling, 0))
        anchor = call((3, root, salt, 4, 0, 0))
        return column, sibling, salt, root, anchor, trace

    first = opening((0, 0), 0, 0)
    variants = [opening(column, sibling, salt)
                for column in product(range(p), repeat=2)
                for sibling, salt in product(range(p), repeat=2)]
    # Same commitment/position, different column; divergences in anchor, node or leaf chain.
    eligible = [v for v in variants if v[0] != first[0] and v[4] == first[4]]
    selected = [next(v for v in eligible if v[3] != first[3]),
                next(v for v in eligible if v[2:4] == first[2:4] and v[1] != first[1]),
                next(v for v in eligible if v[1:4] == first[1:4])]
    for second, expected_tag in zip(selected, (3, 2, 1)):
        assert first[4] == second[4] and first[0] != second[0]
        for (left, a), (right, b) in zip(reversed(first[-1]), reversed(second[-1])):
            assert a == b  # equality propagates backwards while the complete frame agrees
            if left != right:
                assert left[0] == right[0] == expected_tag
                assert sum((i+1)*x for i, x in enumerate(left)) % p == sum((i+1)*x for i, x in enumerate(right)) % p
                break
        else:
            pytest.fail('different column with valid same-anchor openings must expose a hash collision')
    # Malformed openings are not sampler evidence: altered salt fails the public anchor.
    assert opening(first[0], first[1], 1)[4] != first[4]


def test_ibcs_missing_valid_positions_match_exact_resampling_probability():
    # Four equally likely continuations: invalid, {0}, {1}, {0,1}.
    # Invalid openings contribute NO position, even if they name one.
    outcomes = (set(), {0}, {1}, {0,1})
    for n in range(1,5):
        misses, single = 0, 0
        for draws in product(range(4),repeat=n+1):
            seen = set().union(*(outcomes[i] for i in draws[:-1]))
            current = outcomes[draws[-1]]
            misses += bool(current-seen)
            single += 0 in current and 0 not in seen
        exact_single = Fraction(single,4**(n+1))
        assert exact_single == Fraction(1,2)*Fraction(1,2)**n
        assert Fraction(misses,4**(n+1)) <= 2*exact_single <= Fraction(2,n)
    # The union bound does not silently condition on future acceptance.
    for n in range(1,12):
        for j in range(8):
            delta = Fraction(j,7)
            assert delta*(1-delta)**n <= Fraction(1,n)


def test_static_source_sampler_covers_adaptive_lifetimes_and_late_aborts():
    # Two attempts, independent F3 masks, request 2 depends on public correction 1.
    # An exact toy VC checks against this fixed source; no hash/MAC security claim.
    source, outcomes, first_only = (2, 0, 1), [], []
    for coins in product(range(2), repeat=2):
        for masks in product(range(3), repeat=2):
            records, previous_correction = [], 0
            for slot in range(2):
                query = coins[0] if slot == 0 else (coins[1]+previous_correction) % 3
                value = source[query]
                if slot == 1 and coins[1] == 1 and masks[1] == 2:
                    value = (value+1) % 3  # invalid complete opening contributes nothing
                correction = (value-masks[slot]) % 3
                decoded = (correction+masks[slot]) % 3
                valid = decoded == source[query]
                late_abort = slot == 0 and coins[0] == 0
                records.append((slot, query, decoded, valid, late_abort))
                previous_correction = correction
            assert [r[0] for r in records] == [0, 1]  # abort does not refund a slot
            # Already received valid openings survive a LATER abort in that attempt.
            known = {r[1]: r[2] for r in records if r[3]}
            assert all(source[j] == value for j, value in known.items())
            assert all(r[1] in known for r in records if r[3] and r[4])
            outcomes.append(set(known))
            first_only.append({r[1] for r in records[:1] if r[3]})
    assert len(outcomes) == 36 and all(2 not in seen for seen in first_only)
    assert any(2 in seen for seen in outcomes)  # first-attempt-only sampling misses this position
    for samples in (1, 2):
        missing, missing_any = [0]*3, 0
        for draws in product(range(len(outcomes)), repeat=samples+1):
            seen = set().union(*(outcomes[i] for i in draws[:-1]))
            absent = outcomes[draws[-1]]-seen
            missing_any += bool(absent)
            for j in absent:
                missing[j] += 1
        denominator = len(outcomes)**(samples+1)
        for j in range(3):
            delta = Fraction(sum(j in seen for seen in outcomes), len(outcomes))
            assert Fraction(missing[j], denominator) == delta*(1-delta)**samples
        assert Fraction(missing_any, denominator) <= sum(Fraction(x, denominator) for x in missing)
        assert sum(Fraction(x, denominator) for x in missing) <= Fraction(3, samples)


def test_decoded_static_source_uses_joint_column_distance_not_independent_row_balls():
    # Degree<2 RS on four distinct F7 points: distance 3, joint radius <3/2.
    p, domain = 7, range(4)
    code = {c: tuple((c[0]+c[1]*x) % p for x in domain)
            for c in product(range(p), repeat=2)}
    assert min(sum(a != b for a, b in zip(x, y))
               for x, y in product(code.values(), repeat=2) if x != y) == 3

    def decode(rows):
        candidates = [[c for c, word in code.items()
                       if 2*sum(a != b for a, b in zip(row, word)) < 3] for row in rows]
        assert all(len(c) <= 1 for c in candidates)
        if any(not c for c in candidates):
            return None
        coefficients = tuple(c[0] for c in candidates)
        bad_columns = sum(any(row[j] != code[c][j] for row, c in zip(rows, coefficients)) for j in domain)
        return coefficients if 2*bad_columns < 3 else None

    weights = ((1, 2), (3, 1))
    rows = [list(code[c]) for c in weights]
    assert decode(rows) == weights
    rows[0][0] = (rows[0][0]+1) % p
    assert decode(rows) == weights  # malformed oracle can still have the SAME unique decode
    rows[1][1] = (rows[1][1]+1) % p
    assert all(sum(a != b for a, b in zip(row, code[c])) == 1 for row, c in zip(rows, weights))
    assert decode(rows) is None  # row-wise decoding alone would incorrectly accept


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
    assert s["fixed_oracle_interactive_error_numerator"]+s["weight_batch_interactive_error_numerator"] == 40364
    assert s["compact_operand_vectors_bytes"] == 300_646_400
    assert s["known_b_tree_vectors_scratch_and_messages_union_bytes"] == 5_714_441_824
    assert s["private_product_equations"] == s["w_free_input_evaluation_obligations"] == 772
    assert s["cut_output_evaluation_obligations"] == 773
    assert s["w_dependent_subsystem_source_reads_with_A4"] == 3
    assert s["complete_prover_weight_reads"] is None
    assert not s["credit"] and not s["non_w_input_links_or_range_proofs_compiled"]


def test_p0_shared_source_glue_needs_prebatch_weights_and_same_mac_wires():
    p = 7
    for count in (1, 2, 3):
        for errors in product(range(p), repeat=count):
            if any(errors):
                roots = sum(sum(pow(coin, j+1, p)*e for j, e in enumerate(errors)) % p == 0
                            for coin in range(p))
                assert roots <= count  # includes coin=0; do not silently sample nonzero coins

    weights, forms = (2, 3), ((1, 0), (0, 1), (1, 1))
    claims = tuple(sum(a*b for a, b in zip(weights, form)) % p for form in forms)
    tags = (1, 3, 5)
    for delta in range(p):
        keys = tuple((tag-delta*value) % p for tag, value in zip(tags, claims))
        for coin in range(p):
            coefficients = tuple(pow(coin, j+1, p) for j in range(3))
            combined = tuple(sum(a*form[k] for a, form in zip(coefficients, forms)) % p for k in range(2))
            value = sum(a*x for a, x in zip(coefficients, claims)) % p
            tag = sum(a*m for a, m in zip(coefficients, tags)) % p
            key = sum(a*k for a, k in zip(coefficients, keys)) % p
            assert value == sum(a*b for a, b in zip(weights, combined)) % p
            assert tag == (key+delta*value) % p  # linear alias, no new authentication of S

    # If W is chosen after lambda, even perfect aggregate openings cannot bind old claims.
    for coin in range(p):
        late_weights = ((1+coin) % p, 0)
        assert late_weights != (1, 1)  # at least one of the two unit-form claims is false
        assert (coin+coin*coin) % p == (coin*late_weights[0]+coin*coin*late_weights[1]) % p

    # Both MACs can be valid while a detached weight wire accepts a false product relation.
    for delta in range(p):
        original, detached = (2, 4), (1, 3)  # (plaintext, tag)
        for value, tag in (original, detached):
            key = (tag-delta*value) % p
            assert tag == (key+delta*value) % p
        source_weight, input_value, claimed_output = 1, 1, 2
        assert claimed_output == input_value*original[0]  # P0 product check passes
        assert detached[0] == source_weight  # detached PCS check passes too
        assert claimed_output != input_value*source_weight
        assert original[0] != detached[0]  # same-wire rule (or a checked equality) is necessary


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


def test_input_routes_preserve_stages_heads_and_decision_selection():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           "manifests/c7-d126-gemma31b-source-metadata-v1.json").read_bytes())
    tensors = [t for t in metadata["tensors"] if t["disposition"] == "private_text"]
    cohorts = plan.gemma_weight_cohorts(tensors)
    routes = plan.gemma_input_routes(cohorts)
    by_op = {(c["layer"], c["operation"]): r for c, r in zip(cohorts[1:], routes)}
    assert {r["cohort_ordinal"] for r in routes} == set(range(1, 773))
    assert all(r["same_i16_stage"] for r in routes)
    qnorm = by_op[5, "q_norm"]
    assert qnorm["source_shape"] == (150, 32*512)
    assert (qnorm["column_point_bits"], qnorm["row_point_bits"]) == (14, 8)
    assert qnorm["source_producer"] == {"layer": 5, "operation": "q_proj"}
    final = by_op[None, "final_rms"]
    assert (final["source_shape"], final["selected_rows"], final["row_offset"]) == ((150, 5376), 149, 0)
    head = by_op[None, "lm_head"]
    assert head["logical_producer"] == {"layer": None, "operation": "last_row_select"}
    assert head["source_producer"] == {"layer": None, "operation": "final_rms"}
    assert (head["source_shape"], head["selected_rows"], head["row_offset"]) == ((149, 5376), 50, 99)
    small = plan.gemma_input_routes(plan.gemma_weight_cohorts(tensors, 1, 1))[-1]
    assert (small["selected_rows"], small["row_offset"], small["row_point_bits"]) == (1, 0, 0)
    qn = next(i for i, c in enumerate(cohorts) if c["operation"] == "q_norm")
    for change in ({"columns": 255}, {"input_stage": "raw_accumulator"}):
        altered = [dict(c) for c in cohorts]
        altered[qn].update(change)
        with pytest.raises(ValueError):
            plan.gemma_input_routes(altered)
    s = plan.input_link_screen(cohorts)
    assert s["input_route_manifest_sha256"] == "e6cf76a59b2fb69540a8de2a2086a9051680385517ecca093d222065d79f1c1b"
    assert s["distinct_producer_point_obligations"] == 602
    assert s["producer_operations"]["final_rms"] == 1
    assert "last_row_select" not in s["producer_operations"]
    assert s["producer_seed_fanout_histogram"] == {1: 482, 2: 70, 3: 50}
    assert s["direct_point_aliases"] == 480 and s["seed_form_sumchecks"] == 122
    assert s["sumcheck_rounds"] == 2562 and s["extension_corrections"] == 7808
    assert s["message_bytes_before_framing_and_shared_closures"] == 187392
    assert s["extension_challenges"] == 2682
    assert s["fixed_replay_interactive_error_numerator"] == 5294
    assert s["single_reducer_two_extension_vectors_bytes"] == 100_663_296
    assert s["additional_weight_reads"] == s["additional_private_product_equations"] == 0
    assert s["full_gamma_record_or_workspace_counts"] is None
    assert not s["credit"] and not s["producer_values_proved_as_replay"]


def test_gamma_barrier_routes_the_pinned_dag_with_rne_last_and_no_late_edges():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           "manifests/c7-d126-gemma31b-source-metadata-v1.json").read_bytes())
    tensors = [t for t in metadata["tensors"] if t["disposition"] == "private_text"]
    cohorts = plan.gemma_weight_cohorts(tensors)
    g = plan.gamma_barrier_plan(cohorts)
    records, order, s = g["cohorts"], g["reverse_order"], g["summary"]
    by_op = {(r["layer"], r["operation"]): r for r in records}
    assert (s["pinned_tensor_nodes"], s["tensor_edges"]) == (79963, 101322)
    assert s["delegated_tensor_edges"] == {
        "P0": 21011, "T1": 12240, "K1": 9120, "public_decisions": 50}
    assert (s["cohorts"], s["retained_cohort_edges"]) == (1568, 1155)
    assert (s["ordinary_kernel_cohorts"], s["final_rne_cohorts"], s["source_boundary_cohorts"]) == (975, 531, 62)
    assert s["seed_cohorts_by_role"] == {
        "P0": 602, "T1": 120, "K1": 120, "public_decisions": 1, "validity": 1506}
    assert s["plan_sha256"] == "8f34456c6e3a715ed1fa4e80640eefaed80d18fcf909a0d86907f4c8fd231a0f"
    assert not s["credit"] and s["complete_gamma_forms_and_workspace"] is None
    assert sum(r["executions"] for r in records) == 79963
    assert sorted(order) == list(range(1568))
    assert all(records[i]["kind"] == "rne48" for i in order[975:1506])
    assert all(not records[i]["dependencies"] for i in order[975:])

    def late_edges(sequence):
        closed, late = set(), []
        for i in sequence:
            # Any reducer may emit new authenticated claims on each input.
            late.extend((i, d) for d in records[i]["dependencies"] if d in closed)
            closed.add(i)
        return late

    assert not late_edges(order)
    q = by_op[5, "q_proj"]["ordinal"]
    assert late_edges([q] + [i for i in order if i != q])  # closing P0 seeds alone is premature
    for layer in range(60):
        for norm, operand in (("q_norm", "q_proj"), ("k_norm", "k_proj"),
                              ("post_attention_rms", "o_proj"), ("post_ffw_rms", "down_proj")):
            r = by_op[layer, norm]
            assert r["kind"] == "weighted_rms" and r["byte_source"] == "B"
            assert r["dependencies"] == [by_op[layer, operand]["ordinal"]]
        v = by_op[layer, "v_source"]
        assert v["dependencies"] == ([by_op[layer, "k_proj"]["ordinal"]] if layer % 6 == 5 else [])
        for role, ops in (("K1", ("k_rope", "v_norm")), ("T1", ("q_rope", "softmax"))):
            assert all(role in by_op[layer, op]["seeds"] for op in ops)
    assert by_op[None, "final_rms"]["query_rows"] == 149
    assert by_op[59, "post_ffw_rms"]["query_rows"] == 150
    assert by_op[None, "argmax"]["executions"] == 50
    assert by_op[None, "token_input"]["executions"] == 51
    for altered in (cohorts[:-1], cohorts + [cohorts[0]],
                    [{**c, "kind": "matrix"} if c["kind"] == "norm" else c for c in cohorts],
                    plan.gemma_weight_cohorts(tensors, 1, 1)):
        with pytest.raises(ValueError):
            plan.gamma_barrier_plan(altered)


def test_gamma_validity_includes_dead_outputs_and_rms_requires_original_input():
    logical = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                                "scripts/c7_d126_gemma_qspec_dag.py"))
    manifest = plan.pinned_gemma_manifest()
    executions = logical["_expand_schedule"](manifest["workload_schedule"])
    nodes = logical["expand_dag"](manifest, executions)
    # Even ancestors of public decisions, all KV states and P0/T1 operands
    # miss an executed norm at the end of terminal absorption.
    needed = {n.id for n in nodes if n.operation in {"argmax", "kv_cache_append"}}
    needed.update(d for n in nodes if n.weight_terminal is not None
                  or n.operation in {"qk_matmul", "pv_matmul"} for d in n.dependencies)
    todo = list(needed)
    while todo:
        for d in nodes[todo.pop()].dependencies:
            if d not in needed:
                needed.add(d)
                todo.append(d)
    dead = next(n for n in nodes if (n.execution, n.layer, n.operation) == (50, 59, "post_ffw_rms"))
    assert dead.id not in needed
    # Equal demanded outputs do not imply equal whole-program validity.
    good, bad = [7, 3], [7, 32768]
    assert plan.rne_i48_to_i16(good[0], 0) == plan.rne_i48_to_i16(bad[0], 0)
    assert [plan.rne_i48_to_i16(x, 0) for x in good] == good
    with pytest.raises(ValueError):
        [plan.rne_i48_to_i16(x, 0) for x in bad]
    # Same fixed W and identical B products, but different RMS statistics.
    w, x, other_x = [1, 0], [2, 1], [2, 2]
    assert [a*b for a, b in zip(w, x)] == [a*b for a, b in zip(w, other_x)] == [2, 0]
    eps = Fraction(1, 1_000_000)
    squared = [Fraction(4)/(eps + Fraction(sum(a*a for a in values), 2))
               for values in (x, other_x)]
    assert squared[0] != squared[1]


def test_shifted_eq_digit_dp_matches_every_small_interval():
    def basis(point, index):
        return math.prod(r if (index >> i) & 1 else 1-r for i, r in enumerate(point)) % plan.P
    for source_bits in range(5):
        for input_bits in range(source_bits+1):
            for tape in ([2, 3, 5, 7], [0, 1, -1, 17]):
                ip, sp = tape[:input_bits], list(reversed(tape))[:source_bits]
                for count in range((1 << input_bits)+1):
                    for offset in range((1 << source_bits)-count+1):
                        expected = sum(basis(ip, d)*basis(sp, offset+d) for d in range(count)) % plan.P
                        assert plan.shifted_eq_form(ip, sp, offset, count) == expected
    for args in (([], [], 0, 2), ([2], [], 0, 1), ([2], [3], 2, 1),
                 ([2], [3], -1, 1), ([2], [3], 0, True)):
        with pytest.raises(ValueError):
            plan.shifted_eq_form(*args)


def test_input_selector_forms_bind_prefix_gather_and_head_reshape():
    # Each table is a canonical producer, with independently padded axes.
    cases = [
        # Final RMS must omit the still-live terminal-absorb row.
        ((4, 3), 3, 0, [2, 3, 5, 7]),
        # Two decision rows select producer tokens 2 and 3, not 0 and 1.
        ((4, 3), 2, 2, [2, 3, 5]),
        # q_norm: (3 tokens * 2 heads, 4 lanes) -> (3 tokens, 8 columns).
        ((3, 8), 3, 0, [2, 3, 5, 7, 11]),
    ]
    for (rows, width), count, offset, ip in cases:
        cb, rb = (width-1).bit_length(), (count-1).bit_length()
        stride, row_domain = 1 << cb, 1 << (rows-1).bit_length()
        table = [[(t+1)*(k*k+3)-2 for k in range(width)]+[0]*(stride-width) for t in range(rows)]
        table += [[0]*stride for _ in range(row_domain-rows)]
        selected = table[offset:offset+count]+[[0]*stride for _ in range((1 << rb)-count)]
        route = {"source_shape": (rows, width), "selected_rows": count, "row_offset": offset,
                 "column_point_bits": cb, "row_point_bits": rb}
        n = cb+(rows-1).bit_length()
        weights = [plan.input_route_form(route, ip, [(index >> i) & 1 for i in range(n)])
                   for index in range(1 << n)]
        claim = plan.mle(sum(selected, []), ip)
        assert sum(a*x for a, x in zip(weights, sum(table, []))) % plan.P == claim
        probe = [13, 17, 19, 23, 29][:n]
        assert plan.input_route_form(route, ip, probe) == plan.mle(weights, probe)
        if count < rows and offset == 0:
            assert claim != plan.mle(sum(table, []), ip)  # naive same-point alias is false
        if offset:
            assert claim != plan.mle(sum(table[:count], []), ip)
        if width == 8:
            heads = [table[t][4*h:4*h+4] for t in range(rows) for h in range(2)]
            heads += [[0]*4 for _ in range(8-len(heads))]
            assert claim == plan.mle(sum(heads, []), ip)  # no bit permutation
        with pytest.raises(ValueError):
            plan.input_route_form(route, ip+[0], probe)


def test_seed_fanout_reduction_transfers_to_same_producer_endpoint():
    values = [2, 7, -3, 11, 5, 13, 17, 19]
    points, beta, coins = [[2, 3, 5], [7, 11, 13], [17, 19, 23]], 29, [31, 37, 41]
    claims = [plan.mle(values, r) for r in points]
    def eq(a, b):
        return math.prod((1-u)*(1-v)+u*v for u, v in zip(a, b)) % plan.P
    def form(s):
        return sum(pow(beta, j, plan.P)*eq(r, s) for j, r in enumerate(points)) % plan.P
    def partial(prefix):
        return sum(form(prefix+list(t))*plan.mle(values, prefix+list(t))
                   for t in product((0, 1), repeat=3-len(prefix))) % plan.P
    claim = sum(pow(beta, j, plan.P)*v for j, v in enumerate(claims)) % plan.P
    assert claim == partial([])
    for i, coin in enumerate(coins):
        prefix = coins[:i]
        assert claim == (partial(prefix+[0])+partial(prefix+[1])) % plan.P
        samples = [partial(prefix+[t]) for t in range(4)]
        for _ in range(3):
            samples = [(b-a) % plan.P for a, b in zip(samples, samples[1:])]
        assert samples == [0]  # degree two, not dependent on fanout
        claim = partial(prefix+[coin])
    endpoint = plan.mle(values, coins)
    assert claim == form(coins)*endpoint % plan.P
    assert claim != form(coins)*(endpoint+1) % plan.P
    # With fixed claims, a nonzero 3-term error has at most two roots in F7.
    for errors in product(range(7), repeat=3):
        if any(errors):
            assert sum(sum(e*pow(b, j, 7) for j, e in enumerate(errors)) % 7 == 0
                       for b in range(7)) <= 2
    # Knowing beta before choosing claims would permit deterministic cancellation.
    late_errors = [1, -pow(beta, -1, plan.P), 0]
    assert sum(pow(beta, j, plan.P)*e for j, e in enumerate(late_errors)) % plan.P == 0


def test_kv_views_are_logical_rectangles_with_complete_terminal_absorption():
    for old in (0, 3900, 3946):
        views = plan.kv_view_schedule(old)
        assert len(views) == 51 and sum(v['emits_decision'] for v in views) == 50
        appended = [t for v in views for t in range(v['first_new_row'], v['first_new_row']+v['query_rows'])]
        assert appended == list(range(150))
        assert views[0]['kv_view_rows'] == old+100
        assert views[-1] == {'execution': 50, 'first_new_row': 149, 'query_rows': 1,
                             'kv_view_rows': old+150, 'emits_decision': False}
        assert all(v['kv_view_rows'] == old+v['first_new_row']+v['query_rows'] for v in views)
    # Prefill's rectangle includes future prompt keys; causal/local masks are separate.
    assert plan.kv_view_schedule(2, 3, 2)[0]['kv_view_rows'] == 5 > 2+1
    assert plan.kv_view_schedule(4094, 1, 1)[-1]['kv_view_rows'] == 4096
    for args in ((3947, 100, 50), (-1, 1, 1), (0, 0, 1), (0, 1, 0), (True, 1, 1)):
        with pytest.raises(ValueError):
            plan.kv_view_schedule(*args)


def test_kv_append_form_and_old_prefix_alias_match_dense_concatenation():
    def padded(values, width):
        return values+[0]*(width*(1 << (len(values)//width-1).bit_length())-len(values))
    for old in range(6):
        for count in range(1, 6):
            width, rows = 2, old+count
            before, tail = list(range(11, 11+2*old)), list(range(37, 37+2*count))
            new = padded(before+tail, width)
            nb, tb = 1+(rows-1).bit_length(), 1+(count-1).bit_length()
            for tape in ([2, 3, 5, 7, 11], [0, 1, 0, 1, 0], [1, 0, 1, 0, 1]):
                r, s = tape[:nb], list(reversed(tape))[:tb]
                weights = [plan.kv_append_form(r, [(i >> j) & 1 for j in range(tb)], width, old, count)
                           for i in range(1 << tb)]
                append = plan.dot(weights, padded(tail, width))
                assert plan.kv_append_form(r, s, width, old, count) == plan.mle(weights, s)
                prior = 0
                if old:
                    ob = 1+(old-1).bit_length()
                    prior = math.prod(1-x for x in r[ob:])*plan.mle(padded(before, width), r[:ob]) % plan.P
                assert plan.mle(new, r) == (prior+append) % plan.P
    for args in (([2], [], 3, 0, 1), ([2], [], 2, 0, 0), ([2], [], 2, 4096, 1),
                 ([2], [], 2, True, 1), ([2], [], 2, 0, 1)):
        with pytest.raises(ValueError):
            plan.kv_append_form(*args)


def test_kv_transition_quadratic_sumcheck_and_view_tampering():
    # O=3,T=3, width=2. Old padding overlaps the physical new tail: read it as ZERO.
    width, old, count = 2, 3, 3
    before, tail = [11, 13, 17, 19, 23, 29], [31, 37, 41, 43, 47, 53]
    new, tail_pad, old_pad = before+tail+[0]*4, tail+[0]*2, before+[0]*2
    r, coins = [2, 3, 5, 7], [11, 13, 17]
    previous = (1-r[3])*plan.mle(old_pad, r[:3]) % plan.P
    assert previous != (1-r[3])*plan.mle(new[:8], r[:3]) % plan.P
    def form(point):
        return plan.kv_append_form(r, point, width, old, count)
    def partial(prefix):
        return sum(form(prefix+list(t))*plan.mle(tail_pad, prefix+list(t))
                   for t in product((0, 1), repeat=3-len(prefix))) % plan.P
    claim = (plan.mle(new, r)-previous) % plan.P
    assert claim == partial([])
    for i, coin in enumerate(coins):
        prefix = coins[:i]
        assert claim == (partial(prefix+[0])+partial(prefix+[1])) % plan.P
        samples = [partial(prefix+[t]) for t in range(4)]
        for _ in range(3):
            samples = [(b-a) % plan.P for a, b in zip(samples, samples[1:])]
        assert samples == [0]
        claim = partial(prefix+[coin])
    assert claim == form(coins)*plan.mle(tail_pad, coins) % plan.P
    assert claim != form(coins)*(plan.mle(tail_pad, coins)+1) % plan.P
    for index in (0, 6, 10, 12):  # old prefix, first append, terminal absorb, virtual padding
        tampered = new.copy()
        tampered[index] += 1
        assert (plan.mle(tampered, r)-previous) % plan.P != partial([])
    # A read of three rows excludes all later rows, even within its padded power of two.
    route = {'source_shape': (6, 2), 'selected_rows': 3, 'row_offset': 0,
             'column_point_bits': 1, 'row_point_bits': 2}
    point = r[:3]
    weights = [plan.input_route_form(route, point, [(i >> j) & 1 for j in range(4)]) for i in range(16)]
    altered = new.copy()
    altered[6] += 101
    assert plan.dot(weights, new) == plan.dot(weights, altered) == plan.mle(old_pad, point)
    assert plan.mle(new[:8], point) != plan.mle(altered[:8], point)  # naive alias leaks a future slot
    # Read-router prefix repair: coefficients precede coin, then a second source visit.
    first_round = []
    for x in range(3):
        first_round.append(sum((f0+x*(f1-f0))*(v0+x*(v1-v0))
                               for f0, f1, v0, v1 in zip(weights[::2], weights[1::2], new[::2], new[1::2])) % plan.P)
    assert (first_round[0]+first_round[1]) % plan.P == plan.dot(weights, new)
    coin = 19
    f_tail = [(a+coin*(b-a)) % plan.P for a, b in zip(weights[::2], weights[1::2])]
    v_tail = [(a+coin*(b-a)) % plan.P for a, b in zip(new[::2], new[1::2])]
    c2 = (first_round[2]-2*first_round[1]+first_round[0])*pow(2, -1, plan.P) % plan.P
    c1 = (first_round[1]-first_round[0]-c2) % plan.P
    assert plan.dot(f_tail, v_tail) == (first_round[0]+coin*c1+coin*coin*c2) % plan.P
    assert plan.mle(v_tail, r[1:]) == plan.mle(new, [coin]+r[1:])
    # Fixing the random state probe before committing lets two errors cancel.
    eq0, eq1 = math.prod(1-x for x in r) % plan.P, r[0]*math.prod(1-x for x in r[1:]) % plan.P
    late = new.copy()
    late[0] += 1
    late[1] -= eq0*pow(eq1, -1, plan.P) % plan.P
    assert late != new and plan.mle(late, r) == plan.mle(new, r)


def test_kv_transition_counts_are_not_free_pcs_or_complete_gamma():
    report = plan.report()
    first, last = report['kv_transition_screens'][0], report['kv_transition_screens'][-1]
    assert first['state_planes'] == first['tail_producer_obligations'] == 120
    manifest = Path(__file__).resolve().parents[1] / 'manifests/c7-d126-gemma31b-qspec-dag-v1.json'
    raw = manifest.read_bytes()
    assert plan.hashlib.sha256(raw).hexdigest() == plan.QSPEC_SHA256
    layer = {row[0]: row[2] for row in json.loads(raw)['compact_program']['layer']}
    sources = layer['kv_cache_append'].split('[')[0].split('+')
    assert first['tail_producer_operations'] == {s: 60 for s in sources} == {'k_rope': 60, 'v_norm': 60}
    assert layer['qk_matmul'].split('+')[0] == 'q_rope' not in sources
    config = plan.pinned_model_config()
    assert all(config[k+'_kv_heads'] != config['query_heads'] for k in ('local', 'global'))
    assert first['predecessor_opening_claims'] == 0 and last['predecessor_opening_claims'] == 120
    assert first['sumcheck_rounds'] == 0 and last['sumcheck_rounds'] == 2380
    assert first['tail_direct_point_aliases'] == 120 and last['tail_direct_point_aliases'] == 0
    assert first['extension_corrections'] == 120 and last['extension_corrections'] == 7500
    assert first['payload_before_read_routes_pcs_framing_and_shared_closures'] == 2880
    assert last['payload_before_read_routes_pcs_framing_and_shared_closures'] == 180000
    assert first['extension_challenges'] == 2380 and last['extension_challenges'] == 5240
    assert first['fixed_state_interactive_error_numerator_before_mac_pcs_fs'] == 2380
    assert last['fixed_state_interactive_error_numerator_before_mac_pcs_fs'] == 7620
    assert first['single_plane_two_extension_vectors_bytes'] == 0
    assert last['single_plane_two_extension_vectors_bytes'] == 50331648
    assert first['core_requested_packed_kv_bytes_one_fused_visit'] == 135168000
    assert last['core_requested_packed_kv_bytes_one_fused_visit'] == 3690987520
    assert last['read_route_literal_two_full_extension_vectors_bytes_at_capacity'] == 805306368
    assert last['read_route_one_bit_prefix_two_tail_vectors_bytes_at_capacity'] == 402653184
    assert last['read_route_source_visits_with_one_prefix_bit'] == 2
    b = report['cut_byte_opening_screen']['selected_paired_opening']
    base = (report['cut_witness_screens'][0]['checkpoint_storage_bytes']
            +b['retained_outer_internal_nodes_bytes']+b['known_message_descriptor_alpha_union_bytes'])
    assert base == 5745049488
    assert base+last['read_route_literal_two_full_extension_vectors_bytes_at_capacity'] == 6550355856 > 6442450944
    assert base+last['read_route_one_bit_prefix_two_tail_vectors_bytes_at_capacity'] == 6147702672 < 6442450944
    assert first['prover_extension_products_upper_before_mac_metadata_and_replay'] == 136442880
    assert last['prover_extension_products_upper_before_mac_metadata_and_replay'] == 8057420080
    assert first['zero_residuals'] == 0 and last['zero_residuals'] == 2500
    for screen in (first, last):
        assert screen['private_products'] == 0
        assert screen['additional_weight_reads'] == screen['per_token_commitments'] == 0
        assert not screen['credit'] and not screen['kv_pcs_read_consumers_and_full_liveness_compiled']
        assert screen['complete_certificate_bytes'] is None


def test_attention_rectangle_dp_matches_dense_views_and_not_causal_pruning():
    def eq(point, i):
        return math.prod(x if (i >> j) & 1 else 1-x for j, x in enumerate(point)) % plan.P
    for old, prompt, generated in product(range(5), range(1, 5), range(1, 4)):
        t, s = prompt+generated, old+prompt+generated
        nt, ns = (t-1).bit_length(), (s-1).bit_length()
        for tape in ([2, 3, 5, 7], [0, 1, 0, 1], [1, 0, 1, 0]):
            rt, rs, ut, us = tape[:nt], tape[:ns], tape[::-1][:nt], tape[::-1][:ns]
            expected = sum(eq(rt, i)*eq(ut, i)*eq(rs, j)*eq(us, j)
                           for i in range(t) for j in range(old+prompt if i < prompt else old+i+1)) % plan.P
            assert plan.attention_rectangle_form(rt, rs, ut, us, old, prompt, generated) == expected
    for row, key, expected in ((0, 4045, 1), (0, 4046, 0), (149, 4095, 1), (149, 0, 1)):
        rt, rs = [(row >> j) & 1 for j in range(8)], [(key >> j) & 1 for j in range(12)]
        assert plan.attention_rectangle_form(rt, rs, rt, rs, 3946) == expected
    # Input axes/workload validation also applies before the DP.
    for args in (([], [], [], [], 0, 1, 1), ([0], [0], [0], [0], -1, 1, 1),
                 ([0], [0], [0], [0], 0, 0, 1), ([0], [0], [0], [0], 4095, 1, 1)):
        with pytest.raises(ValueError):
            plan.attention_rectangle_form(*args)


def test_attention_raw_qk_pv_sumchecks_return_exact_gqa_and_kv_endpoints():
    # Synthetic arithmetic only: these P values are NOT claimed to be a softmax.
    old, prompt, generated, t, tp, sp, groups, repeats, lanes = 1, 2, 1, 3, 4, 4, 2, 2, 2
    heads = groups*repeats
    def eq(point, i):
        return math.prod(x if (i >> j) & 1 else 1-x for j, x in enumerate(point)) % plan.P
    def eq_point(a, b):
        return plan.shifted_eq_form(a, b, 0, 1 << len(a))
    def valid(i, j):
        return i < t and j < (old+prompt if i < prompt else old+i+1)
    q = [3*i+5*h+d*d+1 if i < t else 0 for i in range(tp) for h in range(heads) for d in range(lanes)]
    k = [2*j*j+7*b+3*d+2 for j in range(sp) for b in range(groups) for d in range(lanes)]
    v = [5*j+3*b*b+7*d+1 for j in range(sp) for b in range(groups) for d in range(lanes)]
    prob = [7*(h+1)+3*i*i+5*j*(h+1) if valid(i, j) else 0
            for h in range(heads) for i in range(tp) for j in range(sp)]
    def Q(i, h, d):
        return q[d+lanes*(h+heads*i)]
    def K(j, b, d):
        return k[d+lanes*(b+groups*j)]
    def V(j, b, d):
        return v[d+lanes*(b+groups*j)]
    def Prob(i, h, j):
        return prob[j+sp*(i+tp*h)]  # scores are head,token,key, NOT token,head,key
    raw_qk = [int(valid(i, j))*sum(Q(i, h, d)*K(j, h//repeats, d) for d in range(lanes))
              for h in range(heads) for i in range(tp) for j in range(sp)]
    raw_pv = [sum(Prob(i, h, j)*V(j, h//repeats, d) for j in range(sp) if valid(i, j))
              for i in range(tp) for h in range(heads) for d in range(lanes)]
    rt, rs, re, rb, rd = [5, 7], [2, 3], [11], [13], [17]
    def rectangle(a, b, x, y):
        return plan.attention_rectangle_form(a, b, x, y, old, prompt, generated)
    def reduce_poly(fn, coins, degrees, initial):
        def partial(prefix):
            return sum(fn(prefix+list(bits)) for bits in product((0, 1), repeat=len(coins)-len(prefix))) % plan.P
        claim = initial
        assert claim == partial([])
        for i, (coin, degree) in enumerate(zip(coins, degrees)):
            prefix = coins[:i]
            assert claim == (partial(prefix+[0])+partial(prefix+[1])) % plan.P
            samples = [partial(prefix+[x]) for x in range(degree+2)]
            for _ in range(degree+1):
                samples = [(b-a) % plan.P for a, b in zip(samples, samples[1:])]
            assert samples == [0]
            claim = partial(prefix+[coin])
        return claim

    # QK: eliminate token/key/group/lane in that order; only group is cubic.
    def qk_poly(x):
        ut, us, ub, ud = x[:2], x[2:4], x[4:5], x[5:]
        return rectangle(rt, rs, ut, us)*eq_point(rb, ub)*plan.mle(q, ud+re+ub+ut)*plan.mle(k, ud+ub+us) % plan.P
    q_coins = [19, 23, 29, 31, 37, 41]
    q_claim = plan.mle(raw_qk, rs+rt+re+rb)
    q_last = reduce_poly(qk_poly, q_coins, [2, 2, 2, 2, 3, 2], q_claim)
    ut, us, ub, ud = q_coins[:2], q_coins[2:4], q_coins[4:5], q_coins[5:]
    scalar = rectangle(rt, rs, ut, us)*eq_point(rb, ub) % plan.P
    q_end, k_end = plan.mle(q, ud+re+ub+ut), plan.mle(k, ud+ub+us)
    assert q_last == scalar*q_end*k_end % plan.P
    assert q_last != scalar*(q_end+1)*k_end % plan.P

    # Honest QK availability: prefix K, snapshot at logical lengths; never a t*s*d table.
    c = groups*lanes
    prefix, h_table = [0]*c, [[0]*c for _ in range(tp)]
    for j in range(sp):
        prefix = [(a+eq(rs, j)*K(j, b, d)) % plan.P for b in range(groups)
                  for d, a in enumerate(prefix[b*lanes:(b+1)*lanes])]
        for i in range(t):
            if j+1 == (old+prompt if i < prompt else old+i+1):
                h_table[i] = [eq(rt, i)*eq(rb, b)*prefix[b*lanes+d] % plan.P
                              for b in range(groups) for d in range(lanes)]
    qbar = [[sum(eq(re, e)*Q(i, b*repeats+e, d) for e in range(repeats)) % plan.P
             for b in range(groups) for d in range(lanes)] for i in range(tp)]
    assert sum(plan.dot(a, b) for a, b in zip(qbar, h_table)) % plan.P == q_claim
    fstar = [sum(eq(ut, i)*eq(rt, i)*eq(rs, j) for i in range(t) if valid(i, j)) % plan.P for j in range(sp)]
    for b, d in product(range(groups), range(lanes)):
        assert plan.mle([h_table[i][b*lanes+d] for i in range(tp)], ut) == (
            eq(rb, b)*sum(fstar[j]*K(j, b, d) for j in range(sp))) % plan.P
    assert plan.mle(fstar, us) == rectangle(rt, rs, ut, us)

    # PV contracts to M(group,key), then explicitly proves M back to the same P tensor.
    m = [sum(eq(rt, i)*eq(re, e)*Prob(i, b*repeats+e, j)
             for i in range(t) for e in range(repeats) if valid(i, j)) % plan.P
         for j in range(sp) for b in range(groups)]
    vbar = [sum(eq(rd, d)*V(j, b, d) for d in range(lanes)) % plan.P
            for j in range(sp) for b in range(groups)]
    def pv_outer(x):
        return eq_point(rb, x[:1])*plan.mle(m, x)*plan.mle(vbar, x) % plan.P
    pv_coins = [43, 47, 53]
    pv_claim = plan.mle(raw_pv, rd+re+rb+rt)
    pv_last = reduce_poly(pv_outer, pv_coins, [3, 2, 2], pv_claim)
    vb, vs = pv_coins[:1], pv_coins[1:]
    m_end, v_end = plan.mle(m, pv_coins), plan.mle(v, rd+vb+vs)
    assert v_end == plan.mle(vbar, pv_coins)
    assert pv_last == eq_point(rb, vb)*m_end*v_end % plan.P
    def m_link(x):
        return rectangle(rt, vs, x[:2], x[2:])*plan.mle(prob, x[2:]+x[:2]+re+vb) % plan.P
    link_coins = [59, 61, 67, 71]
    m_last = reduce_poly(m_link, link_coins, [2]*4, m_end)
    p_end = plan.mle(prob, link_coins[2:]+link_coins[:2]+re+vb)
    factor = rectangle(rt, vs, link_coins[:2], link_coins[2:])
    assert m_last == factor*p_end % plan.P and m_last != factor*(p_end+1) % plan.P
    altered_m = m.copy()
    altered_m[0] += 1
    assert plan.mle(altered_m, pv_coins) != m_end  # a free contraction cannot pass the link
    # Both tempting shortcuts change the off-Boolean polynomial.
    assert plan.mle([2, 15], [7]) != plan.mle([1, 3], [7])*plan.mle([2, 5], [7]) % plan.P
    assert plan.mle([0, 2], [3]) != plan.mle([0, 1], [3])*plan.mle([1, 2], [3]) % plan.P
    # QK retains future prompt keys before masking, but not keys outside the view.
    assert raw_qk[2] != 0 and raw_qk[3] == 0
    # Wrong GQA group mapping or score-axis order does not preserve the claimed output.
    wrong_group = [int(valid(i, j))*sum(Q(i, h, d)*K(j, h % groups, d) for d in range(lanes))
                   for h in range(heads) for i in range(tp) for j in range(sp)]
    assert plan.mle(wrong_group, rs+rt+re+rb) != q_claim
    assert plan.mle(raw_qk, rs+re+rb+rt) != q_claim


def test_attention_contracted_replay_does_not_fold_a_masked_product_as_linear():
    # Minimal PV contraction counterexample: M(s)=L(s)*P(s) on Boolean cells.
    # A linear M oracle is legal only with its own source link; L~(s)P~(s) is quadratic.
    mask, prob, value = [0, 1], [1, 2], [3, 5]
    m = [a*b for a, b in zip(mask, prob)]
    r = 7
    assert plan.mle(m, [r]) != plan.mle(mask, [r])*plan.mle(prob, [r]) % plan.P
    # Link at r: sum_s EQ(r,s)*L(s)*P(s), encoded as public form times P~.
    form = [(1-r)*mask[0] % plan.P, r*mask[1] % plan.P]
    assert plan.dot(form, prob) == plan.mle(m, [r])
    samples = [plan.mle(mask, [x])*plan.mle(prob, [x])*plan.mle(value, [x]) % plan.P for x in range(4)]
    for _ in range(3):
        samples = [(b-a) % plan.P for a, b in zip(samples, samples[1:])]
    assert samples[0] != 0  # the unlinked three-factor source polynomial needs degree three


def test_attention_component_counts_and_local_arrays_do_not_close_integer_gamma():
    report = plan.report()
    first, last = report['attention_product_screens']
    assert first['extension_corrections'] == 10850 and last['extension_corrections'] == 13010
    assert first['sumcheck_rounds_and_extension_challenges'] == 3330
    assert last['sumcheck_rounds_and_extension_challenges'] == 4050
    assert first['interactive_error_numerator_before_input_links_mac_fs'] == 7100
    assert last['interactive_error_numerator_before_input_links_mac_fs'] == 8540
    assert first['payload_before_output_normalizers_integer_links_kv_pcs_framing_shared_closures'] == 260400
    assert last['payload_before_output_normalizers_integer_links_kv_pcs_framing_shared_closures'] == 312240
    assert first['kv_router_with_k1_and_one_call_each']['payload_before_kv_pcs_framing_shared_closures'] == 174240
    assert last['kv_router_with_k1_and_one_call_each']['payload_before_kv_pcs_framing_shared_closures'] == 208800
    assert first['rectangular_score_cells_per_layer'] == 520800
    assert last['rectangular_score_cells_per_layer'] == 19461600
    assert first['cases'][0]['qk_literal_dense_product_extension_table_bytes'] == 12884901888 > 6442450944
    assert last['cases'][0]['qk_key_phase_arrays_bytes'] == 403222960
    assert max(c['pv_probability_link_arrays_bytes'] for c in last['cases']) == 117623072
    for screen, expected in ((first, (736460080, 128043440, 1069790)),
                             (last, (3384636720, 3743905200, 1319150))):
        assert tuple(sum(c['layers']*c[field] for c in screen['cases']) for field in (
            'qk_prover_extension_products_before_replay_mac_metadata_upper',
            'pv_prover_extension_products_before_replay_mac_metadata_upper',
            'verifier_extension_products_before_inputs_fs_shared_closures_upper')) == expected
    b = report['cut_byte_opening_screen']['selected_paired_opening']
    base = (report['cut_witness_screens'][0]['checkpoint_storage_bytes']
            +b['retained_outer_internal_nodes_bytes']+b['known_message_descriptor_alpha_union_bytes'])
    for screen, k1, expected in ((first, report['kv_transition_screens'][0], 5800633184),
                                 (last, report['kv_transition_screens'][-1], 6149674528)):
        records = k1['core_plaintext_and_mac_record_bytes']+48*(screen['extension_corrections']
                    +screen['kv_router_with_k1_and_one_call_each']['extension_corrections'])
        arrays = max(c[field] for c in screen['cases'] for field in (
            'qk_query_phase_arrays_bytes', 'qk_key_phase_arrays_bytes',
            'pv_group_phase_arrays_bytes', 'pv_probability_link_arrays_bytes'))
        assert base+records+arrays == expected < 6442450944  # still excludes KV PCS/Replay/runtime
    for screen in (first, last):
        assert screen['private_products'] == screen['new_kv_point_demands'] == 120
        assert screen['additional_weight_reads'] == screen['new_trace_commitments'] == 0
        assert not screen['credit'] and not screen['integer_lowering_output_normalizers_kv_pcs_and_full_liveness_compiled']
        assert screen['complete_certificate_bytes'] is report['complete_certificate_bytes'] is None
        for c in screen['cases']:
            assert c['qk_error_numerator_before_input_links_mac_fs'] <= 3*c['qk_rounds']
    with pytest.raises(ValueError):
        plan.attention_product_screen(3947)


def test_auxiliary_layout_raw_probes_and_rne_use_one_byte_source():
    sources = [
        {'shape': (1, 3, 2), 'word_bytes': 6, 'rne': True, 'token_offset': 0},
        {'shape': (2, 2, 2), 'word_bytes': 6, 'rne': True, 'token_offset': 0},
        {'shape': (2, 1, 3), 'word_bytes': 6, 'rne': True, 'token_offset': 2},
        {'shape': (2, 3, 2), 'word_bytes': 6, 'rne': True, 'token_offset': 0},
        {'shape': (1, 2, 1), 'word_bytes': 2, 'rne': False, 'token_offset': 0},
    ]
    byte_tiles, rq_tiles = plan.auxiliary_word_layout(sources)
    live = sum(math.prod(s['shape'])*s['word_bytes'] for s in sources)
    u, seen = [0]*(1 << (live-1).bit_length()), set()
    def raw(i, h, r, c):
        return 11*i-5*h+3*r*r+2*c-17
    for i, r, c, heads, height, width, j, count, offset in byte_tiles:
        size = heads*height*width*count
        assert offset % size == 0
        for h, a, b, l in product(range(heads), range(height), range(width), range(count)):
            key = i, h, r+a, c+b, j+l
            assert key not in seen
            seen.add(key)
            word = raw(i, h, r+a, c+b)+(1 << (8*sources[i]['word_bytes']-1))
            u[offset+count*(b+width*(a+height*h))+l] = (word >> (8*(j+l))) & 255
    assert len(seen) == live and all(0 <= x < 256 for x in u)
    points = {0: ([], [2, 3], [5], 7), 1: ([11], [13, 17], [19, 23], 29),
              2: ([11], [13, 17], [19, 23], 29), 3: ([31], [37, 41], [43], 47),
              4: ([], [53], [], 59)}
    terms, bias = plan.auxiliary_probe_terms(byte_tiles, sources, points)
    def eq(point, index):
        return math.prod(x if (index >> j) & 1 else 1-x for j, x in enumerate(point)) % plan.P
    expected = 0
    for i, s in enumerate(sources):
        hp, rp, cp, scale = points[i]
        expected += sum(scale*eq(hp,h)*eq(rp,s['token_offset']+r)*eq(cp,c)*raw(i,h,r,c)
                        for h,r,c in product(*(range(d) for d in s['shape'])))
    actual = sum(coef*plan.mle(u[offset:offset+(1 << len(point))], point)
                 for offset,point,coef in terms) % plan.P
    assert (actual-bias) % plan.P == expected % plan.P
    # Non-power-of-two support makes the bias different from one bias per source.
    assert bias != sum(v[3]*(1 << (8*sources[i]['word_bytes']-1)) for i,v in points.items()) % plan.P
    rq_live = sum(t[3]*t[4]*t[5] for t in rq_tiles)
    rq_planes = [[0]*(1 << (rq_live-1).bit_length()) for _ in range(6)]
    for i,r,c,heads,height,width,offset in rq_tiles:
        assert offset % (heads*height*width) == 0
        assert sources[i]['rne']
        for h,a,b in product(range(heads), range(height), range(width)):
            value = raw(i,h,r+a,c+b)
            digits = [((value+(1 << 47)) >> (8*j)) & 255 for j in range(6)]
            for j in range(6):
                rq_planes[j][offset+b+width*(a+height*h)] = digits[j]
            y, valid = plan.rne48_byte_polynomials(digits, 2)
            assert valid == 1 and y == plan.rne_i48_to_i16(value,2) % plan.P
    rq_point = list(range(2,2+(rq_live-1).bit_length()))
    for j, plane in enumerate(rq_planes):
        terms = plan.auxiliary_rq_terms(byte_tiles, rq_tiles, rq_point, j)
        actual = sum(coef*plan.mle(u[o:o+(1 << len(q))],q) for o,q,coef in terms) % plan.P
        assert actual == plan.mle(plane,rq_point)
    for point,j in ((rq_point[:-1],0),(rq_point,6),(rq_point,-1)):
        with pytest.raises(ValueError):
            plan.auxiliary_rq_terms(byte_tiles,rq_tiles,point,j)
    bad = [dict(sources[0], shape=(3,3,2))]
    with pytest.raises(ValueError):
        plan.auxiliary_word_layout(bad)
    with pytest.raises(ValueError):
        plan.auxiliary_probe_terms(byte_tiles, sources, {1: ([11],[],[19,23],1)})


def test_masked_raw_overflow_cannot_be_removed_by_attention_pruning():
    # Two prompt rows, scale shift=0: only the FUTURE prompt score overflows.
    q, k = [[2,0], [0,0]], [[1,0], [32767,0]]
    raw = [[sum(a*b for a,b in zip(x,y)) for y in k] for x in q]
    assert raw == [[2,65534], [0,0]]
    assert all(plan.rne_i48_to_i16(raw[i][j],0) in (0,2) for i in range(2) for j in range(i+1))
    with pytest.raises(ValueError):
        plan.rne_i48_to_i16(raw[0][1],0)
    # Even byte-valid words need to be fixed BEFORE the raw-equality probe.
    # Tiny-field necessity example, not an attack claimed against Goldilocks.
    for coin in range(7):
        late_words = [coin, (coin-1) % 7]
        assert any(late_words) and ((1-coin)*late_words[0]+coin*late_words[1]) % 7 == 0
    assert sum((1-r) % 7 == 0 for r in range(7)) == 1  # fixed error [1,0]


def test_striped_rs_is_the_identical_codeword_not_a_different_pcs():
    rng = random.Random(713)
    for block in (1,2,4,8,16,32,64):
        values = [rng.randrange(plan.P) for _ in range(block)]
        expected = plan.small_goldilocks_fft(values+[0]*(3*block))
        for bits in range(block.bit_length()):
            assert plan.small_striped_rs(values, 1 << bits) == expected
    for args in (([],1), ([0]*3,1), ([0]*4,3), ([0]*128,4), ([plan.P],1)):
        with pytest.raises(ValueError):
            plan.small_striped_rs(*args)


def test_three_level_query_subtrees_and_segmented_digest_build_are_exact():
    # Prover cache scheduling only; SHA256 here is NOT a Poseidon2/A2 KAT.
    def parent(a,b):
        return plan.hashlib.sha256(a+b).digest()
    leaves = [plan.hashlib.sha256(bytes([i])).digest() for i in range(64)]
    levels = [leaves]
    while len(levels[-1]) > 1:
        levels.append([parent(a,b) for a,b in zip(levels[-1][::2],levels[-1][1::2])])
    segments = [leaves[i:i+16] for i in range(0,64,16)]
    for level in (1,2):
        folded = [parent(a,b) for a,b in zip(sum(segments,[])[::2],sum(segments,[])[1::2])]
        segments = [folded[i:i+16] for i in range(0,len(folded),16)]
        assert folded == levels[level] and len(segments) == 4 >> level
    assert sum(len(level) for level in levels[3:]) == 64//4-1
    queries = [0,1,7,8,23,24,63]
    expanded = sorted({8*(q//8)+j for q in queries for j in range(8)})
    assert len(expanded) <= 8*len(queries)
    for q in queries:
        subtree = [leaves[j] for j in range(8*(q//8),8*(q//8)+8)]
        x, index = leaves[q], q
        for h in range(3):
            sibling = subtree[(index % len(subtree)) ^ 1]
            x = parent(sibling,x) if index & 1 else parent(x,sibling)
            subtree = [parent(a,b) for a,b in zip(subtree[::2],subtree[1::2])]
            index //= 2
        assert x == levels[3][q//8]
        for h in range(3,len(levels)-1):
            sibling = levels[h][index ^ 1]
            x = parent(sibling,x) if index & 1 else parent(x,sibling)
            index //= 2
        assert x == levels[-1][0]


def test_auxiliary_bridge_exclusions_repairs_and_pending_composition_are_explicit():
    first, last = plan.report()['auxiliary_witness_screens']
    assert (first['source_byte_cells'],last['source_byte_cells']) == (5846628096,12665316096)
    assert (first['rq_live_cells'],last['rq_live_cells']) == (764739200,1901187200)
    assert (first['byte_cubes'],last['byte_cubes']) == (36070,69310)
    assert (first['rq_cubes'],last['rq_cubes']) == (16343,32963)
    assert (first['unified_pcs_payload_before_framing_shared_closures'],last['unified_pcs_payload_before_framing_shared_closures']) == (9810600,15708840)
    assert first['raw_probe_extension_challenges_and_error_numerator_before_t1_mac_pcs_fs'] == 2530
    assert last['raw_probe_extension_challenges_and_error_numerator_before_t1_mac_pcs_fs'] == 2770
    assert first['layout_sha256'] == 'adafad225aae2eaa2bb915cc9e5af063671b746665e6cfc9fc88cd5cffc3cac7'
    assert last['layout_sha256'] == 'f4d83e2da5ffb7faa17760d31de63d25fe9e6a8fe303d93ca9dea9ab7aee734b'
    assert last['literal_full_source_retention_bytes'] > 6442450944
    for s in (first,last):
        assert s['source_templates'] == 3893 and s['raw_probe_payload_bytes'] == 2880
        assert s['literal_four_row_commit_with_b_bytes'] > 6442450944
        assert s['commit_source_traversals'] == 64 and s['opening_source_traversals_after_commit'] == 2
        assert s['commit_padded_source_element_visits'] == 64*s['source_padded_byte_cells']
        assert s['cached_outer_tree_bytes'] == 268435424
        assert s['compact_c1_internal_tree_cache_bytes'] == 67108832
        assert s['query_reconstructed_columns_upper'] == 2856
        assert s['rne_indicator_screen']['top_fixed_cell_prefix'] == 18
        assert s['rne_indicator_screen']['link_fixed_cell_prefix'] == 11
        for key,value in s.items():
            if 'known_union_before_replay_runtime' in key:
                assert value < 6442450944, (key,value)  # NOT a full-liveness assertion
        assert not s['credit'] and not s['full_auxiliary_source_retained']
        assert not s['source_reader_all_gamma_forms_and_full_liveness_compiled']
        assert s['additional_weight_reads_given_w_free_source_reader'] == 0
        assert s['complete_certificate_bytes'] is None
    for args in ((30,0,11),(30,18,0),(30,True,11)):
        with pytest.raises(ValueError):
            plan.rne_indicator_screen(*args)


def test_i48_requantization_matches_exact_fraction_and_rejects_overflow():
    for shift in range(-2, 13):
        for value in range(-512, 513):
            want = round(Fraction(value, 1 << shift)) if shift >= 0 else value*(1 << -shift)
            if -32767 <= want <= 32767:
                assert plan.rne_i48_to_i16(value, shift) == want
            else:
                with pytest.raises(ValueError):
                    plan.rne_i48_to_i16(value, shift)
    for shift in (-14, 0, 1, 15, 31, 32, 33, 47, 48):
        for value in (-(1 << 47), -(1 << 47)+1, -23088334918656, 0, 23088334918656, (1 << 47)-1):
            want = round(Fraction(value, 1 << shift)) if shift >= 0 else value*(1 << -shift)
            if -32767 <= want <= 32767:
                assert plan.rne_i48_to_i16(value, shift) == want
            else:
                with pytest.raises(ValueError):
                    plan.rne_i48_to_i16(value, shift)
    assert [plan.rne_i48_to_i16(x, 1) for x in (-3, -1, 1, 3)] == [-2, 0, 0, 2]
    assert plan.rne_i48_to_i16(-(1 << 47), 10**9) == 0
    assert plan.rne_i48_to_i16(0, -10**9) == 0
    for args in ((1, -10**9), (1 << 47, 48), (-(1 << 47)-1, 48), (True, 0), (0, False)):
        with pytest.raises(ValueError):
            plan.rne_i48_to_i16(*args)


def test_byte_basis_has_no_private_denominator_or_exception_at_roots():
    for point in range(256):
        assert plan.byte_lagrange_basis(point) == [int(point == j) for j in range(256)]
    for point in (256, 1234567, plan.P-1):
        basis = plan.byte_lagrange_basis(point)
        for degree in (0, 1, 2, 17, 255):
            assert sum(pow(j, degree, plan.P)*x for j, x in enumerate(basis)) % plan.P == pow(point, degree, plan.P)
    for value in (-1, plan.P, True):
        with pytest.raises(ValueError):
            plan.byte_lagrange_basis(value)


def test_biased_byte_rounding_polynomials_cover_all_shift_classes_and_ties():
    cases = {(0, -10**6), (1, -10**6), (-(1 << 47), 10**6)}
    for shift in range(-15, 49):
        cases.update((a, shift) for a in (0, 17, -17))
        if -14 <= shift <= 0:
            bound = 32767 >> -shift
            cases.update((a, shift) for a in (bound, bound+1, -bound, -bound-1))
        if 1 <= shift <= 47:
            half = 1 << (shift-1)
            cases.update((a, shift) for a in (-3*half, -half, half, 3*half) if -(1 << 47) <= a < 1 << 47)
        if 1 <= shift <= 32:
            bound = 65535*(1 << (shift-1))-1
            cases.update((a, shift) for a in (bound, bound+1, -bound, -bound-1))
    for value, shift in sorted(cases):
        digits = list((value+(1 << 47)).to_bytes(6, 'little'))
        y, valid = plan.rne48_byte_polynomials(digits, shift)
        if abs(shift) > 100:
            expected_valid = int(shift > 0 or value == 0)
            expected = 0
        else:
            expected = round(Fraction(value, 1 << shift)) if shift >= 0 else value*(1 << -shift)
            expected_valid = int(-32767 <= expected <= 32767)
        assert valid == expected_valid, (value, shift)
        if valid:
            assert y == expected % plan.P, (value, shift)
    # Reconstruction ALONE is insufficient: the first "byte" is not a byte.
    bad, good = [256, 0, 0, 0, 0, 128], [0, 1, 0, 0, 0, 128]
    decode = lambda ds: sum((1 << (8*j))*v for j, v in enumerate(ds))-(1 << 47)
    assert decode(bad) == decode(good) == 256
    bad_y, bad_valid = plan.rne48_byte_polynomials(bad, 8)
    assert bad_valid == 1 and bad_y != 1
    assert plan.rne48_byte_polynomials(good, 8) == (1, 1)
    assert math.prod(256-j for j in range(256)) % plan.P != 0  # byte-range proof rejects


def test_byte_polynomial_sumcheck_round_degrees_on_a_nonboolean_line():
    values = []
    for t in range(1534):
        digits = [(19+j+(3+2*j)*t) % plan.P for j in range(6)]
        y, valid = plan.rne48_byte_polynomials(digits, 15)
        values.append(((3+7*t)*y+(5+11*t)*(1-valid)) % plan.P)
    assert len(set(values)) > 1
    for _ in range(1532):
        values = [(b-a) % plan.P for a, b in zip(values, values[1:])]
    assert values == [0, 0]  # round degree <=1531, including public MLE factor
    values = [(3+7*t)*math.prod(19+5*t-j for j in range(256)) % plan.P
              for t in range(260)]
    for _ in range(258):
        values = [(b-a) % plan.P for a, b in zip(values, values[1:])]
    assert values == [0, 0]  # byte range round degree <=257, not 256


def test_byte_lift_literal_exclusion_and_four_row_repair_are_only_screens():
    s = plan.report()['requantization_screen']
    assert s['matrix_raw_cells'] == 647475200 and s['matrix_padded_cells'] == 1 << 30
    assert s['b_biased_byte_live_cells'] == 5143044096
    assert s['requantization_extension_corrections_upper'] == 3601
    assert s['requantization_payload_upper_before_framing_and_shared_closures'] == 86424
    assert s['rne_direct_reference']['extension_corrections'] == 51133
    assert s['rne_direct_reference']['payload_before_framing_and_shared_closures'] == 1227192
    assert s['byte_range_extension_corrections'] == 1192
    assert s['byte_range_payload_before_framing_and_shared_closures'] == 28608
    assert s['byte_range_direct_reference']['extension_corrections'] == 8770
    assert s['byte_range_direct_reference']['payload_before_framing_and_shared_closures'] == 210480
    literal = {row['block_bits']: row for row in s['literal_six_row_byte_pcs_screens']}
    assert literal[21]['w_plus_b_base_corrections_only_bytes_no_anchors'] == 35470976 > 35000000
    assert literal[22]['b_preparation_with_full_tree_bytes'] == 7626072032 > 6442450944
    assert s['four_row_no_outer_tree_pcs_payload_before_framing'] == 15507248
    assert s['four_row_no_outer_tree_preparation_with_b_bytes'] == 6283894784
    assert s['queried_tree_rebuild_known_union_without_x1_bytes'] == 6347936704
    assert s['fixed_prefix_rounds_before_materialization'] == 17
    assert s['source_scans_per_sumcheck_before_cached_tail_upper'] == 18
    assert s['additional_w_reads_for_these_byte_algorithms'] == 0
    assert s['requires_new_b_byte_commitment_profile']
    assert not s['credit'] and not s['byte_pcs_forms_and_complete_liveness_compiled']
    assert s['complete_gamma_or_certificate_bytes'] is None
    normal = plan.private_hobbit_arithmetic_hash_screen(1 << 33, 1 << 22, 357)
    changed = plan.private_hobbit_arithmetic_hash_screen(1 << 33, 1 << 22, 357, 4)
    assert normal['source_words_per_hash_group'] == 6 and changed['source_words_per_hash_group'] == 4
    assert normal['chain_groups'] == 342 and changed['chain_groups'] == 512
    assert changed['setup_code_rows_and_chain_digests_bytes'] == 256*(1 << 22)
    for group in (0, 7, True):
        with pytest.raises(ValueError):
            plan.private_hobbit_arithmetic_hash_screen(1 << 33, 1 << 22, 357, group)


def small_byte_cut_case():
    cohorts, raw, physical = [], [], 0
    for i, (kind, width, rows, cols) in enumerate((('matrix', 6, 3, 5), ('norm', 4, 2, 3), ('lookup', 2, 3, 2))):
        cohorts.append({'ordinal': i, 'kind': kind, 'cut_scalar_bytes': width,
                        'cut_byte_offset': physical, 'rows': rows, 'columns': cols})
        values = [(-1)**j*(17+23*j) for j in range(rows*cols)]
        values[0], values[-1] = -(1 << (8*width-1)), (1 << (8*width-1))-1
        raw.append(values)
        physical += rows*cols*width
    byte_tiles, rq_tiles = plan.cut_byte_layout(cohorts)
    source, mapping = [0]*(1 << (physical-1).bit_length()), {}
    for i, row, col, height, width, first, count, offset in byte_tiles:
        c = cohorts[i]
        for r, s, lane in product(range(height), range(width), range(count)):
            cell = (row+r)*c['columns']+col+s
            index = offset+count*(r*width+s)+lane
            assert index not in mapping
            mapping[index] = i, cell, first+lane
            biased = raw[i][cell]+(1 << (8*c['cut_scalar_bytes']-1))
            source[index] = (biased >> (8*(first+lane))) & 255
    matrices = sum(t[3]*t[4] for t in rq_tiles)
    planes = [[0]*(1 << (matrices-1).bit_length()) for _ in range(6)]
    for i, row, col, height, width, offset in rq_tiles:
        for r, s in product(range(height), range(width)):
            biased = raw[i][(row+r)*cohorts[i]['columns']+col+s]+(1 << 47)
            for lane in range(6):
                planes[lane][offset+r*width+s] = (biased >> (8*lane)) & 255
    return cohorts, raw, source, planes, mapping


def test_virtual_byte_cubes_cover_every_physical_byte_once_and_preserve_bias():
    cs, raw, source, _, mapping = small_byte_cut_case()
    byte_tiles, rq_tiles = plan.cut_byte_layout(cs)
    live = sum(len(values)*c['cut_scalar_bytes'] for c, values in zip(cs, raw))
    assert sorted(mapping) == list(range(live))
    assert len(set(mapping.values())) == live
    offset = 0
    for tile in byte_tiles:
        size = tile[3]*tile[4]*tile[6]
        assert tile[-1] == offset and offset % size == 0 and size & (size-1) == 0
        offset += size
    assert offset == live
    inverse = {key: source[index] for index, key in mapping.items()}
    for i, values in enumerate(raw):
        width = cs[i]['cut_scalar_bytes']
        for cell, a in enumerate(values):
            assert sum((1 << (8*j))*inverse[i, cell, j] for j in range(width))-(1 << (8*width-1)) == a
    assert sum(t[3]*t[4] for t in rq_tiles) == len(raw[0])
    assert all(t[5] % (t[3]*t[4]) == 0 for t in rq_tiles)
    for bad in ([{**cs[0], 'cut_scalar_bytes': 4}, *cs[1:]],
                [cs[0], {**cs[1], 'cut_byte_offset': 1}, cs[2]]):
        with pytest.raises(ValueError):
            plan.cut_byte_layout(bad)


def test_known_byte_opening_forms_match_all_macs_biases_and_padding():
    cs, raw, source, planes, mapping = small_byte_cut_case()
    rng = random.Random(20260907)
    point = lambda bits: [rng.randrange(plan.P) for _ in range(bits)]
    cuts = [(point((c['rows']-1).bit_length()), point((c['columns']-1).bit_length())) for c in cs]
    rq, byte, pad = point((len(planes[0])-1).bit_length()), point(7), point(7)
    coin = 17
    terms, biases = plan.cut_byte_opening_forms(cs, cuts, rq, byte, pad, coin)
    def eq(r, index):
        return math.prod(x if (index >> j) & 1 else 1-x for j, x in enumerate(r)) % plan.P
    y = [sum(a*eq(r, cell//c['columns'])*eq(s, cell % c['columns']) for cell, a in enumerate(values)) % plan.P
         for c, values, (r, s) in zip(cs, raw, cuts)]
    known_values = [(a+b) % plan.P for a, b in zip(y, biases)]+[plan.mle(v, rq) for v in planes]+[plan.mle(source, byte), 0]
    claim = sum(pow(coin, j, plan.P)*a for j, a in enumerate(known_values)) % plan.P
    for other_coin in (0, 1, plan.P-1):
        other_terms, other_biases = plan.cut_byte_opening_forms(cs, cuts, rq, byte, pad, other_coin)
        assert other_biases == biases
        want = sum(pow(other_coin, j, plan.P)*a for j, a in enumerate(known_values)) % plan.P
        assert sum(c*plan.mle(source[o:o+(1 << len(q))], q) for o, q, c in other_terms) % plan.P == want
    table = [sum(c*eq(q, index-offset) for offset, q, c in terms if offset <= index < offset+(1 << len(q))) % plan.P
             for index in range(len(source))]
    assert plan.dot(source, table) == claim
    # Independent scalar pullback checks the coefficient of each physical byte.
    rq_indices = {}
    for i, row, col, height, width, offset in plan.cut_byte_layout(cs)[1]:
        for r, s in product(range(height), range(width)):
            rq_indices[i, (row+r)*cs[i]['columns']+col+s] = offset+r*width+s
    for index, actual in enumerate(table):
        expected = pow(coin, len(cs)+6, plan.P)*eq(byte, index)
        if index in mapping:
            i, cell, lane = mapping[index]
            r, s = cuts[i]
            expected += pow(coin, i, plan.P)*pow(256, lane, plan.P)*eq(r, cell//cs[i]['columns'])*eq(s, cell % cs[i]['columns'])
            if cs[i]['kind'] == 'matrix':
                expected += pow(coin, len(cs)+lane, plan.P)*eq(rq, rq_indices[i, cell])
        else:
            expected += pow(coin, len(cs)+7, plan.P)*eq(pad, index)
        assert actual == expected % plan.P
    for target in ([0]*7, [1]*7, point(7)):
        assert plan.mle(table, target) == sum(c*plan.folded_cube_form(o, q, [1], target) for o, q, c in terms) % plan.P
    for block_bits in range(8):
        block = 1 << block_bits
        alpha, inner = point(len(source)//block), point(block_bits)
        folded = [sum(a*table[i*block+j] for i, a in enumerate(alpha)) % plan.P for j in range(block)]
        assert plan.mle(folded, inner) == sum(c*plan.folded_cube_form(o, q, alpha, inner) for o, q, c in terms) % plan.P
    assert (claim+pow(coin, len(cs), plan.P)-plan.dot(source, table)) % plan.P != 0  # altered RNE endpoint
    # Byte range still passes when a dummy is changed from zero to one.
    bad = list(source)
    bad[len(mapping)] = 1
    revised_claim = (claim+pow(coin, len(cs)+6, plan.P)*(plan.mle(bad, byte)-known_values[-2])) % plan.P
    assert (plan.dot(bad, table)-revised_claim) % plan.P == pow(coin, len(cs)+7, plan.P)*eq(pad, len(mapping)) % plan.P != 0
    for args in ((cs, cuts[:-1], rq, byte, pad, coin), (cs, cuts, rq[:-1], byte, pad, coin),
                 (cs, cuts, rq, byte, pad, True), (cs, cuts, rq, byte, [True]*7, coin)):
        with pytest.raises(ValueError):
            plan.cut_byte_opening_forms(*args)


def test_byte_form_sumcheck_transfers_to_one_same_source_endpoint():
    cs, _, source, planes, _ = small_byte_cut_case()
    cuts = [([3]*(c['rows']-1).bit_length(), [5]*(c['columns']-1).bit_length()) for c in cs]
    terms, _ = plan.cut_byte_opening_forms(cs, cuts, [7]*(len(planes[0])-1).bit_length(), [11]*7, [13]*7, 17)
    f = [sum(c*math.prod(v if ((i-o) >> j) & 1 else 1-v for j, v in enumerate(q))
             for o, q, c in terms if o <= i < o+(1 << len(q))) % plan.P for i in range(len(source))]
    u, claim, challenges = list(source), plan.dot(source, f), []
    for round_index in range(7):
        c0 = c2 = at1 = 0
        for a, b, x, y in zip(u[::2], u[1::2], f[::2], f[1::2]):
            c0 += a*x
            c2 += (b-a)*(y-x)
            at1 += b*y
        coefficients = [c0 % plan.P, (at1-c0-c2) % plan.P, c2 % plan.P]
        assert (coefficients[0]+sum(coefficients)) % plan.P == claim
        challenge = 19+23*round_index  # chosen after coefficients in the protocol
        challenges.append(challenge)
        claim = sum(c*pow(challenge, j, plan.P) for j, c in enumerate(coefficients)) % plan.P
        u = [(a+challenge*(b-a)) % plan.P for a, b in zip(u[::2], u[1::2])]
        f = [(a+challenge*(b-a)) % plan.P for a, b in zip(f[::2], f[1::2])]
    public_endpoint = sum(c*plan.folded_cube_form(o, q, [1], challenges) for o, q, c in terms) % plan.P
    assert u[0] == plan.mle(source, challenges) and f[0] == public_endpoint
    assert claim == u[0]*public_endpoint % plan.P
    assert (claim-(u[0]+1)*public_endpoint) % plan.P != 0
    # The selected B opening reuses A4's arbitrary fold, not an extra U-MLE.
    block, alpha = 16, [1, 7, 11, 13, 17, 19, 23, 29]
    source_rows = [source[i:i+block] for i in range(0, len(source), block)]
    original_form = [sum(c*math.prod(v if ((i-o) >> j) & 1 else 1-v for j, v in enumerate(q))
                         for o, q, c in terms if o <= i < o+(1 << len(q))) % plan.P for i in range(len(source))]
    form_rows = [original_form[i:i+block] for i in range(0, len(source), block)]
    folded_source, folded_form, row_claims, _, folded_claim = plan.paired_fold(source_rows, form_rows, alpha[1:])
    assert sum(row_claims) % plan.P == plan.dot(source, original_form)
    assert folded_claim == plan.dot(folded_source, folded_form)
    inner = [31, 37, 41, 43]
    assert plan.mle(folded_form, inner) == sum(c*plan.folded_cube_form(o, q, alpha, inner) for o, q, c in terms) % plan.P
    assert plan.mle(folded_source, inner) == sum(a*plan.mle(row, inner) for a, row in zip(alpha, source_rows)) % plan.P


def test_known_byte_barrier_counts_do_not_close_gamma_or_full_resources():
    s = plan.report()['cut_byte_opening_screen']
    assert s['byte_tiles'] == 10510 and s['matrix_cell_tiles'] == 3563
    assert s['byte_and_rq_descriptor_bytes'] == 843664
    assert s['layout_diagnostic_sha256'] == 'a439e692bf3e0587c5445b37e5f38b7a9bb233d07cea25dd83735572143bbf16'
    assert s['known_claims_including_padding'] == 781
    assert s['public_cube_terms_for_known_claims'] == 31899
    r = s['simple_sumcheck_reference']
    assert r['extension_corrections'] == 100 and r['payload_before_framing_and_shared_closures'] == 2400
    assert r['interactive_transfer_error_numerator_including_padding_probe'] == 879
    assert r['extension_challenges_including_padding_probe'] == 67
    assert r['zero_residual_equations'] == 34 and r['additional_private_products'] == 0
    assert r['two_cached_tail_vectors_bytes'] == 402653184
    assert r['extension_mul_upper_before_form_generation_and_mac'] == 214765142011
    assert r['known_barrier_extension_mul_upper_before_metadata_and_mac'] == 592722264059
    a = s['selected_paired_opening']
    assert a['additional_extension_corrections_over_A3'] == 4162
    assert a['added_payload_before_framing_and_shared_closures'] == 99888
    assert a['component_payload_with_byte_pcs_before_framing'] == 15607136
    assert a['additional_extension_challenges_including_padding_and_batch'] == 2103
    assert a['interactive_transfer_error_numerator_before_A3_and_mac'] == 4951
    assert a['source_traversals_after_commit'] == 2 and not a['x1_regeneration_required']
    assert a['retained_alpha_bytes'] == 49152
    assert a['first_pass_f_f2_g_and_decoded_block_bytes'] == 335544320
    assert a['retained_outer_internal_nodes_bytes'] == 536870880
    assert a['queried_and_sibling_columns_upper'] == 714
    assert a['postcommit_outer_column_hash_calls_upper'] == 365568
    assert a['known_message_descriptor_alpha_union_bytes'] == 65134512
    assert a['commit_preparation_with_b_and_descriptors_bytes'] == 6284738448
    assert a['staged_tree_build_with_b_and_descriptors_bytes'] == 6217629552
    assert a['first_pass_known_union_bytes'] == 6080593808
    assert a['compact_commit_and_sumcheck_known_union_bytes'] == 6305054512
    assert a['queried_columns_known_union_bytes'] == 6217019824
    assert s['gather_requested_packed_bytes_upper_per_byte_source_traversal'] == 9027895296
    assert s['known_claim_forms_compiled'] and not s['complete_gamma_consumers_or_liveness_compiled']
    assert not s['credit'] and not s['physical_b_copy_created'] and s['additional_weight_reads'] == 0
    assert plan.report()['requantization_screen']['sparse_rne_public_coefficient_tail_bytes_upper'] == 564192


def test_internal_only_tree_cache_reconstructs_paths_from_queried_sibling_columns():
    # Cache equivalence with a deterministic hash, NOT an A2/Poseidon2 KAT.
    import hashlib
    block, rows = 4, [[(i*19+j*31) % 256 for j in range(4)] for i in range(8)]
    code = [plan.small_goldilocks_fft(row+[0]*(3*block)) for row in rows]
    domain = 4*block
    def leaf(j):
        return hashlib.sha256(b'L'+j.to_bytes(4,'little')+b''.join(row[j].to_bytes(8,'little') for row in code)).digest()
    def node(i, left, right):
        return hashlib.sha256(b'N'+i.to_bytes(4,'little')+left+right).digest()
    tree = [b'']*(2*domain)
    tree[domain:] = [leaf(j) for j in range(domain)]
    for i in range(domain-1, 0, -1):
        tree[i] = node(i, tree[2*i], tree[2*i+1])
    internal = {i: tree[i] for i in range(1, domain)}
    for queries in ([0], [0, 1, 7, 14], list(range(domain))):
        needed = set(queries) | {j ^ 1 for j in queries}
        assert len(needed) <= 2*len(queries)
        rebuilt = {domain+j: leaf(j) for j in needed}
        for j in queries:
            i, digest = domain+j, rebuilt[domain+j]
            path = []
            while i > 1:
                sibling = rebuilt[i ^ 1] if i >= domain else internal[i ^ 1]
                path.append(sibling)
                digest = node(i//2, sibling, digest) if i & 1 else node(i//2, digest, sibling)
                i //= 2
            assert digest == internal[1]
            # Tamper with the reconstructed leaf sibling; the same root rejects.
            path[0] = bytes([path[0][0] ^ 1])+path[0][1:]
            i, digest = domain+j, rebuilt[domain+j]
            for sibling in path:
                digest = node(i//2, sibling, digest) if i & 1 else node(i//2, digest, sibling)
                i //= 2
            assert digest != internal[1]


def test_byte_range_product_tree_and_cubic_gkr_end_at_same_source():
    p, rng = plan.P, random.Random(20260908)
    def eq(point, index):
        return math.prod(x if (index >> j) & 1 else 1-x for j, x in enumerate(point)) % p
    for x in [*range(256), 256, 257, p-1, rng.randrange(256, p)]:
        tree = plan.byte_product_tree(x)
        assert tree[1] == math.prod(x-j for j in range(256)) % p
        assert (tree[1] == 0) == (x < 256)
    for bad in (-1, p, True, 1.5):
        with pytest.raises(ValueError):
            plan.byte_product_tree(bad)
    for values in ([0, 1, 127, 128, 255, 7, 7, 42], [256, 1, p-1, 42]):
        trees = [plan.byte_product_tree(x) for x in values]
        qnode, qcell = [], [rng.randrange(p) for _ in range((len(values)-1).bit_length())]
        claim = plan.mle([t[1] for t in trees], qcell)
        assert (claim == 0) == all(x < 256 for x in values)  # fixed test probe, not a universal claim
        for depth in range(8):
            left = [t[2*((1 << depth)+j)] for t in trees for j in range(1 << depth)]
            right = [t[2*((1 << depth)+j)+1] for t in trees for j in range(1 << depth)]
            weights = [eq(qnode+qcell, j) for j in range(len(left))]
            assert claim == sum(a*b*c for a, b, c in zip(left, right, weights)) % p
            challenges = []
            for round_index in range(depth+len(qcell)):
                coefficients = [0]*4
                for i in range(0, len(left), 2):
                    term = [1]
                    for vector in (left, right, weights):
                        a, delta = vector[i], (vector[i+1]-vector[i]) % p
                        out = [0]*(len(term)+1)
                        for j, c in enumerate(term):
                            out[j] += a*c
                            out[j+1] += delta*c
                        term = [x % p for x in out]
                    coefficients = [(a+b) % p for a, b in zip(coefficients, term)]
                assert (coefficients[0]+sum(coefficients)) % p == claim
                # The seven-products-per-pair work bound uses this EQ factorization.
                point = qnode+qcell
                gamma = math.prod((1-q)*(1-r)+q*r for q, r in zip(point, challenges)) % p
                quadratic = [0, 0, 0]
                for h, (a, b, c, d) in enumerate(zip(left[::2], left[1::2], right[::2], right[1::2])):
                    p0, p2 = a*c, (b-a)*(d-c)
                    weight = gamma*eq(point[round_index+1:], h) % p
                    for j, value in enumerate((p0, b*d-p0-p2, p2)):
                        quadratic[j] = (quadratic[j]+weight*value) % p
                a, b = 1-point[round_index], 2*point[round_index]-1
                q0, q1, q2 = quadratic
                assert coefficients == [v % p for v in (a*q0, a*q1+b*q0, a*q2+b*q1, b*q2)]
                # Independent non-Boolean evaluations check all degree-3 coefficients.
                for z in (0, 1, 2, 17):
                    folded = [[(a+z*(b-a)) % p for a, b in zip(v[::2], v[1::2])]
                              for v in (left, right, weights)]
                    assert sum(c*pow(z, j, p) for j, c in enumerate(coefficients)) % p == sum(
                        a*b*c for a, b, c in zip(*folded)) % p
                challenge = rng.randrange(p)  # after the four coefficient wires
                challenges.append(challenge)
                claim = sum(c*pow(challenge, j, p) for j, c in enumerate(coefficients)) % p
                left, right, weights = [[(a+challenge*(b-a)) % p for a, b in zip(v[::2], v[1::2])]
                                        for v in (left, right, weights)]
            product_wire = left[0]*right[0] % p
            assert claim == weights[0]*product_wire % p
            assert (claim-weights[0]*(product_wire+1)) % p != 0
            eta = (0, 1, p-1, 7, 11, 13, 17, 19)[depth]  # after L, R and their product
            claim = ((1-eta)*left[0]+eta*right[0]) % p
            qnode, qcell = [eta]+challenges[:depth], challenges[depth:]
            frontier = [t[(1 << (depth+1))+j] for t in trees for j in range(1 << (depth+1))]
            assert claim == plan.mle(frontier, qnode+qcell)
        alias = (claim+sum((1 << j)*x for j, x in enumerate(qnode))) % p
        assert alias == plan.mle(values, qcell)
        # Early eta would invalidate the false-frontier transfer lemma.
        for eta in (0, 1, p-1, 17):
            errors = eta, (eta-1) % p
            assert any(errors) and ((1-eta)*errors[0]+eta*errors[1]) % p == 0
    assert plan.byte_product_tree(1)[1] == 0  # a nonzero dummy still needs the separate padding link


def test_range_gate_histogram_and_fixed_cell_prefix_match_dense_folds():
    p, rng = plan.P, random.Random(20260909)
    values = [rng.randrange(256) for _ in range(32)]
    trees = [plan.byte_product_tree(x) for x in values]
    public = [plan.byte_product_tree(x) for x in range(256)]
    qcell = [rng.randrange(p) for _ in range(5)]
    def eq(point, index):
        return math.prod(x if (index >> j) & 1 else 1-x for j, x in enumerate(point)) % p
    hist = [sum(eq(qcell, i) for i, x in enumerate(values) if x == byte) % p for byte in range(256)]
    assert sum(hist) % p == 1
    for depth in range(8):
        qnode = [rng.randrange(p) for _ in range(depth)]
        for prefix_bits in range(depth+1):
            gate_prefix = [rng.randrange(p) for _ in range(prefix_bits)]
            def gate_value(tree, child, suffix):
                return sum(eq(gate_prefix, j)*tree[2*((1 << depth)+(suffix << prefix_bits)+j)+child]
                           for j in range(1 << prefix_bits)) % p
            for suffix in range(1 << (depth-prefix_bits)):
                dense = sum(eq(qcell, i)*gate_value(t, 0, suffix)*gate_value(t, 1, suffix) for i, t in enumerate(trees)) % p
                histogram = sum(h*gate_value(t, 0, suffix)*gate_value(t, 1, suffix) for h, t in zip(hist, public)) % p
                assert dense == histogram
        functions = [[sum(eq(qnode, j)*t[2*((1 << depth)+j)+child] for j in range(1 << depth)) % p
                      for t in public] for child in (0, 1)]
        source_tables = [[f[x] for x in values] for f in functions]
        prefix = [rng.randrange(p) for _ in range(5)]
        for k in range(6):
            for dense, function in zip(source_tables, functions):
                cached = [sum(eq(prefix[:k], low)*function[values[(high << k)+low]] for low in range(1 << k)) % p
                          for high in range(len(values) >> k)]
                expected = list(dense)
                for r in prefix[:k]:
                    expected = [(a+r*(b-a)) % p for a, b in zip(expected[::2], expected[1::2])]
                assert cached == expected
    # Byte lookups cannot replace polynomial evaluation at a folded non-byte input.
    assert plan.byte_product_tree(plan.mle([0, 1], [257]))[1] != plan.mle([0, 0], [257])


def test_range_product_tree_counts_and_resource_limits_remain_conditional():
    report = plan.report()
    s = report['requantization_screen']['byte_range_product_tree']
    assert s['layers'] == 8 and s['sumcheck_round_degree'] == 3 and s['sumcheck_rounds'] == 292
    assert s['extension_corrections'] == 1192 and s['payload_before_framing_and_shared_closures'] == 28608
    assert s['private_products'] == 8 and s['zero_residuals'] == 300 and s['extension_challenges'] == 333
    assert s['interactive_error_numerator_before_b_mac_and_fs'] == 917
    assert s['source_endpoints'] == 1 and s['extra_endpoint_corrections'] == s['extra_trace_commitments'] == 0
    assert s['source_visits_including_gate_histograms'] == 95 and s['additional_w_reads'] == 0
    assert s['public_node_table_bytes'] == 1046528 and s['public_node_table_base_products'] == 65280
    assert s['gate_phase_public_folded_tables_bytes_upper'] == 1572864
    assert s['two_cached_cell_tail_vectors_bytes'] == 402653184
    assert s['extension_products_upper_before_mac_and_metadata'] == 2053132784689
    assert s['verifier_extension_products_before_fs_b_and_shared_closures_upper'] == 2677
    b = report['cut_byte_opening_screen']
    assert b['byte_range_tree_known_union_bytes'] == 6148794256 < 6442450944
    assert b['byte_range_requested_packed_bytes_upper'] == 857650053120
    known_payload = (report['paired_rs_opening_screen']['component_payload_before_framing_and_caller']
                     +b['selected_paired_opening']['component_payload_with_byte_pcs_before_framing']
                     +24*(report['weight_cohort_screen']['extension_corrections_before_other_circuits']
                           +report['input_link_screen']['extension_corrections']
                           +report['requantization_screen']['requantization_extension_corrections_upper']
                           +s['extension_corrections']))
    assert known_payload == 30833200 and report['complete_certificate_bytes'] is None
    assert known_payload+report['kv_transition_screens'][0][
        'payload_before_read_routes_pcs_framing_and_shared_closures'] == 30836080
    assert not s['credit'] and not s['full_gamma_liveness_or_feasibility'] and not s['proves_zero_padding']
    for bits in range(1, 11):
        tiny = plan.byte_range_tree_screen(bits)
        assert tiny['source_visits_including_gate_histograms'] == 8*(bits+1)+7
        assert tiny['two_cached_cell_tail_vectors_bytes'] == 48
    for bad in (0, 36, True):
        with pytest.raises(ValueError):
            plan.byte_range_tree_screen(bad)


def test_lagrange_sum_tree_is_linear_in_public_function_and_valid_off_alphabet():
    p, rng = plan.P, random.Random(20260910)
    weights = [rng.randrange(p) for _ in range(256)]
    for x in [*range(256), 256, 257, p-1, rng.randrange(p)]:
        products, sums = plan.byte_lagrange_tree(x, weights)
        assert products == plan.byte_product_tree(x)
        expected = weights[x] if x < 256 else plan.dot(weights, plan.byte_lagrange_basis(x))
        assert sums[1] == expected
        assert all(sums[j] == (sums[2*j]*products[2*j+1]+products[2*j]*sums[2*j+1]) % p
                   for j in range(1, 256))
    other, coin = [rng.randrange(p) for _ in range(256)], 17
    combined = [(a+coin*b) % p for a, b in zip(weights, other)]
    for x in (0, 128, 256, p-1):
        _, a = plan.byte_lagrange_tree(x, weights)
        _, b = plan.byte_lagrange_tree(x, other)
        _, c = plan.byte_lagrange_tree(x, combined)
        assert c == [(u+coin*v) % p for u, v in zip(a, b)]
    for bad_weights in (weights[:-1], [True]+weights[1:], [p]+weights[1:]):
        with pytest.raises(ValueError):
            plan.byte_lagrange_tree(0, bad_weights)


def test_lifted_indicator_rne_has_degree_six_and_needs_its_own_source_link():
    p = plan.P
    source_bytes = [0, 0, 0, 0, 0, 128]
    basis = [[int(j == x) for j in range(256)] for x in source_bytes]
    for shift in range(-15, 49):
        assert plan.rne48_indicator_polynomials(basis, shift) == plan.rne48_byte_polynomials(source_bytes, shift)
    line, unlinked = [], []
    for z in range(9):
        lifted = [[((1-z)*int(j == x)+z*int(j == x+1)) % p for j in range(256)] for x in source_bytes]
        _, valid = plan.rne48_indicator_polynomials(lifted, -15)
        assert valid == pow(1-z, 6, p)
        line.append((3+5*z)*(1-valid) % p)
        unlinked.append(plan.rne48_byte_polynomials([(x+z) % p for x in source_bytes], -15)[1])
    assert unlinked[2] != pow(-1, 6, p)  # delta(MLE(U)) is not MLE(delta(U))
    for degree in range(8):
        line = [(b-a) % p for a, b in zip(line, line[1:])]
        if degree == 6:
            assert line[0] != 0  # public EQ/selector adds the seventh degree
    assert line == [0]
    for bad in (basis[:-1], [basis[0][:-1]]+basis[1:], [[True]+basis[0][1:]]+basis[1:]):
        with pytest.raises(ValueError):
            plan.rne48_indicator_polynomials(bad, 8)


def test_indicator_ps_gkr_binds_six_source_planes_with_public_dummy_lanes():
    p, rng = plan.P, random.Random(20260911)
    def eq(point, index):
        return math.prod(x if (index >> j) & 1 else 1-x for j, x in enumerate(point)) % p
    def fold(vector, r):
        return [(a+r*(b-a)) % p for a, b in zip(vector[::2], vector[1::2])]
    rho_f, rho_lane = [3, 5, 7, 11, 13, 17, 19, 23], [29, 31, 37]
    omega = [eq(rho_f, j) for j in range(256)]
    for last_selector in (0, 1, 19):
        planes = [[(17*l+3) % 256, (31*l+1) % 256] for l in range(6)]
        if last_selector == 19:
            planes[2][0] = 256  # the link still holds without presuming valid byte inputs
        point = [41]
        bases = [[plan.byte_lagrange_basis(x) for x in row] for row in planes]
        indicator_claims = [[plan.mle([basis[j] for basis in row], point) for j in range(256)] for row in bases]
        dummy = (eq(rho_lane, 6)+eq(rho_lane, 7))*omega[0] % p
        claim = (sum(eq(rho_lane, l)*plan.dot(omega, row) for l, row in enumerate(indicator_claims))+dummy) % p
        trees = [plan.byte_lagrange_tree(x, omega) for row in planes+[[0, 0], [0, 0]] for x in row]
        assert claim == plan.mle([s[1] for _, s in trees], point+rho_lane)
        assert dummy != 0  # omitting the public lanes would change even the honest claim
        selector, node_point, cell_point, lane_point = 1, [], point, rho_lane
        retained = None
        for depth in range(8):
            arrays = [[tree[which][2*((1 << depth)+j)+child] for tree in trees for j in range(1 << depth)]
                      for which, child in ((0, 0), (0, 1), (1, 0), (1, 1))]
            weights = [eq(node_point+cell_point+lane_point, j) for j in range(len(arrays[0]))]
            assert claim == sum(w*((1-selector)*pl*pr+selector*(sl*pr+pl*sr))
                                for w, pl, pr, sl, sr in zip(weights, *arrays)) % p
            challenges = []
            for round_index in range(depth+4):  # one cell bit, then three lane bits
                coefficients = [0]*4
                for i in range(0, len(weights), 2):
                    quadratic = [0, 0, 0]
                    for lhs, rhs, scale in ((0, 1, 1-selector), (2, 1, selector), (0, 3, selector)):
                        a, b = arrays[lhs][i:i+2]
                        c, d = arrays[rhs][i:i+2]
                        q0, q2 = a*c, (b-a)*(d-c)
                        quadratic = [(u+scale*v) % p for u, v in zip(quadratic, (q0, b*d-q0-q2, q2))]
                    for j, q in enumerate(quadratic):
                        coefficients[j] = (coefficients[j]+weights[i]*q) % p
                        coefficients[j+1] = (coefficients[j+1]+(weights[i+1]-weights[i])*q) % p
                assert (coefficients[0]+sum(coefficients)) % p == claim
                for z in (0, 1, 2, 17):
                    folded = [fold(v, z) for v in arrays]
                    expected = sum(w*((1-selector)*pl*pr+selector*(sl*pr+pl*sr))
                                   for w, pl, pr, sl, sr in zip(fold(weights, z), *folded)) % p
                    assert sum(c*pow(z, j, p) for j, c in enumerate(coefficients)) % p == expected
                r = rng.randrange(p)  # after all four coefficient records
                challenges.append(r)
                claim = sum(c*pow(r, j, p) for j, c in enumerate(coefficients)) % p
                arrays, weights = [fold(v, r) for v in arrays], fold(weights, r)
                if depth == 7 and round_index == depth:
                    constant = 2*sum((1 << j)*x for j, x in enumerate(challenges[:depth])) % p
                    retained = [(x+constant) % p for x in arrays[0][:6]]
                    assert retained == [plan.mle(row, challenges[depth:]) for row in planes]
            pl, pr, sl, sr = [v[0] for v in arrays]
            products = pl*pr % p, sl*pr % p, pl*sr % p
            assert claim == weights[0]*((1-selector)*products[0]+selector*(products[1]+products[2])) % p
            # All three products remain obligations even when their public coefficient is zero.
            assert (products[0]+1-pl*pr) % p != 0
            selector = last_selector if depth == 7 else (0, 1, 7, 11, 13, 17, 23)[depth]
            child = (0, 1, 29, 31, 37, 41, 43, 47)[depth]  # both coins AFTER the seven terminal records
            claim = ((1-selector)*((1-child)*pl+child*pr)+selector*((1-child)*sl+child*sr)) % p
            node_point, cell_point, lane_point = [child]+challenges[:depth], challenges[depth:depth+1], challenges[depth+1:]
            next_layer = [((1-selector)*pt[(1 << (depth+1))+j]+selector*st[(1 << (depth+1))+j]) % p
                          for pt, st in trees for j in range(1 << (depth+1))]
            assert claim == plan.mle(next_layer, node_point+cell_point+lane_point)
        assert retained == [plan.mle(row, cell_point) for row in planes]
        leaf_constant = sum((1 << j)*r for j, r in enumerate(node_point)) % p
        psi = plan.mle(trees[0][1][256:], node_point)  # same public w_j for every source cell
        mixed = sum(eq(lane_point, l)*x for l, x in enumerate(retained)) % p
        assert claim == ((1-selector)*(mixed-leaf_constant)+selector*psi) % p
        if selector != 1:
            assert (claim-((1-selector)*(mixed+eq(lane_point, 0)-leaf_constant)+selector*psi)) % p != 0
        # If the function challenge preceded the claims, these actual altered wires would disappear.
        changed = [list(row) for row in indicator_claims]
        changed[0][0] = (changed[0][0]+omega[1]) % p
        changed[0][1] = (changed[0][1]-omega[0]) % p
        assert changed != indicator_claims
        assert sum(eq(rho_lane, l)*plan.dot(omega, row) for l, row in enumerate(changed)) % p == sum(
            eq(rho_lane, l)*plan.dot(omega, row) for l, row in enumerate(indicator_claims)) % p


def test_rne_histograms_and_six_lane_ps_replay_equal_full_dense_tables():
    p, rng = plan.P, random.Random(20260912)
    planes = [[rng.randrange(256) for _ in range(15)]+[0] for _ in range(6)]
    cell_point, lane_point = [3, 5, 7, 11], [13, 17, 19]
    def eq(point, index):
        return math.prod(x if (index >> j) & 1 else 1-x for j, x in enumerate(point)) % p
    # These weighted bins ARE the folded indicator tables, not delta_j of a folded byte.
    for prefix in range(5):
        block = 1 << prefix
        for row in planes:
            for start in range(0, len(row), block):
                hist = [0]*256
                for low, x in enumerate(row[start:start+block]):
                    hist[x] = (hist[x]+eq(cell_point[:prefix], low)) % p
                assert hist == [plan.mle([int(x == j) for x in row[start:start+block]], cell_point[:prefix])
                                for j in range(256)]
    omega = [eq([23, 29, 31, 37, 41, 43, 47, 53], j) for j in range(256)]
    public = [plan.byte_lagrange_tree(x, omega) for x in range(256)]
    hist = [0]*256
    for lane, row in enumerate(planes):
        for i, x in enumerate(row):
            hist[x] = (hist[x]+eq(lane_point, lane)*eq(cell_point, i)) % p
    hist[0] = (hist[0]+eq(lane_point, 6)+eq(lane_point, 7)) % p
    for depth in (0, 3, 7):
        node_point = [rng.randrange(p) for _ in range(depth)]
        functions = [[sum(eq(node_point, j)*tree[which][2*((1 << depth)+j)+child] for j in range(1 << depth)) % p
                      for tree in public] for which, child in ((0, 0), (0, 1), (1, 0), (1, 1))]
        dense = [[f[x] for row in planes+[[0]*16, [0]*16] for x in row] for f in functions]
        for a, b in ((0, 1), (2, 1), (0, 3)):
            assert sum(h*functions[a][x]*functions[b][x] for x, h in enumerate(hist)) % p == sum(
                eq(cell_point+lane_point, i)*u*v for i, (u, v) in enumerate(zip(dense[a], dense[b]))) % p
        for prefix in range(5):
            block = 1 << prefix
            for f, table in zip(functions, dense):
                six_lanes = [[sum(eq(cell_point[:prefix], low)*f[row[start+low]] for low in range(block)) % p
                              for start in range(0, len(row), block)] for row in planes]
                full = list(table)
                for r in cell_point[:prefix]:
                    full = [(a+r*(b-a)) % p for a, b in zip(full[::2], full[1::2])]
                pruned = [x for lane in six_lanes for x in lane]+[f[0]]*(2*(16 >> prefix))
                assert pruned == full
                if prefix == 4:
                    assert plan.mle(pruned, lane_point) == plan.mle(table, cell_point+lane_point)


def test_rne_indicator_counts_do_not_claim_complete_prover_feasibility():
    s = plan.rne_indicator_screen(30)
    assert s['top_round_degree'] == 7 and s['top_extension_corrections'] == 2371
    assert s['link_round_degree'] == 3 and s['link_rounds'] == 292 and s['link_extension_corrections'] == 1230
    assert s['extension_corrections'] == 3601 and s['payload_before_framing_and_shared_closures'] == 86424
    assert s['private_products'] == 619 and s['zero_residuals'] == 332 and s['extension_challenges'] == 381
    assert s['link_interactive_error_numerator_before_b_mac_and_fs'] == 903
    assert s['rne_error_numerator_before_output_batch_size_range_b_mac_fs']+240 == 1383
    assert s['source_endpoints'] == 6 and s['extra_trace_commitments'] == s['function_axis_sumcheck_rounds'] == 0
    assert s['top_fixed_cell_prefix'] == 17 and s['top_indicator_tail_bytes'] == 301989888
    assert s['link_fixed_cell_prefix'] == 10 and s['link_six_lane_four_function_tail_bytes'] == 603979776
    assert s['link_counterfactual_eight_lane_tail_bytes'] == 805306368
    assert s['top_rq_visits'] == 18 and s['link_rq_visits'] == 95 and s['source_rq_visits'] == 113
    assert s['link_public_p_s_tree_bytes'] == 4186112 and s['link_public_child_fold_tables_bytes_upper'] == 3145728
    assert s['top_extension_products_upper_before_public_forms_mac_metadata'] == 140737501088000
    assert s['link_extension_products_upper_before_mac_metadata'] == 4389733525568
    assert s['link_public_base_products_upper'] == 66174
    assert s['verifier_extension_products_before_forms_fs_b_shared_closures_upper'] == 24292
    report = plan.report()
    b = report['cut_byte_opening_screen']
    assert report['requantization_screen']['rne_indicator_opening'] == s
    assert b['rne_top_known_union_bytes'] == 6051085168
    assert b['rne_ps_link_known_union_bytes'] == 6353297296 < 6442450944
    assert b['rne_ps_counterfactual_eight_lane_known_union_bytes'] == 6554623888 > 6442450944
    assert b['rne_requested_matrix_packed_bytes_upper'] == 438988185600
    assert not s['credit'] and not s['all_shifts_gamma_liveness_or_feasibility_compiled'] and s['additional_w_reads'] == 0
    for bits in (1, 10, 17, 32):
        tiny = plan.rne_indicator_screen(bits)
        assert tiny['top_fixed_cell_prefix'] == min(17, bits)
        assert tiny['link_fixed_cell_prefix'] == min(10, bits)
    for bad in (0, 33, True):
        with pytest.raises(ValueError):
            plan.rne_indicator_screen(bad)
