"""Small C7.1 accounting/algebra/DAG checks; no weights, native build or GPU."""

import importlib.util
import json
import math
import random
import runpy
from collections import Counter
from decimal import Decimal, localcontext
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
    form_peak = plan.auxiliary_witness_screen(cohorts, 3945)['rne_public_form_screen']
    form_at_capacity = report['auxiliary_witness_screens'][-1]['rne_public_form_screen']
    # The same metadata envelope bounds the direct public evaluator: all
    # point/domain bit counts are at most the capacity counts, 25 and 31.
    max_cubes = 3803+60*envelope['max_qk_dyadic_rectangles_per_layer']
    assert form_peak['output_terms_if_one_point_per_cohort'] == max_cubes == 33443
    extra_cubes = max_cubes-form_at_capacity['output_terms_if_one_point_per_cohort']
    field = 'verifier_extension_products_at_one_rq_point_upper_if_one_point_per_cohort'
    assert form_peak[field] == form_at_capacity[field]+extra_cubes*(25+5*31+8) == 6275623
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


def test_public_zero_rs_rows_omit_inputs_but_not_hashes_or_partial_rows():
    for dedup in (False, True):
        old = plan.wide_hash_rs_screen(16, 4, 3, dedup)
        for zero in (0, 1, 2, 4):
            new = plan.wide_hash_rs_screen(16, 4, 3, dedup, zero)
            assert old['base_corrections_including_salt']-new['base_corrections_including_salt'] == 3*zero
            assert old['private_component_payload_before_framing_and_caller']-new[
                'private_component_payload_before_framing_and_caller'] == 24*zero
            assert old['known_boundary_and_extension_record_bytes']-new[
                'known_boundary_and_extension_record_bytes'] == 96*zero
            for key in ('private_hash_calls_including_anchor_and_recursion', 'padded_permutation_instances',
                        'power_gkr_extension_corrections', 'tiled_commit_source_traversals',
                        'tiled_commit_native_fft_butterflies', 'full_outer_tree_bytes'):
                assert new[key] == old[key]
            assert new['levels'][1:] == old['levels'][1:]  # no recursive zero-row credit
    old = plan.wide_hash_joint_opening_screen([16, 8], 4, 3)
    new = plan.wide_hash_joint_opening_screen([16, 8], 4, 3, [2, 1])
    assert old['private_component_payload_before_framing_and_caller']-new[
        'private_component_payload_before_framing_and_caller'] == 72
    assert new['source_offsets'] == old['source_offsets'] == [0, 16]
    assert new['joint_rows'] == old['joint_rows'] == 8  # two virtual zeros already omitted
    for counts in ([2], [2, 1, 0], [-1, 0], [5, 0], [0, True], [0, 1.0]):
        with pytest.raises(ValueError):
            plan.wide_hash_joint_opening_screen([16, 8], 4, 3, counts)

    # A perfect symbolic VC tests the clear relation, NOT hash/MAC security.
    block, live, n = 4, 5, 16
    first_zero = (live+block-1)//block
    source = list(range(1, live+1))+[0]*(n-live)
    encoded = [plan.small_goldilocks_fft(source[i:i+block]+[0]*(3*block))
               for i in range(0, n, block)]
    root = tuple(zip(*encoded))  # fixed complete column oracle
    def check(anchor, query, received, start=first_zero):
        if len(received) != start:
            return False
        return tuple(received)+(0,)*(n//block-start) == anchor[query]
    assert all(check(root, j, col[:first_zero]) for j, col in enumerate(root))
    assert not check(root, 0, root[0])  # extra private slots cannot redefine public zeros
    assert all(not check(root, j, col[:live//block], live//block) for j, col in enumerate(root))
    # An entirely nonzero encoded padding row cannot be opened by this codec.
    bad = tuple(col[:first_zero]+(1, 0) for col in root)
    assert all(not check(bad, j, col[:first_zero]) for j, col in enumerate(bad))
    # A malformed root may pass queries elsewhere: no exact-codeword claim.
    sparse = list(root)
    sparse[0] = bad[0]
    assert sum(check(sparse, j, col[:first_zero]) for j, col in enumerate(sparse)) == 15
    # With a fixed zero-row oracle, a nonzero decoded degree<2 row is not
    # close: exhaustive tiny-field RS distance, independent of honest roots.
    distances = [sum((a+b*x) % 17 != 0 for x in range(8))
                 for a, b in product(range(17), repeat=2) if a or b]
    assert min(distances) == 8-2+1
    assert all(distance > (8-2+1)/2 for distance in distances)


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
        "P0": 602, "T1": 120, "K1": 120, "public_decisions": 1, "validity": 1506, 'RMS_statistic':411}
    assert s["plan_sha256"] == "2e4bef32b7749f5b49178971167e81dd60c31d26bc8f7d22ac087a55a6edf468"
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


def test_gamma_rms_source_boundary_preserves_statistics_validity_and_input_identity():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           'manifests/c7-d126-gemma31b-source-metadata-v1.json').read_bytes())
    cohorts = plan.gemma_weight_cohorts([t for t in metadata['tensors'] if t['disposition'] == 'private_text'])
    before, after = plan.gamma_barrier_plan(cohorts), plan.gamma_barrier_plan(cohorts,True)
    s, records, order = after['summary'], after['cohorts'], after['reverse_order']
    assert s['includes_rms_outputs'] and not before['summary']['includes_rms_outputs']
    assert before['rms_statistic_demands'] == after['rms_statistic_demands']
    assert (s['ordinary_kernel_cohorts'],s['final_rne_cohorts'],s['source_boundary_cohorts']) == (554,531,483)
    assert s['retained_cohort_edges'] == 734 and s['delegated_tensor_edges']['RMS_joint_P0_statistics'] == 21470
    assert s['seed_cohorts_by_role'] == {'P0':602,'T1':120,'K1':120,'public_decisions':1,
                                        'validity':1085,'RMS_joint_validity':421,'RMS_statistic':411}
    assert s['ordinary_kernel_operations'] == {**{op:60 for op in (
        'q_rope','k_rope','attention_mask_add','softmax','gelu_tanh','gate_up_mul',
        'attention_residual_add','ffw_residual_add','layer_scalar_mul')},
        'embedding_scale':1,'v_source':10,'last_row_select':1,'final_tanh_softcap':1,'argmax':1}
    assert s['plan_sha256'] == 'a9bdd7ac209b02e3205c3eb4adae8780ccb7abb2779028d66cea84cd6fd0269d'
    rank = {i:r for r,i in enumerate(order)}
    by_op = {(r['layer'],r['operation']):r['ordinal'] for r in records}
    norms, sources = plan.rms_statistic_cohorts(cohorts), plan.rms_output_byte_sources(cohorts)
    for i,norm in enumerate(norms):
        r = records[by_op[norm['layer'],norm['operation']]]
        p = norm['source_producer']
        assert after['rms_statistic_demands'][i] == (i,by_op[p['layer'],p['operation']])
        assert sources[r['rms_source_id']]['source_id'] == i
        assert sources[i]['shape'] == (1,norm['statistic_rows'],norm['columns'])
        assert r['byte_source'] == 'RMS_outputs' and r['kind'] == 'rms_output_boundary' and not r['dependencies']
        assert 'RMS_joint_validity' in r['seeds']
    multiplicities = Counter(p for _,p in after['rms_statistic_demands'])
    assert len(after['rms_statistic_demands']) == 421 and Counter(multiplicities.values()) == {1:401,2:10}
    for old,new in zip(before['cohorts'],records):
        assert (old['ordinal'],old['query_rows'],old['executions']) == (new['ordinal'],new['query_rows'],new['executions'])
        assert all(rank[new['ordinal']] < rank[d] for d in new['dependencies'])
        assert set(old['seeds'])-{'validity'} <= set(new['seeds'])
        if new['kind'] != 'rms_output_boundary':
            assert old['kind'] == new['kind'] and old['dependencies'] == new['dependencies']
            assert ('validity' in old['seeds']) == ('validity' in new['seeds'])
    assert all(records[i]['kind'] == 'rne48' for i in order[554:1085])
    assert all(not records[i]['dependencies'] for i in order[554:])
    assert records[by_op[None,'final_rms']]['query_rows'] == 149
    assert records[by_op[59,'post_ffw_rms']]['query_rows'] == 150
    assert plan.rms_statistic_dependency_plan(cohorts,before) == plan.rms_statistic_dependency_plan(cohorts,after)
    for target,changes in (((0,'q_norm'),{'input_producer':{'layer':0,'operation':'k_rope'}}),
                            ((None,'final_rms'),{'rows':148})):
        altered = [{**c,**changes} if (c['layer'],c['operation']) == target else c for c in cohorts]
        for mode in (False,True):
            with pytest.raises(ValueError):
                plan.gamma_barrier_plan(altered,mode)
    for mode in (1,None,'Y'):
        with pytest.raises(ValueError):
            plan.gamma_barrier_plan(cohorts,mode)
    assert not s['credit'] and s['complete_gamma_forms_and_workspace'] is None


def test_rms_statistic_input_cones_and_two_stage_preparation_are_acyclic():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           'manifests/c7-d126-gemma31b-source-metadata-v1.json').read_bytes())
    cohorts = plan.gemma_weight_cohorts([t for t in metadata['tensors'] if t['disposition'] == 'private_text'])
    gamma = plan.gamma_barrier_plan(cohorts)
    result = plan.rms_statistic_dependency_plan(cohorts,gamma)
    s = result['summary']
    assert s['input_cone_cohorts'] == 592 and s['distinct_raw_B_leaves'] == 290 and s['rms_Y_leaves'] == 120
    assert s['direct_raw_statistic_sources'] == 300 and s['residual_statistic_sources'] == 120
    assert s['pointwise_kernel_cohorts'] == {'embedding_scale':1, 'attention_residual_add':60,
                                           'ffw_residual_add':60, 'layer_scalar_mul':60}
    assert s['statistic_dependency_edges'] == 7260 and s['all_Y_dependencies_have_B_only_statistics']
    assert s['initial_raw_rne_calls_without_K_V_deduplication'] == 250368000
    assert s['initial_post_norm_Y_generations'] == 96768000
    assert s['initial_pointwise_roundings'] == 145958400
    assert s['initial_B_S_kappa_logical_read_bytes'] == 1909036800
    assert s['initial_S_kappa_write_bytes'] == 6913788
    assert s['single_token_residual_vector_bytes'] == 10752
    assert s['reader_raw_reservation_bytes'] == {
        'pointwise_profile_descriptors': 5792, 'raw_shift_by_B_cohort': 6184,
        'statistic_reader_token_vector': 10752, 'pointwise_integer_wave': 20480}
    assert s['sumcheck_input_live_cells'] == plan.rms_statistic_screen(cohorts)['source_live_cells_read'] == 347942400
    assert s['sumcheck_input_raw_rne_calls'] == 250368000
    assert s['sumcheck_input_Y_generations'] == 5854464000
    assert s['sumcheck_input_pointwise_roundings'] == 8855078400
    assert s['sumcheck_input_lookup_cells'] == 97574400
    assert s['sumcheck_input_B_S_kappa_logical_read_bytes'] == 26212924800
    assert not s['credit'] and s['complete_native_statistic_reader_and_liveness'] is None
    norms = plan.rms_statistic_cohorts(cohorts)
    by_key = {(n['layer'],n['operation']): i for i,n in enumerate(norms)}
    rank = {i:r for r,i in enumerate(result['preparation_order'])}
    for i,norm in enumerate(norms):
        layer,op = norm['layer'],norm['operation']
        expected = []
        if op in ('input_rms','pre_ffw_rms','final_rms'):
            expected = [by_key[l,name] for l in range(60 if op == 'final_rms' else layer)
                        for name in ('post_attention_rms','post_ffw_rms')]
            if op == 'pre_ffw_rms':
                expected.append(by_key[layer,'post_attention_rms'])
        assert result['statistic_dependencies'][i] == sorted(expected)
        assert all(rank[j] < rank[i] and not result['statistic_dependencies'][j] for j in expected)
        replay = result['input_replay_counts'][i]
        if op in ('input_rms','pre_ffw_rms','final_rms'):
            layers = 60 if op == 'final_rms' else layer
            half = int(op == 'pre_ffw_rms')
            assert replay == {'Y': (2*layers+half)*150*5376, 'raw_rne': 0,
                              'lookup': 150*5376, 'pointwise': (1+3*layers+half)*150*5376}
        else:
            assert replay == {'Y': 0, 'raw_rne': math.prod(norm['source_shape']), 'lookup': 0, 'pointwise': 0}
    nodes = gamma['cohorts']
    by_op = {(r['layer'],r['operation']):r['ordinal'] for r in nodes}
    for ordinal,changes in ((by_op[0,'q_proj'], {'byte_source':'raw_attention'}),
                            (by_op[0,'attention_residual_add'], {'dependencies':[by_op[0,'softmax']]}),
                            (by_op[0,'attention_residual_add'], {'dependencies':[by_op[0,'attention_residual_add']]})):
        altered = [dict(r) for r in nodes]
        altered[ordinal].update(changes)
        with pytest.raises(ValueError):
            plan.rms_statistic_dependency_plan(cohorts,{'cohorts':altered})
    cyclic = [{**c,'input_producer':{'layer':0,'operation':'post_ffw_rms'}}
              if (c['layer'],c['operation']) == (0,'post_ffw_rms') else c for c in cohorts]
    with pytest.raises(ValueError):
        plan.rms_statistic_dependency_plan(cyclic,gamma)
    truncated = [{**c,'rows':149} if (c['layer'],c['operation']) == (0,'post_attention_rms') else c
                 for c in cohorts]
    with pytest.raises(ValueError):
        plan.rms_statistic_dependency_plan(truncated,gamma)
    # Pointwise does not mean that successive rounded operators can be fused.
    sequential = plan.rne_i48_to_i16(plan.rne_i48_to_i16(1,1)+1,1)
    assert sequential == 0 and plan.rne_i48_to_i16(3,2) == 1
    # A small residual subsystem: capture raw/P first, then prepare S/Y
    # from those cuts, without calling the upstream private matrices again.
    raw = [[1,2,-3], [-2,1,3], [3,-1,2], [-1,-2,1]]  # two post-norms per layer
    products = [[x*w for x,w in zip(row,(1,-2,3))] for row in raw]
    direct_s = [sum(x*x for x in row) for row in raw]
    reference_y = [[plan.rms_rne_i16(p,statistic,3,0,0,0) for p in row]
                   for row,statistic in zip(products,direct_s)]
    a,b,c = plan.rms_integer_coefficients(3,0,0,0)
    staged_y = []
    for row,statistic in zip(products,direct_s):
        denominator = b+c*statistic
        kappa = plan.rms_row_multiplier(a,denominator)
        staged_y.append([plan.rms_rne_from_multiplier(p,a,denominator,kappa) for p in row])
    def residual_statistics(outputs):
        state = [round(Fraction(147*x,2)) for x in (0,1,-1)]
        statistics = []
        for layer in range(2):
            statistics.append(sum(x*x for x in state))
            after_attention = [x+y for x,y in zip(state,outputs[2*layer])]
            statistics.append(sum(x*x for x in after_attention))
            state = [round(Fraction(x+y,2)) for x,y in zip(after_attention,outputs[2*layer+1])]
        return statistics+[sum(x*x for x in state)], state
    assert staged_y == reference_y
    assert residual_statistics(staged_y) == residual_statistics(reference_y)
    altered_y = [row[:] for row in staged_y]
    altered_y[0][0] += 1
    assert residual_statistics(altered_y) != residual_statistics(reference_y)


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


def test_rms_statistics_cover_all_norms_and_preserve_producer_domains():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           "manifests/c7-d126-gemma31b-source-metadata-v1.json").read_bytes())
    tensors = [t for t in metadata["tensors"] if t["disposition"] == "private_text"]
    cohorts = plan.gemma_weight_cohorts(tensors)
    stats = plan.rms_statistic_cohorts(cohorts)
    gamma = plan.gamma_barrier_plan(cohorts)["cohorts"]
    by_op = {(r["layer"], r["operation"]): r for r in stats}
    assert set(by_op) == {(r["layer"], r["operation"]) for r in gamma
                         if r["kind"] == "weighted_rms" or r["operation"] == "v_norm"}
    for r in gamma:
        if (r["layer"], r["operation"]) in by_op:
            s = by_op[r["layer"], r["operation"]]
            assert s["statistic_rows"] == r["query_rows"]*s["heads"]
            predecessor = gamma[r["dependencies"][0]]
            if predecessor["operation"] == "v_source" and predecessor["dependencies"]:
                predecessor = gamma[predecessor["dependencies"][0]]  # global public alias
            assert s["source_producer"] == {"layer": predecessor["layer"], "operation": predecessor["operation"]}
    for layer in range(60):
        heads, lanes = (4, 512) if layer % 6 == 5 else (16, 256)
        v = by_op[layer, "v_norm"]
        assert (v["heads"], v["columns"], v["source_shape"]) == (heads, lanes, (150, heads*lanes))
        assert v["statistic_rows"] == v["source_rows"] == 150*heads
        assert by_op[layer, "q_norm"]["statistic_rows"] == 150*32
    final = by_op[None, "final_rms"]
    assert (final["statistic_rows"], final["source_rows"], final["columns"]) == (149, 150, 5376)
    small = plan.rms_statistic_cohorts(plan.gemma_weight_cohorts(tensors, 1, 1))[-1]
    assert (small["statistic_rows"], small["source_rows"]) == (1, 2)
    s = plan.rms_statistic_screen(cohorts)
    assert (s["normalization_cohorts"], s["weighted_cohorts"], s["statistic_rows"]) == (421, 361, 576149)
    assert (s["statistic_input_cells"], s["source_live_cells_read"], s["source_padded_cells_processed"]) == (
        347937024, 347942400, 767557632)
    assert s["max_integer_statistic_given_i16_ranges"] == 5376*32767**2 < 2**43 < plan.P//2
    assert (s["sumcheck_rounds"], s["extension_corrections"], s["private_square_equations"]) == (8711, 35686, 421)
    assert s["zero_residual_equations"] == 9132
    assert s["message_bytes_before_incoming_claims_framing_and_shared_closures"] == 856464
    assert s["new_plaintext_and_tag_array_bytes"] == 1712928
    assert s["single_cohort_X_and_selector_array_bytes"] == 100872192
    assert s["one_point_per_cohort_prover_E_products_before_replay_and_mac_upper"] == 7681579976
    assert s["X_array_logical_read_write_bytes_before_selectors_replay_and_mac"] == 110528248488
    assert s["fixed_input_error_numerator_before_claim_batching"] == 26133
    assert s["additional_weight_reads_given_w_free_reader"] == s["new_statistic_pcs_instances"] == 0
    assert s["actual_statistic_claim_count"] is s["complete_gamma_memory_or_work"] is None
    assert not s["credit"] and not s["complete_rms_normalizer_and_validity"]


def test_rope_pinned_pairs_positions_integer_bounds_and_q30_refinement_counterexample():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           'manifests/c7-d126-gemma31b-source-metadata-v1.json').read_bytes())
    cohorts = plan.gemma_weight_cohorts([t for t in metadata['tensors'] if t['disposition'] == 'private_text'])
    norms, gamma = plan.rms_statistic_cohorts(cohorts), plan.gamma_barrier_plan(cohorts,True)
    by_op = {(r['layer'],r['operation']): r for r in gamma['cohorts']}
    first, last = plan.gemma_rope_plan(cohorts), plan.gemma_rope_plan(cohorts,3946)
    assert first['summary'] == last['summary']
    for r, end in zip(first['cohorts'],last['cohorts']):
        assert r['position_start'] == 0 and end['position_start']+end['rows']-1 == 4095
        n = norms[r['rms_source_id']]
        producer = by_op[r['layer'],n['operation']]
        assert by_op[r['layer'],r['operation']]['dependencies'] == [producer['ordinal']]
        assert producer['rms_source_id'] == r['rms_source_id']
        assert n['operation'] == r['operation'][0]+'_norm'
        assert n['statistic_rows'] == 150*r['heads']
        assert r['rotating_pairs'] == (64 if r['columns'] == 512 else 128)
    screen = first['summary']
    assert (screen['rope_cohorts'],screen['live_output_cells']) == (120,119808000)
    assert screen['raw_absolute_bound_given_Q30_coefficients'] == 70366596694016 < 1 << 46
    assert screen['public_active_Q30_table_bytes_at_capacity'] == 6291456
    assert screen['raw_virtual_bytes_if_added_to_sigma'] == 718848000
    assert screen['raw_linear_sumcheck_rounds'] == 2460
    assert screen['raw_probe_and_linear_payload_before_rne_pcs_framing'] == 182880
    assert screen['maximum_two_field_arrays_without_reader'] == 201326592
    assert screen['linear_sumcheck_field_products_before_fill_reader_mac'] == 1226833200
    assert screen['raw_identity_error_numerator_before_source_mac_fs'] == 7380
    assert screen['new_private_products_for_raw_linear_reductions'] == 0
    assert screen['coefficient_profile'] == 'C71-RoPE-Q30-v1' and screen['canonical_coefficient_recipe_specified']
    assert (screen['public_setup_root_isqrt_calls'],screen['public_setup_max_root_operand_bits'],
            screen['public_setup_trig_signed_bits']) == (1088,12289,256)
    assert (screen['public_setup_main_integer_products'],screen['public_setup_rne_divisions']) == (50331648,40894464)
    assert screen['canonical_coefficient_table_sha256'] == '67503dd31c4504bed77f836ac1389d64692cef2a721ad74381d6297071d90951'
    assert screen['complete_gemma_quantization_and_runtime_refinement'] is None
    assert not screen['credit'] and not screen['raw_rope_adopted_in_active_source_totals']
    assert screen['raw_rope_common_source_layout_specified']
    assert screen['complete_rope_mac_kernel_and_liveness'] is None
    for old in (-1,3947,True):
        with pytest.raises(ValueError):
            plan.gemma_rope_plan(cohorts,old)

    q = 1 << 30
    values = list(range(1,513))
    raw = plan.rope_raw_row(values,[(0,q)]*64)
    assert raw[:64] == [-q*v for v in values[256:320]]
    assert raw[256:320] == [q*v for v in values[:64]]
    assert raw[64:256] == [q*v for v in values[64:256]]
    assert raw[320:] == [q*v for v in values[320:]]
    assert raw[0] != -q*values[64]  # Rotating a contiguous 128-lane prefix is wrong.
    assert plan.rne_i48_to_i16(raw[64],31) == 32 != values[64]  # Inactive is not free rescaling.
    assert plan.rne_i48_to_i16(plan.rope_raw_row([1,1],[(q//2,q//2)])[1],30) == 1
    assert 2*plan.rne_i48_to_i16(q//2,30) == 0  # Do not round each product separately.
    for (a,b),(c,s) in product(product((-32767,-1,0,1,32767),repeat=2),product((-q,0,q//2,q),repeat=2)):
        for value in plan.rope_raw_row([a,b],[(c,s)]):
            assert abs(value) <= screen['raw_absolute_bound_given_Q30_coefficients']
            for shift in (0,29,30,31,48):
                expected = round(Fraction(value,1 << shift))
                if abs(expected) <= 32767:
                    assert plan.rne_i48_to_i16(value,shift) == expected
                else:
                    with pytest.raises(ValueError):
                        plan.rne_i48_to_i16(value,shift)
    assert max(map(abs,plan.rope_raw_row([32767,32767],[(q,q)]))) == screen['raw_absolute_bound_given_Q30_coefficients']
    for values, coeff in (([1,2,3],[]),([32768,0],[]),([1,2],[(q+1,0)]),([1,2],[(1,0)]*2)):
        with pytest.raises(ValueError):
            plan.rope_raw_row(values,coeff)

    # Pinned position=1, j=0 gives theta=1 in BOTH families. Rational
    # alternating Taylor bounds certify the discrepancy, without libm.
    cosine = sum((Fraction((-1)**k,math.factorial(2*k)) for k in range(13)),Fraction(0))
    sine = sum((Fraction((-1)**k,math.factorial(2*k+1)) for k in range(13)),Fraction(0))
    cb = (cosine-Fraction(1,math.factorial(26)),cosine)
    sb = (sine-Fraction(1,math.factorial(27)),sine)
    assert [round(v*q) for v in cb] == [580145183]*2
    assert [round(v*q) for v in sb] == [903522590]*2
    a,b = -12194,-2574
    lo,hi = min(a*v for v in cb)-max(b*v for v in sb),max(a*v for v in cb)-min(b*v for v in sb)
    assert Fraction(-4422500003,1000000) < lo <= hi < Fraction(-4422500002,1000000)
    assert round(lo) == round(hi) == -4423
    assert plan.rne_i48_to_i16(plan.rope_raw_row([a,b],[(580145183,903522590)])[0],30) == -4422
    assert not screen['canonical_Q30_substitution_preserves_exact_real_rne']


def test_rope_byte_extension_and_gamma_keep_one_source_and_all_rne_validity():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           'manifests/c7-d126-gemma31b-source-metadata-v1.json').read_bytes())
    cohorts = plan.gemma_weight_cohorts([t for t in metadata['tensors'] if t['disposition'] == 'private_text'])
    raw = plan.rope_raw_byte_sources(cohorts)
    bridge = plan.rope_byte_bridge_screen(cohorts)
    assert len(raw) == bridge['raw_rope_sources'] == 120
    assert (bridge['extra_byte_cubes'],bridge['extra_rq_cubes'],bridge['extra_source_and_cube_descriptor_bytes']) == (960,480,107520)
    assert bridge['extra_virtual_source_bytes'] == 718848000
    assert bridge['additional_direct_sigma_claim_wires'] == 240
    assert bridge['known_t1_k1_rope_output_demands'] == 120
    assert bridge['changed_padding_contexts'] == {'sigma':list(range(767,1183)),'rq':list(range(657,1073))}
    assert not bridge['same_rq_layout'] and bridge['additional_pcs_instances'] == 0
    assert bridge['complete_extended_payload_and_liveness'] is None
    rms = plan.rms_statistic_screen(cohorts)
    rms_e = rms['extension_corrections']+len(plan.rms_statistic_byte_sources(cohorts))
    weight_live = sum(math.prod(s) for s in {c['weight_key']:c['weight_shape'] for c in cohorts}.values())
    for old in (0,1,32,33,64,65,106,107,128,129,256,257,362,363,512,513,
                656,657,766,767,874,875,1024,1025,1072,1073,1182,1183,
                1898,1899,2048,2049,3945,3946):
        base = plan.auxiliary_word_sources(cohorts,old)+plan.rms_statistic_byte_sources(cohorts)+plan.rms_output_byte_sources(cohorts)
        before,rq_before = plan.auxiliary_word_layout(base)
        after,rq_after = plan.auxiliary_word_layout(base+raw)
        assert len(after)-len(before) == 960 and len(rq_after)-len(rq_before) == 480
        assert rq_before != rq_after  # Existing raw/RNE offsets must be rebuilt too.
        for name,sources,delta in (('sigma',base,718848000),('rq',[s for s in base if s['rne']],119808000)):
            live = sum(math.prod(s['shape'])*(s['word_bytes'] if name == 'sigma' else 1) for s in sources)
            assert ((live-1).bit_length() != (live+delta-1).bit_length()) == (old in bridge['changed_padding_contexts'][name])
        # Rebuild the known caller/layout at each threshold, not the screen's
        # finite-domain cache. Public-zero omission goes through the PCS API.
        old_source = plan.auxiliary_witness_screen(cohorts,old)
        original = plan.wide_hash_witness_screen(cohorts,old)['joint_w_kv_candidate']
        live = sum(math.prod(s['shape'])*s['word_bytes'] for s in base+raw)
        rq_live = sum(math.prod(s['shape']) for s in base+raw if s['rne'])
        n,t = (live-1).bit_length(),(rq_live-1).bit_length()
        zero = (1 << n)//(1 << 23)-(live+(1 << 23)-1)//(1 << 23)
        sigma = plan.wide_hash_joint_opening_screen([1 << n],1 << 23,357,[zero])
        width = plan.kv_transition_screen(old)['core_requested_packed_kv_bytes_one_fused_visit']//(2*(old+150))
        prefixes = [weight_live]+[width*(1 << (length-1).bit_length()) for length in (old,old+150) if length]
        joint_cells = original['weight_and_state_opening']['source_cells']
        zeros = [v//(1 << 24)-(s+(1 << 24)-1)//(1 << 24) for v,s in zip(joint_cells,prefixes)]
        joint = plan.wide_hash_joint_opening_screen(joint_cells,1 << 24,357,zeros)
        caller = (original['known_caller_extension_corrections']
                  -old_source['rne_indicator_screen']['extension_corrections']
                  -old_source['byte_range_screen']['extension_corrections']
                  +plan.rne_indicator_screen(t,18,11)['extension_corrections']
                  +plan.byte_range_tree_screen(n)['extension_corrections']+rms_e+2+7620
                  +plan.byte_bit_lift_screen(n)['extension_corrections_excluding_incoming_claims']
                  +plan.rne_output_bit_screen(t)['additional_extension_corrections'])
        payload = (joint['private_component_payload_before_framing_and_caller']
                   +sigma['private_component_payload_before_framing_and_caller']-72+24*caller
                   +joint['public_anchor_bytes_if_all_resent']+64)
        assert bridge['known_partial_payload_by_old_tokens'][old] == payload
    first,last = bridge['cases']
    assert (first['source_byte_cells'],last['source_byte_cells']) == (7264807038,14083495038)
    assert (first['rq_live_cells'],last['rq_live_cells']) == (884547200,2020995200)
    assert (first['rq_cubes'],last['rq_cubes']) == (16823,33443)
    assert [c['known_partial_payload_before_rms_joint_gamma_and_framing'] for c in (first,last)] == [26097272,33070392]
    assert [c['known_authenticated_record_bytes_before_rms_joint_gamma'] for c in (first,last)] == [97666256,124909664]
    assert bridge['source_path_payload_delta_distribution'] == {
        425640:1050,426600:36,428496:2371,429456:74,
        2816064:31,2817024:93,2818920:79,2819880:213}
    def source_record_reference(live,rq_live):
        n,t = (live-1).bit_length(),(rq_live-1).bit_length()
        zeros = (1 << n)//(1 << 23)-(live+(1 << 23)-1)//(1 << 23)
        # Independent closed counts: PCS + (32n+136) range + (35n+177)
        # bit lift + (40t+2401) RNE + 768 output-bit products.
        return ({33:1083700,34:1740580}[n]-357*zeros,
                {33:10379,34:12809}[n]+67*n+40*t+3482)
    for old,(b,e) in enumerate(bridge['source_path_correction_deltas_by_old_tokens']):
        before = source_record_reference(6545959038+1728000*old,764739200+288000*old)
        after = source_record_reference(7264807038+1728000*old,884547200+288000*old)
        assert (b,e) == (after[0]-before[0],after[1]-before[1]+7620)
    assert bridge['maximum_source_path_record_delta_bytes'] == 10791984
    assert len(bridge['known_partial_payload_by_old_tokens']) == 3947
    assert bridge['maximum_known_partial_payload_before_rms_joint_gamma_and_framing'] == 33070392
    assert bridge['remaining_payload_bytes_before_missing_components'] == 1929608
    previous = plan.rms_byte_bridge_screen(cohorts,True)
    for case in previous['cases']:
        o = case['old_tokens']
        b,e = bridge['source_path_correction_deltas_by_old_tokens'][o]
        assert (case['known_partial_payload_before_rms_circuit_gamma_and_framing']+8*b+24*e
                == bridge['known_partial_payload_by_old_tokens'][o])
    arrays = bridge['additional_known_retained_arrays_256_byte_aligned']
    assert all(v % 256 == 0 for v in arrays.values()) and sum(arrays.values()) == 7019264
    assert arrays['linear_plaintexts_and_tags'] == 365824  # Not 240 new endpoint copies.
    phases = bridge['source_and_rope_arena_phase_upper_bytes_before_rms_joint_reader_gamma_runtime']
    for k,v in previous['all_context_arena_phase_upper_bytes'].items():
        assert phases[k] == v+7019264+(23040 if k == 'rne_top' else 0)
    assert phases['rope_linear'] == phases['opening_first_pass']-80*(1 << 23)+201326592 == 5635527808
    assert bridge['known_phase_max_upper_bytes_before_rms_joint_reader_gamma_runtime'] == max(phases.values()) == 6348559488
    assert (bridge['known_bulk_sigma_visits'],bridge['known_bulk_rq_visits']) == (231,122)
    assert bridge['raw_byte_requests_in_known_bulk_paths'] == 253753344000
    assert bridge['raw_linear_field_products_before_fill_reader_mac'] == 1226833200
    reader = bridge['word_reader_work']
    assert (reader['raw_word_lanes'],reader['retained_word_buffer_bytes']) == (64,1024)
    assert reader['bulk_raw_generations'] == 69967872000
    assert reader['y_generations_including_linear_fill'] == 140055552000
    assert reader['extra_input_raw_rne_calls'] == 0
    assert reader['B_S_kappa_logical_read_bytes'] == 4*140055552000+12*(140055552000//64)
    assert reader['public_q30_logical_read_bytes_upper'] == 8*(69967872000+119808000)
    assert reader['raw_signed_i64_products_upper'] == 2*69967872000
    assert reader['raw_signed_i64_additions_upper'] == 69967872000
    assert reader['complete_all_gamma_reader_work_and_runtime'] is None
    gamma = plan.gamma_barrier_plan(cohorts,True,True)
    summary = gamma['summary']
    assert (summary['ordinary_kernel_cohorts'],summary['final_rne_cohorts'],summary['source_boundary_cohorts'],
            summary['retained_cohort_edges']) == (434,651,483,614)
    assert summary['delegated_tensor_edges']['RoPE_linear'] == 6120
    assert summary['seed_cohorts_by_role']['validity'] == 1085
    assert summary['seed_cohorts_by_role']['RMS_joint_validity'] == 421
    assert summary['plan_sha256'] == 'a598a635062c1c1db0fb4628a24d80714122a38967f66e055c7d1c2ed4517811'
    before = plan.gamma_barrier_plan(cohorts,True)
    assert gamma['rms_statistic_demands'] == before['rms_statistic_demands']
    assert plan.rms_statistic_dependency_plan(cohorts,gamma) == plan.rms_statistic_dependency_plan(cohorts,before)
    by_rope = {r['rope_source_id']:r for r in gamma['cohorts'] if r['byte_source'] == 'RoPE_raw'}
    norms = plan.rms_statistic_cohorts(cohorts)
    for i,producer in gamma['rope_input_demands']:
        r,n = by_rope[i],gamma['cohorts'][producer]
        assert r['kind'] == 'rne48' and not r['dependencies'] and 'validity' in r['seeds']
        assert r['layer'] == n['layer'] and r['operation'][0]+'_norm' == n['operation']
        assert n['kind'] == 'rms_output_boundary' and 'RoPE_linear' in n['seeds']
        assert (raw[i]['layer'],raw[i]['operation']) == (r['layer'],r['operation'])
        assert raw[i]['shape'] == (norms[n['rms_source_id']]['heads'],150,norms[n['rms_source_id']]['columns'])
        assert ('T1' if r['operation'] == 'q_rope' else 'K1') in r['seeds']
        head,rows,cols = raw[i]['shape']
        cb,hb,tb = ((d-1).bit_length() for d in (cols,head,rows))
        point = list(range(2,2+cb+hb+tb))
        hp,tp,cp,weight = plan.rope_output_source_point(raw[i],point,7)
        assert cp+hp+tp == point and weight == 7
        _,rp,ycp,_ = plan.rms_output_source_point(norms[n['rms_source_id']],point)
        assert (rp,ycp) == (hp+tp,cp)
    for args in ((False,True),(True,1)):
        with pytest.raises(ValueError):
            plan.gamma_barrier_plan(cohorts,*args)


def test_rope_word_reader_uses_its_rms_source_pair_and_absolute_position(monkeypatch):
    calls = []
    read = plan.rms_read_input_word
    def counted(reader, first, count, *args):
        calls.append((first,count))
        return read(reader,first,count,*args)
    monkeypatch.setattr(plan,'rms_read_input_word',counted)
    for family,width,pairs in (('local',256,128),('global',512,64)):
        coefficients = plan.rms_integer_coefficients(width,0,5,-3)
        a,b,c = coefficients
        rows = [[(17*r+11*j)%101-50 for j in range(width)] for r in range(4)]
        statistics = [sum(x*x for x in row) for row in rows]
        buffers = (bytes(8)+b''.join(x.to_bytes(4,'little',signed=True) for row in rows for x in row),
                   bytes(6)+b''.join((s+(1 << 47)).to_bytes(6,'little') for s in statistics),
                   bytes(6)+b''.join(plan.rms_row_multiplier(a,b+c*s).to_bytes(6,'little') for s in statistics))
        reader = {'norm_source_id':7, 'product_source_id':4, 'product_byte_offset':8,
                  'statistic_byte_offset':6, 'rows':4, 'columns':width, 'product_word_bytes':4}
        record = {'operation':'q_rope', 'rms_source_id':7, 'heads':2, 'rows':2,
                  'columns':width, 'rotating_pairs':pairs, 'position_start':4094}
        public = [(pos,plan.gemma_rope_q30_coefficients(family,pos)) for pos in (4094,4095)]
        for row in range(4):
            y = [plan.rms_rne_i16(v,statistics[row],width,0,5,-3) for v in rows[row]]
            expected = plan.rope_raw_row(y,public[row//2][1])
            for lane in range(0,width,64):
                calls.clear()
                raw = plan.rope_read_raw_word(record,reader,row*width+lane,64,buffers,coefficients,public[row//2])
                assert raw == expected[lane:lane+64]
                first = row*width+lane % (width//2)
                assert calls == [(first,64),(first+width//2,64)]
                biased = [v+(1 << 47) for v in raw]
                # The two Sigma groups emit exactly the same six bytes as RQ.
                grouped = [[(v >> (8*j)) & 255 for j0,n in ((0,4),(4,2)) for j in range(j0,j0+n)] for v in biased]
                assert [sum(x << (8*j) for j,x in enumerate(d))-(1 << 47) for d in grouped] == raw
        # Sigma's cube order is byte/lane/token/head, not native lane/head/token.
        tiles,_ = plan.auxiliary_word_layout([{'shape':(2,2,width),'word_bytes':6,'rne':True}])
        calls.clear()
        for _,row0,col0,heads,height,cols,j0,n,offset in tiles:
            assert offset % (64*n) == 0 and (1 << 23) % (64*n) == 0
            emitted = []
            for h in range(heads):
                for t in range(row0,row0+height):
                    for lane in range(col0,col0+cols,64):
                        raw = plan.rope_read_raw_word(record,reader,(t*heads+h)*width+lane,64,
                                                     buffers,coefficients,public[t])
                        emitted.extend(((v+(1 << 47)) >> (8*j)) & 255 for v in raw for j in range(j0,j0+n))
            dense = []
            for h in range(heads):
                for t in range(row0,row0+height):
                    row = t*heads+h
                    y = [plan.rms_rne_i16(v,statistics[row],width,0,5,-3) for v in rows[row]]
                    raw = plan.rope_raw_row(y,public[t][1])
                    dense.extend(((v+(1 << 47)) >> (8*j)) & 255 for v in raw[col0:col0+cols] for j in range(j0,j0+n))
            assert emitted == dense
        assert sum(n for _,n in calls) == 4*4*width  # 2 byte groups, 2 Y inputs, 4 native rows.
        for r,rr,first,count,bufs,pub in (
                ({**record,'rms_source_id':8},reader,0,1,buffers,public[0]),
                (record,{**reader,'product_word_bytes':6},0,1,buffers,public[0]),
                (record,reader,-1,1,buffers,public[0]),
                (record,reader,4*width,1,buffers,public[0]),
                (record,reader,0,65,buffers,public[0]),
                (record,reader,width//2-1,2,buffers,public[0]),
                (record,reader,width-1,2,buffers,public[0]),
                (record,reader,0,1,buffers,public[1]),
                (record,reader,0,1,buffers,(4094,public[0][1][:-1])),
                (record,reader,0,1,buffers,(4094,((1 << 31,0),)+public[0][1][1:])),
                (record,reader,0,1,(b'',*buffers[1:]),public[0]),
                (record,reader,0,1,(buffers[0],b'',buffers[2]),public[0])):
            with pytest.raises(ValueError):
                plan.rope_read_raw_word(r,rr,first,count,bufs,coefficients,pub)


def test_rope_canonical_q30_recipe_has_fixed_precision_and_quantized_semantics():
    q = 1 << 96
    error = 12
    assert Fraction(1,4**22*math.factorial(22)) < Fraction(1,q)
    assert Fraction(1,4**23*math.factorial(23)) < Fraction(1,q)
    for _ in range(14):
        assert Fraction(error,q) < Fraction(1,2)
        error = 5*error+1
    assert error == 74768066406 < 1 << 37
    for family,degree,power,count in (('local',32,1,128),('global',128,3,64)):
        frequencies = plan.rope_inverse_frequencies_q96(family)
        assert len(frequencies) == count and frequencies[0] == q
        assert all(a > b for a,b in zip(frequencies,frequencies[1:]))
        for j,f in enumerate(frequencies):
            assert f**degree*10**(power*j) <= q**degree < (f+1)**degree*10**(power*j)
        assert plan.gemma_rope_q30_coefficients(family,0) == ((1 << 30,0),)*count
        assert plan.gemma_rope_q30_coefficients(family,1)[0] == (580145183,903522590)
        for position in (1,1023,3946,4095):
            coefficients = plan.gemma_rope_q30_coefficients(family,position)
            assert len(coefficients) == count
            for j in (0,1,count//2,count-1):
                # Independent exact-rational RNE checks every rounded operation;
                # no libm and no integer helper shared with the recipe.
                def rnd(n,d):
                    assert abs(n).bit_length() < 256 and d.bit_length() < 256
                    return round(Fraction(n,d))
                x = rnd(position*frequencies[j],1 << 14)
                square = rnd(x*x,q)
                cs,ss,tc,ts = q,x,q,x
                for k in range(1,11):
                    tc,ts = rnd(-tc*square,q*(2*k-1)*(2*k)),rnd(-ts*square,q*(2*k)*(2*k+1))
                    cs,ss = cs+tc,ss+ts
                for _ in range(14):
                    cs,ss = rnd(cs*cs-ss*ss,q),rnd(2*cs*ss,q)
                assert coefficients[j] == (rnd(cs,1 << 66),rnd(ss,1 << 66))
                # Higher-degree/high-precision reference at the exact dyadic
                # frequency; the exact root inequality above bounds its input error.
                with localcontext() as context:
                    context.prec = 100
                    z = Decimal(position)*Decimal(frequencies[j])/Decimal(q*(1 << 14))
                    cr = sum((-1)**k*z**(2*k)/Decimal(math.factorial(2*k)) for k in range(30))
                    sr = sum((-1)**k*z**(2*k+1)/Decimal(math.factorial(2*k+1)) for k in range(30))
                    for _ in range(14):
                        cr,sr = cr*cr-sr*sr,2*cr*sr
                    assert max(abs(Decimal(cs)/q-cr),abs(Decimal(ss)/q-sr)) < Decimal(2)**-59
                    assert max(abs(Decimal(coefficients[j][0])/(1 << 30)-cr),
                               abs(Decimal(coefficients[j][1])/(1 << 30)-sr)) < Decimal(2)**-31+Decimal(2)**-59
    for family,position in (('other',0),('local',-1),('global',4096),('local',True)):
        with pytest.raises(ValueError):
            plan.gemma_rope_q30_coefficients(family,position)


def test_rope_adjoint_quadratic_sumcheck_and_same_rms_source_point():
    p,q = plan.P,1 << 30
    # Three tokens (one padded), two heads, four lanes; one active pair.
    coefficients = [[(q,0)],[(580145183,903522590)],[(-q//2,q//2)]]
    y = [((5*t+3*h+1)*(j+1)-17) if t < 3 else 0
         for t,h,j in product(range(4),range(2),range(4))]
    raw = sum((plan.rope_raw_row(y[8*t+4*h:8*t+4*h+4],coefficients[t]) if t < 3 else [0]*4
               for t,h in product(range(4),range(2))),[])
    r = ([2,3],[5],[7,11])
    def eq(point,index):
        return math.prod(v if index >> k & 1 else 1-v for k,v in enumerate(point)) % p
    dense = []
    for t,h,c in product(range(4),range(2),range(4)):
        C,S = coefficients[t][c % 2] if t < 3 and c % 2 == 0 else (q,0)
        value = eq(r[1],h)*eq(r[2],t)*(eq(r[0],c)*C+eq(r[0],c ^ 2)*(1-2*(c//2))*S)
        dense.append(value % p if t < 3 else 0)
    coins = [13,17,19,23,29]
    for point in [list(v) for v in product((0,1),repeat=5)]+[coins]:
        assert plan.rope_linear_input_form(coefficients,r,(point[:2],point[2:3],point[3:])) == plan.mle(dense,point)
    claim = plan.mle(raw,sum((list(a) for a in r),[]))
    assert claim == sum(a*b for a,b in zip(dense,y)) % p
    assert claim != (sum(a*b for a,b in zip(dense,y))+dense[0]) % p  # Tampered input, fixed raw.
    f,x = dense[:],y[:]
    pair_count = 0
    for k,coin in enumerate(coins):
        g = [0,0,0]
        for i in range(0,len(x),2):
            df,dx = f[i+1]-f[i],x[i+1]-x[i]
            g = [(a+b) % p for a,b in zip(g,(f[i]*x[i],f[i]*dx+df*x[i],df*dx))]
            pair_count += 1
        polynomial = lambda t: sum(a*pow(t,j,p) for j,a in enumerate(g)) % p
        assert claim == (polynomial(0)+polynomial(1)) % p
        for t in (0,1,2,coin):
            assert polynomial(t) == sum(plan.mle(dense,coins[:k]+[t]+list(tail))*
                                        plan.mle(y,coins[:k]+[t]+list(tail))
                                        for tail in product((0,1),repeat=4-k)) % p
        claim = polynomial(coin)
        f,x = ([(a+coin*(b-a)) % p for a,b in zip(v[::2],v[1::2])] for v in (f,x))
    public = plan.rope_linear_input_form(coefficients,r,(coins[:2],coins[2:3],coins[3:]))
    endpoint = plan.mle(y,coins)
    assert pair_count == 31 and f == [public] and x == [endpoint]
    assert public and claim == public*endpoint % p != public*(endpoint+1) % p
    # Existing Y adapter: head is the FAST part of token*head, not a new PCS.
    norm = {'heads':2,'columns':4,'statistic_rows':6}
    hp,rp,cp,scale = plan.rms_output_source_point(norm,coins)
    assert (hp,rp,cp,scale) == ([],coins[2:],coins[:2],1)
    assert plan.mle(y,cp+rp) == endpoint != plan.mle(y,rp+cp)
    sources = [{'source':'RoPE_raw','operation':'q_rope','shape':(2,3,4),'word_bytes':6,'rne':True,'token_offset':0},
               {'shape':(1,6,4),'word_bytes':2,'rne':False,'token_offset':0}]
    byte_tiles,rq_tiles = plan.auxiliary_word_layout(sources)
    assert sum(h*t*d for _,_,_,h,t,d,_ in rq_tiles) == 24  # Y is not raw RQ.
    size = sum(math.prod(s['shape'])*s['word_bytes'] for s in sources)
    sigma = [0]*(1 << (size-1).bit_length())
    for i,t,c,heads,height,width,j,count,offset in byte_tiles:
        for h,a,b,l in product(range(heads),range(height),range(width),range(count)):
            value = raw[8*(t+a)+4*h+c+b] if i == 0 else y[4*(t+a)+c+b]
            word = value+(1 << (8*sources[i]['word_bytes']-1))
            sigma[offset+count*(b+width*(a+height*h))+l] = (word >> (8*(j+l))) & 255
    # Raw's head/token/column storage and Y's flattened row share ONE byte source.
    terms,bias = plan.auxiliary_probe_terms(byte_tiles,sources,
                    {0:(r[1],r[2],r[0],1),1:(hp,rp,cp,31)})
    actual = (sum(w*plan.mle(sigma[o:o+(1 << len(point))],point) for o,point,w in terms)-bias) % p
    assert actual == (plan.mle(raw,sum((list(a) for a in r),[]))+31*endpoint) % p
    # The existing T1/K1 wire is the rounded output, not the raw probe above.
    point = sum((list(a) for a in r),[])
    demand = plan.rope_output_source_point(sources[0],point)
    assert demand == (r[1],r[2],r[0],1)
    forms = plan.auxiliary_rne_forms(rq_tiles,sources,{0:[demand]},{0:30},coins)
    output_rq = [0]*32
    for _,t,c,heads,height,width,offset in rq_tiles:
        for h,a,b in product(range(heads),range(height),range(width)):
            output_rq[offset+b+width*(a+height*h)] = plan.rne_i48_to_i16(raw[8*(t+a)+4*h+c+b],30)
    incoming = plan.mle([plan.rne_i48_to_i16(v,30) for v in raw],point)
    transferred = 0
    for index,value in enumerate(output_rq):
        vertex = [(index >> k) & 1 for k in range(5)]
        weight = sum(w*plan.folded_cube_form(o,local,[1],vertex) for o,local,w in forms[30]['output']) % p
        valid = sum(w*plan.folded_cube_form(o,local,[1],vertex) for o,local,w in forms[30]['validity']) % p
        assert valid == (eq(coins,index) if index < 24 else 0)
        transferred += weight*value
    assert transferred % p == incoming != (transferred+1) % p
    for source,badpoint in ((sources[0],point[:-1]),(dict(sources[0],token_offset=7),point),
                            (dict(sources[0],operation='v_norm'),point)):
        with pytest.raises(ValueError):
            plan.rope_output_source_point(source,badpoint)
    # A product of MLEs is not the MLE of the Boolean sign/partner selector.
    rh,uh = 3,17
    assert (rh-uh) % p != (1-2*uh)*(rh*(1-uh)+(1-rh)*uh) % p
    swapped = [coefficients[1],coefficients[0],coefficients[2]]
    assert plan.rope_linear_input_form(swapped,r,(coins[:2],coins[2:3],coins[3:])) != public
    with pytest.raises(ValueError):
        plan.rope_linear_input_form(coefficients,r,(coins[:1],coins[2:3],coins[3:]))


def test_rms_statistic_cubic_sumcheck_folds_full_input_to_the_same_gamma_endpoint():
    p = plan.P
    def eq(point, index):
        return math.prod(v if index >> i & 1 else 1-v for i, v in enumerate(point)) % p
    for source_rows, selected, width in ((2, 1, 2), (3, 3, 5), (5, 4, 3), (6, 6, 2)):
        rb, sb, cb = (source_rows-1).bit_length(), (selected-1).bit_length(), (width-1).bit_length()
        rows, cols = 1 << rb, 1 << cb
        x = [[(3*r-2)*(j+1)+1 if r < source_rows and j < width else 0
              for j in range(cols)] for r in range(rows)]
        native = sum(x, [])  # lane || head || token
        statistics = [sum(v*v for v in x[r]) if r < selected else 0 for r in range(1 << sb)]
        points = [[2+i for i in range(sb)], [5+2*i for i in range(sb)]]
        weights = [1, 11]  # powers of a challenge AFTER both incoming wires
        phi = [sum(w*eq(q, r) for q, w in zip(points, weights)) % p if r < selected else 0
               for r in range(rows)]
        chi = [int(j < width) for j in range(cols)]
        claim = sum(w*plan.mle(statistics, q) for q, w in zip(points, weights)) % p
        coins = [7+2*i for i in range(rb+cb)]
        def integrand(point):
            row, col = point[:rb], point[rb:]
            return plan.mle(phi, row)*plan.mle(chi, col)*plan.mle(native, col+row)**2 % p
        def partial(prefix):
            return sum(integrand(prefix+list(tail)) for tail in
                       product((0, 1), repeat=rb+cb-len(prefix))) % p
        assert claim == partial([]) and (claim+1) % p != partial([])
        # Fill one X array row-fast, then fold in place; no second X table
        # in the mathematical prover. Dense copies here are a tiny oracle.
        buf = [x[r][j] for j in range(cols) for r in range(rows)]
        row_form, col_form = phi[:], chi[:]
        pair_count = 0
        for i, coin in enumerate(coins):
            coefficients = [0]*4
            row_round = i < rb
            form = row_form if row_round else col_form
            for offset in range(0, len(buf), 2):
                index = offset % len(form) if row_round else offset
                pair = plan.rms_square_pair_coefficients(buf[offset], buf[offset+1], form[index], form[index+1])
                include = col_form[offset//len(form)] if row_round else 1
                assert include in (0, 1)
                if include:
                    coefficients = [(a+b) % p for a, b in zip(coefficients, pair)]
                pair_count += 1
            if not row_round:
                coefficients = [a*row_form[0] % p for a in coefficients]
            def polynomial(t):
                return sum(a*pow(t, j, p) for j, a in enumerate(coefficients)) % p
            assert claim == (polynomial(0)+polynomial(1)) % p
            for t in (0, 1, 2, 3, coin):
                assert polynomial(t) == partial(coins[:i]+[t])
            claim = polynomial(coin)
            for j in range(len(buf)//2):
                buf[j] = (buf[2*j]+coin*(buf[2*j+1]-buf[2*j])) % p
            del buf[len(buf)//2:]
            for j in range(len(form)//2):
                form[j] = (form[2*j]+coin*(form[2*j+1]-form[2*j])) % p
            del form[len(form)//2:]
        assert pair_count == rows*cols-1
        rr, cc = coins[:rb], coins[rb:]
        public_row = sum(w*plan.shifted_eq_form(q, rr, 0, selected)
                         for q, w in zip(points, weights)) % p
        public_col = cols*plan.shifted_eq_form([(p+1)//2]*cb, cc, 0, width) % p
        assert (public_row, public_col) == (row_form[0], col_form[0])
        endpoint = plan.mle(native, cc+rr)
        assert buf == [endpoint]
        factor = public_row*public_col % p
        square = endpoint*endpoint % p
        assert factor and claim == factor*square % p
        assert (square+1) % p != endpoint*endpoint % p  # ProdBatch
        assert claim != factor*(square+1) % p  # final ZeroBatch
        assert (endpoint+1)**2 % p != square  # replacing just the X wire fails its product
        assert endpoint != plan.mle(native, rr+cc)  # row-fast folding is not the native point order

    # Prefix selection is a coefficient form, not permission to change X.
    assert plan.mle([1, 7], [2]) == 13 != plan.mle([1, 0], [2])
    assert plan.mle([2, 11], [2]) == 20 != plan.mle([2, 0], [2])
    q, r = [2, 3], [5, 7]
    correct = plan.shifted_eq_form(q, r, 0, 3)
    wrong = plan.mle([1, 1, 1, 0], r)*sum(eq(q, j)*eq(r, j) for j in range(4)) % p
    assert correct != wrong  # MLE of pointwise product is NOT product of MLEs
    values = [(1-t)**3 for t in range(4)]
    for _ in range(3):
        values = [b-a for a, b in zip(values, values[1:])]
    assert values == [-6]  # cubic is necessary, even for a public prefix
    # Exact toy with epsilon=0: folding inverse roots differs from taking
    # the inverse root of a folded statistic. Not a Gemma normalizer.
    folded_s = (1-2)*1+2*4
    folded_inverse_root = (1-2)*1+2*Fraction(1, 2)
    assert folded_s*folded_inverse_root**2 != 1


def test_rms_squared_midpoint_predicate_is_unique_with_exact_ties_and_overflow():
    def matches(numerator, denominator, magnitude):
        if not 0 <= magnitude <= 32767:
            return False
        if magnitude == 0:
            return 4*numerator <= denominator
        lo, hi = denominator*(2*magnitude-1)**2, denominator*(2*magnitude+1)**2
        return (lo <= 4*numerator <= hi if magnitude % 2 == 0
                else lo < 4*numerator < hi)

    # Exhaust the interval predicate independently of division/isqrt.
    for denominator in range(1, 24):
        for numerator in range(128):
            choices = [m for m in range(16) if matches(numerator, denominator, m)]
            assert choices == [plan.rne_sqrt_ratio(numerator, denominator)]
    for lower in (*range(32), 32766, 32767):
        for scale in (1, 3, 17):
            denominator = 4*scale
            for side in (-1, 0, 1):
                numerator = scale*(2*lower+1)**2+side
                expected = lower+int(side > 0 or side == 0 and lower & 1)
                assert matches(numerator, denominator, expected) == (expected <= 32767)
                if expected > 32767:
                    with pytest.raises(ValueError, match="overflows"):
                        plan.rne_sqrt_ratio(numerator, denominator)
                else:
                    assert plan.rne_sqrt_ratio(numerator, denominator) == expected
                    assert not matches(numerator, denominator, expected-1)
                    assert not matches(numerator, denominator, expected+1)
    for args in ((-1, 1), (0, 0), (1, -1), (True, 1), (1, False), (1.0, 1), (1 << 4096, 1)):
        with pytest.raises(ValueError):
            plan.rne_sqrt_ratio(*args)


def test_rms_scalar_exact_output_preserves_epsilon_exponents_sign_and_integer_order():
    # Independent honest algorithm: 15 fixed binary decisions, one midpoint
    # comparison. No isqrt, division or floating-point reference.
    def binary_reference(ratio):
        numerator, denominator = ratio.numerator, ratio.denominator
        if 4*numerator >= 65535**2*denominator:
            return None
        lower = 0
        for bit in reversed(range(15)):
            trial = lower+(1 << bit)
            if trial*trial*denominator <= numerator:
                lower = trial
        middle = denominator*(2*lower+1)**2
        return lower+int(4*numerator > middle or 4*numerator == middle and lower & 1)

    cases = []
    for width in (1, 2, 3, 256, 512, 5376):
        for x, w in ((0, 0), (1, 1), (-1, 257), (32767, 32767), (-32767, 32767)):
            for exponents in ((0, 0, 0), (-10, -14, -8), (-12, 0, -10), (10, -5, 7)):
                cases.append((x*w, width*x*x, width, *exponents))
    rng = random.Random(714)
    for _ in range(250):
        row = [rng.randrange(-12, 13) for _ in range(rng.randrange(1, 8))]
        w = rng.randrange(-17, 18)
        cases.append((row[0]*w, sum(x*x for x in row), len(row), *(rng.randrange(-12, 9) for _ in range(3))))
    cases += [(1, 1, 256, 1000, -1000, 0), (1, 1, 512, -1000, 1000, 0)]
    for product_value, statistic, width, ex, ew, ey in cases:
        a, b, c = plan.rms_integer_coefficients(width, ex, ew, ey)
        ratio = (Fraction(product_value**2)*Fraction(2)**(2*(ex+ew-ey)) /
                 (Fraction(1, 1_000_000)+Fraction(statistic, width)*Fraction(2)**(2*ex)))
        assert ratio == Fraction(a*product_value**2, b+c*statistic)
        assert math.gcd(a, b, c) == 1 and min(a, b, c) > 0
        expected = binary_reference(ratio)
        if expected is None:
            with pytest.raises(ValueError, match="overflows"):
                plan.rms_rne_i16(product_value, statistic, width, ex, ew, ey)
        else:
            actual = plan.rms_rne_i16(product_value, statistic, width, ex, ew, ey)
            assert actual == (-expected if product_value < 0 else expected)
            assert plan.rms_rne_i16(-product_value, statistic, width, ex, ew, ey) == -actual
    # One nonzero input in a 256-lane head. Rounding the mean to an integer
    # or rounding the inverse root first changes the pinned real expression.
    assert plan.rms_rne_i16(1, 1, 256, 0, 0, 0) == 16
    assert plan.rms_rne_i16(1, 0, 256, 0, 0, 0) == 1000  # false S is not fixed by range checks
    assert plan.rms_rne_i16(257, 1, 256, 0, 0, 0) == 4111 != 257*16
    assert plan.rms_rne_i16(0, 1, 256, 0, 0, 0) == plan.rms_rne_i16(0, 2, 256, 0, 0, 0)

    # Goldilocks has 2^192 == 1. At e_w=96, reducing the integer
    # comparisons modulo p accepts magnitude 16 although true RNE overflows.
    a, b, c = plan.rms_integer_coefficients(256, 0, 96, 0)
    numerator, denominator = a, b+c
    assert pow(2, 192, plan.P) == 1
    lo, hi = denominator*31**2, denominator*33**2
    assert lo % plan.P <= 4*numerator % plan.P <= hi % plan.P
    assert 4*numerator > hi
    with pytest.raises(ValueError, match="overflows"):
        plan.rms_rne_i16(1, 1, 256, 0, 96, 0)
    a, b, c = plan.rms_integer_coefficients(5376, 0, 0, 0)
    assert max((4*a*32767**4).bit_length(), ((b+c*5376*32767**2)*65535**2).bit_length()) == 89
    # Public parameter validation precedes any secret-dependent shortcut.
    for args in ((0, 0, 0, 0), (5377, 0, 0, 0), (256, True, 0, 0),
                 (256, 0, None, 0), (256, 0, 0, 10**100)):
        with pytest.raises(ValueError):
            plan.rms_integer_coefficients(*args)
    for product_value, statistic in ((32767**2+1, 0), (0, -1), (0, 256*32767**2+1), (True, 0)):
        with pytest.raises(ValueError):
            plan.rms_rne_i16(product_value, statistic, 256, 0, 0, 0)
    with pytest.raises(ValueError, match="local 4096-bit"):
        plan.rms_rne_i16(0, 0, 256, 0, 10**100, 0)


@pytest.mark.parametrize('columns,ex,ew,ey,weighted,counts', [
    (5376, 0, 0, 0, True, (151903, 962, 46712, 98)),
    (256, 0, 0, 0, False, (139419, 904, 39971, 97)),
    (256, 0, 0, 4, True, None),
    (512, -2, 0, -1, False, None),
])
def test_rms_boolean_dags_match_exact_scalar_and_reject_altered_outputs(columns, ex, ew, ey, weighted, counts):
    # Compile ONLY from public parameters; evaluate the same DAG on all inputs.
    computed, checked = [plan.rms_boolean_circuit(columns, ex, ew, ey, weighted, verify)
                         for verify in (False, True)]
    for circuit in (computed, checked):
        summary = circuit['summary']
        assert not summary['credit'] and summary['complete_mac_records_memory_and_feasibility'] is None
        assert summary['requires_copy_wires_or_general_dag_reduction']
        assert summary['requires_separately_bound_candidate_y'] == summary['verify_output']
        assert sum(summary['binary_gates_by_op'].values()) == len(circuit['gates'])
        assert len({(op,min(x,y),max(x,y)) for op,x,y in circuit['gates']}) == len(circuit['gates'])
        for wire, (op, x, y) in enumerate(circuit['gates'], 2+circuit['input_bits']):
            assert op in ('and', 'xor') and 0 <= x < wire and 0 <= y < wire
    if counts:
        assert tuple(c['summary'][key] for c in (computed, checked)
                     for key in ('binary_gate_count', 'generated_dag_depth')) == counts
        assert computed['summary']['total_arithmetic_bits'] == checked['summary']['total_arithmetic_bits'] == 95

    def evaluate(circuit, p_value, s_value, candidate=None):
        words = [(p_value, circuit['product_bits']), (s_value, 48)]
        if candidate is not None:
            words.append((candidate, 16))
        values = [0, 1]
        for value, bits in words:
            assert -(1 << (bits-1)) <= value < 1 << (bits-1)
            biased = value+(1 << (bits-1))
            values.extend((biased >> i) & 1 for i in range(bits))
        assert len(values) == circuit['input_bits']+2
        for op, x, y in circuit['gates']:
            values.append(values[x] & values[y] if op == 'and' else values[x] ^ values[y])
        output = sum(values[wire] << i for i, wire in enumerate(circuit['output_wires']))-32768
        return values[circuit['valid_wire']], output

    pw = computed['product_bits']
    limit = 32767**2 if weighted else 32767
    smax = columns*32767**2
    cases = [(0, 0), (1, 0), (3, 0), (-1, 0), (-3, 0), (1, 1), (257, 1), (-257, 1),
             (limit, smax), (-limit, smax), (32767, 0), (0, -1), (0, smax+1),
             (0, -(1 << 47)), (0, (1 << 47)-1), (-limit-1, 0),
             (-(1 << (pw-1)), 0), ((1 << (pw-1))-1, (1 << 47)-1)]
    if weighted:
        cases.append((limit+1, 0))
    rng = random.Random(715)
    cases += [(rng.randrange(-limit, limit+1), rng.randrange(smax+1)) for _ in range(8)]
    for p_value, s_value in cases:
        expected = None
        if -limit <= p_value <= limit and 0 <= s_value <= smax:
            try:
                expected = plan.rms_rne_i16(p_value, s_value, columns, ex, ew, ey)
            except ValueError as error:
                assert 'overflows' in str(error)
        assert evaluate(computed, p_value, s_value) == (int(expected is not None), expected or 0)
        candidates = {-32768, -1, 0, 1, 32767}
        if expected is not None:
            candidates.update((expected, -expected, expected-1, expected+1))
        for candidate in candidates:
            if -32768 <= candidate <= 32767:
                valid, alias = evaluate(checked, p_value, s_value, candidate)
                assert alias == candidate  # predicate input alias, not a new Y source
                assert valid == int(candidate == expected)
    if (ex, ew, ey) == (0, 0, 4):
        # Arithmetic stress cases: S=0/P!=0 need not be a valid model witness.
        assert evaluate(computed, 1, 0) == (1, 62)  # 62.5 -> even below
        assert evaluate(computed, 3, 0) == (1, 188)  # 187.5 -> even above
        assert evaluate(computed, -1, 0) == (1, -62)
        assert evaluate(computed, -3, 0) == (1, -188)


def test_rms_boolean_scope_caps_and_literal_cohort_certificate_exclusion():
    # Square's diagonal + shifted upper triangle, including truncated products.
    # This independent integer identity also covers constant/zero input bits.
    for word in range(256):
        diagonal = sum((word >> i & 1) << (2*i) for i in range(8))
        triangle = sum(((word >> i & 1)*(word >> j & 1)) << (i+j+1)
                       for i in range(8) for j in range(i+1,8))
        assert diagonal+triangle == word*word
        for bits in range(1,17):
            grouped = [sum((word >> i & 1) << (2*i) for i in range(8) if 2*i < bits)]
            grouped += [sum(((word >> i & 1)*(word >> j & 1)) << (i+j+1)
                            for j in range(i+1,min(8,bits-i-1))) for i in range(8) if 2*i+2 < bits]
            assert sum(grouped) % (1 << bits) == word*word % (1 << bits)
    for args in ((256, 0, 0, 0, 1), (256, 0, 0, 0, True, 1),
                 (256, 0, 1, 0, False), (0, 0, 0, 0), (256, True, 0, 0)):
        with pytest.raises(ValueError):
            plan.rms_boolean_circuit(*args)
    with pytest.raises(ValueError, match='local 128-bit'):
        plan.rms_boolean_circuit(256, 0, 96, 0)
    with pytest.raises(ValueError, match='local 4096-bit'):
        plan.rms_boolean_circuit(256, 0, 10**100, 0)

    # At P=y=0 both total circuits' validity equals this range guard.
    # Exhibit a pair differing in each of its 48 input bits: binary depth>=6.
    for columns in (256, 512, 5376):
        bound = columns*32767**2
        # Repair: signed storage ranges plus source-equality and W/X range
        # premises suffice for integer lifting; SG is not a premise here.
        assert (1 << 47)+bound < (1 << 48) < plan.P
        assert (1 << 31)+32767**2 < (1 << 32) < plan.P
        for x, w in product((-32767, 0, 32767), repeat=2):
            exact_p, exact_s = x*w, columns*x*x
            for stored in (-(1 << 31), -1, 0, exact_p, exact_p+1, (1 << 31)-1):
                assert ((stored-exact_p) % plan.P == 0) == (stored == exact_p)
            for stored in (-(1 << 47), -1, 0, exact_s, exact_s+1, (1 << 47)-1):
                assert ((stored-exact_s) % plan.P == 0) == (stored == exact_s)
            assert 0 <= exact_s <= bound and abs(exact_p) <= 32767**2
        def guard(biased):
            return bool(biased >> 47) and (biased & ((1 << 47)-1)) <= bound
        for bit in range(47):
            low, high = ((bound+1-(1 << bit), bound+1) if bound >> bit & 1
                         else (bound, bound+(1 << bit)))
            assert 0 <= low < high < 1 << 47 and low ^ high == 1 << bit
            assert guard(low+(1 << 47)) and not guard(high+(1 << 47))
        assert guard((1 << 47)+bound) and not guard(bound)
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           'manifests/c7-d126-gemma31b-source-metadata-v1.json').read_bytes())
    cohorts = plan.gemma_weight_cohorts([t for t in metadata['tensors'] if t['disposition'] == 'private_text'])
    s = plan.rms_boolean_cohort_screen(cohorts)
    assert (s['norm_cohorts'], s['minimum_cell_bits_sum'], s['native_cell_bits_sum']) == (421, 8470, 8711)
    assert s['minimum_binary_depth_from_input_guard'] == (48-1).bit_length() == 6
    assert s['coefficient_payload_lower_bound'] == 4878720
    assert s['excludes_gate_axes_terminal_messages_and_incoming_claims']
    assert not s['excludes_joint_reductions_or_guard_reuse']
    assert s['complete_rms_mac_feasibility'] is None and not s['credit']
    current = plan.rms_byte_bridge_screen(cohorts)['cases'][-1]
    assert current['known_partial_payload_before_rms_circuit_gamma_and_framing']+s['coefficient_payload_lower_bound'] == 37286376 > 35000000


def test_rms_live_wire_layering_preserves_outputs_and_counts_joint_profiles():
    def evaluate(op, x, y):
        return x & y if op == 'and' else x ^ y if op == 'xor' else x
    expected = {False: (962, 9433, 46764, 168190, 4105824, 122388),
                True: (98, 902, 4646, 16780, 409776, 12232)}
    for verify in (False, True):
        profiles = []
        for weighted, columns in ((True, 256), (True, 512), (True, 5376), (False, 256), (False, 512)):
            circuit = plan.rms_boolean_circuit(columns, 0, 0, 0, weighted, verify)
            layered = plan.rms_layered_circuit(circuit)
            summary = layered['summary']
            profiles.append(summary['level_widths'])
            assert not summary['credit'] and summary['complete_replicated_trace_memory_or_work'] is None
            assert summary['expanded_layer_rows'] == sum(map(len,layered['levels']))
            assert summary['expanded_layer_rows'] == summary['copy_gates']+summary['reachable_binary_gates']
            assert summary['reachable_binary_gates'] < len(circuit['gates'])  # dead public-folding work removed
            previous_width = layered['input_ports']
            for layer in layered['levels']:
                assert all(op in ('and', 'xor', 'copy') and 0 <= a < previous_width and 0 <= b < previous_width
                           for op, a, b in layer)
                previous_width = len(layer)
            for p_value, s_value, y in ((0, 0, 0), (-1, 0, -1000), (3, 1, -32768)):
                words = [(p_value, circuit['product_bits']), (s_value, 48)]+([(y, 16)] if verify else [])
                inputs = [0, 1]+[(value+(1 << (bits-1))) >> i & 1 for value, bits in words for i in range(bits)]
                original = inputs[:]
                for op, a, b in circuit['gates']:
                    original.append(evaluate(op, original[a], original[b]))
                current = inputs
                for layer in layered['levels']:
                    current = [evaluate(op, current[a], current[b]) for op, a, b in layer]
                roots = [circuit['valid_wire']]+([] if verify else circuit['output_wires'])
                assert [current[i] for i in layered['output_positions']] == [original[w] for w in roots]
        screen = plan.rms_joint_gkr_screen(profiles, 29)
        assert tuple(screen[k] for k in ('depth', 'gate_index_bits_sum', 'sumcheck_rounds',
                     'sumcheck_coefficients', 'payload_before_incoming_input_adapters_and_shared_closures',
                     'interactive_transfer_numerator_before_input_adapters')) == expected[verify]
        assert screen['endpoint_corrections'] == 2*screen['private_product_equations'] == 2*screen['depth']
        assert screen['zero_residual_equations_before_input_adapters'] == screen['sumcheck_rounds']+screen['depth']
        assert screen['endpoint_batch_challenges'] == screen['depth']
        assert screen['reference_folded_array_bytes'] == 24*(1 << 21)
        assert screen['reference_two_gate_vectors_bytes'] == (196608 if verify else 98304)
        assert screen['reference_input_tuple_visits'] == (1784 if verify else 18091)
        assert screen['plaintext_and_tag_records_bytes'] == 2*screen['payload_before_incoming_input_adapters_and_shared_closures']
        assert screen['complete_input_forms_and_source_bindings'] is screen['complete_witness_schedule_memory_and_work'] is None
        assert not screen['credit']
        packed = screen['bitpacked_replay']
        assert not packed['credit'] and packed['requires_64_cell_aligned_profile_blocks']
        assert packed['complete_sumcheck_field_work_and_runtime'] is None
        if verify:
            assert packed['word_gate_or_copy_steps_upper'] == 717119708725248
            assert packed['input_bit_transpositions_upper'] == 91946659872768
            assert packed['fold_table_lookups_upper'] == 178520047222784
            assert packed['fold_high_prefix_products_upper'] == 9245638524928
            assert packed['fold_chunk_additions_upper'] == 77062761086976
            assert packed['fold_high_prefix_accumulations_upper'] == packed['fold_high_prefix_products_upper']
            assert packed['fold_table_preparation_products_upper'] == 392196
            assert packed['fold_table_preparation_additions_upper'] == 115542
            assert packed['input_and_two_word_vectors_bytes'] == 66560
            assert packed['field_block_bytes'] == 6291456
            assert packed['public_fold_table_reservation_bytes'] == 65536
            # 3,612 public Y cubes are independently checked against pinned metadata below.
            field = plan.rms_gkr_field_work_screen(screen,3612)
            assert sum(screen['joint_level_rows_across_profiles'][1:]) == 399038
            assert field['cell_pair_gate_terms'] == 214231894583618
            assert field['products_upper_by_stage']['cell_coefficients'] == 2570782735003416
            assert field['products_upper_by_stage']['profile_sweep'] == 736586884698
            assert field['products_upper_by_stage']['array_folds'] == 205641450
            assert field['products_upper_by_stage']['high_prefix_weights'] == 16785264640
            assert field['combined_clear_replay_and_sumcheck_products_upper'] == 2580782639346704
            assert field['combined_clear_replay_and_sumcheck_additions_upper'] == 3942483663846463
            assert field['additional_public_sweep_and_gate_form_bytes'] == 394496
            assert not field['credit'] and field['complete_getter_mac_fs_runtime_and_liveness'] is None
            aligned = plan.rms_gkr_aligned_word_screen(screen,field)
            assert aligned['first_round_word_gate_terms_upper'] == 725262270464
            assert aligned['rounds_1_to_5_gate_pair_terms_upper'] == 22483130384384
            assert aligned['remaining_cell_gate_pair_terms_upper'] == 3347372960066
            assert aligned['combined_clear_replay_and_sumcheck_products_upper'] == 326494949181128
            assert aligned['combined_clear_replay_and_sumcheck_additions_upper'] == 570840702874249
            assert aligned['fold_table_lookups_upper'] == 143655381762048
            assert aligned['additional_split_and_gate_word_steps_upper'] == 26861555941376
            assert aligned['additional_scratch_bytes'] == 0 and aligned['reference_input_tuple_visits'] == 1784
            assert not aligned['credit'] and aligned['requires_64_cell_aligned_homogeneous_profiles']
            assert aligned['complete_getter_mac_fs_runtime_and_liveness'] is None
    for widths, bits in (([], 2), ([[]], 2), ([[0]], 2), ([[True]], 2), ([[1]], 0)):
        with pytest.raises(ValueError):
            plan.rms_joint_gkr_screen(widths, bits)
    malformed = {'input_bits': 1, 'gates': [('and', 2, 3)], 'valid_wire': 3,
                 'output_wires': [], 'summary': {'verify_output': True}}
    with pytest.raises(ValueError, match='topological'):
        plan.rms_layered_circuit(malformed)


def test_joint_rms_gkr_shares_cells_carries_wires_and_transfers_to_the_same_inputs():
    p = plan.P
    def eq(point, index):
        return math.prod(v if index >> i & 1 else 1-v for i, v in enumerate(point)) % p
    def poly(samples):
        coefficients = [0]*len(samples)
        for j, value in enumerate(samples):
            basis, denominator = [1], 1
            for k in range(len(samples)):
                if j == k:
                    continue
                basis = [(a-k*b) % p for a, b in zip([0]+basis, basis+[0])]
                denominator = denominator*(j-k) % p
            scale = value*pow(denominator, -1, p) % p
            coefficients = [(a+scale*b) % p for a, b in zip(coefficients, basis)]
        return coefficients
    circuits = [
        {'input_bits': 3, 'gates': [('and', 2, 3), ('xor', 5, 4), ('and', 6, 2), ('xor', 2, 3)],
         'valid_wire': 7, 'output_wires': [], 'summary': {'verify_output': True}},
        {'input_bits': 3, 'gates': [('xor', 2, 3), ('and', 5, 4)],
         'valid_wire': 6, 'output_wires': [], 'summary': {'verify_output': True}},
    ]
    lowered = [plan.rms_layered_circuit(c) for c in circuits]
    screen = plan.rms_joint_gkr_screen([c['summary']['level_widths'] for c in lowered], 2)
    widths = [1 << (w-1).bit_length() for w in screen['joint_level_widths']]
    programs = []
    for c in lowered:
        layers = c['levels'][:]
        while len(layers) < screen['depth']:
            layers.append([('copy', i, i) for i in range(len(layers[-1]))])
        programs.append(layers)
    assignments = [0, 1, 0, None]  # two noncontiguous cohorts of profile 0, plus public padding
    cells = [[0, 1, 1, 1, 0], [0, 1, 1, 0, 1], [0, 1, 0, 1, 1], [0]*5]
    tables = [[row+[0]*(widths[0]-len(row)) for row in cells]]
    for level in range(screen['depth']):
        following = []
        for row, program in zip(tables[-1], assignments):
            layer = [] if program is None else programs[program][level]
            values = [(row[a]*row[b] if op == 'and' else row[a]+row[b]-2*row[a]*row[b]
                       if op == 'xor' else row[a]) % p for op, a, b in layer]
            following.append(values+[0]*(widths[level+1]-len(values)))
        tables.append(following)
    # Packed replay + field fold produces the SAME tables used in every
    # cubic/quadratic sumcheck below, including mixed profiles and padding.
    for level, table in enumerate(tables):
        packed = [0]*widths[level]
        for t, circuit in enumerate(lowered):
            mask = sum(1 << i for i,role in enumerate(assignments) if role == t)
            planes = [sum(row[j] << i for i,row in enumerate(cells) if assignments[i] == t)
                      for j in range(circuit['input_ports'])]
            values = plan.rms_bitpacked_replay(circuit,planes,min(level,len(circuit['levels'])),mask)
            for j,word in enumerate(values):
                packed[j] |= word  # disjoint public profile masks
        assert [[word >> i & 1 for word in packed] for i in range(len(cells))] == table
        for j,word in enumerate(packed):
            assert plan.fold_boolean_word(word,plan.boolean_word_fold_tables([2,5]))[0] == plan.mle([r[j] for r in table],[2,5])
    assert tables[-1] == [[1], [1], [0], [0]]
    point, gate_form = [2, 5], [1]
    claim = plan.mle(sum(tables[-1], []), point)
    assert claim != plan.mle([1, 1, 1, 0], point)  # one invalid live cell cannot be omitted
    coefficients_sent = rounds = 0
    for level in reversed(range(1, screen['depth']+1)):
        s = (widths[level-1]-1).bit_length()
        source = sum(tables[level-1], [])  # gate || cell
        profile_forms = [[eq(point, cell) if program == t else 0 for cell, program in enumerate(assignments)]
                         for t in range(len(programs))]
        def kernels(c, a, b):
            result = [0, 0, 0]
            for t, layers in enumerate(programs):
                weight = plan.mle(profile_forms[t], c)
                for gate, (op, left, right) in enumerate(layers[level-1]):
                    factor = weight*gate_form[gate]*eq(a, left)*eq(b, right) % p
                    terms = (0, 0, 1) if op == 'and' else (1, 1, -2) if op == 'xor' else (1, 0, 0)
                    result = [(v+factor*k) % p for v, k in zip(result, terms)]
            return result
        def integrand(q):
            c, a, b = q[:2], q[2:2+s], q[2+s:]
            ka, kb, kc = kernels(c, a, b)
            left, right = plan.mle(source, a+c), plan.mle(source, b+c)
            return (ka*left+kb*right+kc*left*right) % p
        def partial(prefix):
            return sum(integrand(prefix+list(tail)) for tail in product((0, 1), repeat=2+2*s-len(prefix))) % p
        assert claim == partial([]) and (claim+1) % p != partial([])
        coins = [7+3*i+level for i in range(2+2*s)]
        for i, coin in enumerate(coins):
            degree = 3 if i < 2 else 2
            samples = [partial(coins[:i]+[t]) for t in range(degree+1)]
            coefficients = poly(samples)
            # Sparse honest coefficients, using the same source/psi as F.
            h = min(i,2)
            events = iter(plan.rms_gkr_profile_events([(0,0,0),(1,0,1),(2,0,0)],point,coins[:h]))
            event, active, psi = next(events,None), [0]*len(programs), []
            for z in range(1 << (2-h)):
                while event is not None and event[0] <= z:
                    active[event[1]] = (active[event[1]]+event[2]) % p
                    event = next(events,None)
                psi.append([eq(point[h:],z)*v % p for v in active])
                c = coins[:h]+[z >> j & 1 for j in range(2-h)]
                assert psi[-1] == [plan.mle(form,c) for form in profile_forms]
            sparse = [0]*4
            if i < 2:
                for z in range(1 << (1-i)):
                    pair = [[plan.mle([row[j] for row in tables[level-1]],
                             coins[:i]+[b]+[z >> k & 1 for k in range(1-i)])
                             for j in range(widths[level-1])] for b in (0,1)]
                    for t,layers in enumerate(programs):
                        for g,(op,j,k) in enumerate(layers[level-1]):
                            edge = plan.rms_gkr_cell_pair_coefficients(op,pair[0][j],pair[1][j],
                                pair[0][k],pair[1][k],psi[2*z][t],psi[2*z+1][t],gate_form[g])
                            sparse = [(a+b) % p for a,b in zip(sparse,edge)]
            else:
                f = [plan.mle([row[j] for row in tables[level-1]],coins[:2]) for j in range(widths[level-1])]
                right_axis = i >= 2+s
                h = i-2-(s if right_axis else 0)
                a, b = coins[2:2+s], coins[2+s:]
                for t,layers in enumerate(programs):
                    for g,(op,j,k) in enumerate(layers[level-1]):
                        index, prefix = (k,b[:h]) if right_axis else (j,a[:h])
                        values = [plan.mle(f,prefix+[v]+[index >> q & 1 for q in range(h+1,s)]) for v in (0,1)]
                        x0,x1,y0,y1 = ((plan.mle(f,a),)*2+tuple(values) if right_axis else (*values,f[k],f[k]))
                        factor = psi[0][t]*gate_form[g]*eq(prefix,index) % p
                        if right_axis:
                            factor = factor*eq(a,j) % p
                        bit = index >> h & 1
                        edge = plan.rms_gkr_cell_pair_coefficients(op,x0,x1,y0,y1,1-bit,bit,factor)
                        assert edge[3] == 0
                        sparse = [(a+b) % p for a,b in zip(sparse,edge)]
            assert sparse[:degree+1] == coefficients
            def value(t):
                return sum(v*pow(t, j, p) for j, v in enumerate(coefficients)) % p
            assert claim == (value(0)+value(1)) % p
            assert value(coin) == partial(coins[:i+1])
            assert value(degree+1) == partial(coins[:i]+[degree+1])
            claim = value(coin)
            coefficients_sent += degree+1
            rounds += 1
        c, a, b = coins[:2], coins[2:2+s], coins[2+s:]
        left, right = plan.mle(source, a+c), plan.mle(source, b+c)
        ka, kb, kc = kernels(c, a, b)
        product_value = left*right % p
        assert claim == (ka*left+kb*right+kc*product_value) % p
        assert (product_value+1) % p != left*right % p
        beta = 13+level  # after BOTH endpoint records and the product record
        claim = (left+beta*right) % p
        point, gate_form = c, [(eq(a, j)+beta*eq(b, j)) % p for j in range(widths[level-1])]
        assert claim == sum(eq(point, i)*gate_form[j]*row[j]
                            for i, row in enumerate(tables[level-1]) for j in range(widths[level-1])) % p
        # If beta is known early, wrong endpoints can preserve their mixed claim.
        assert (left+1+beta*(right-pow(beta,-1,p))) % p == claim
    assert rounds == screen['sumcheck_rounds'] and coefficients_sent == screen['sumcheck_coefficients']
    assert claim == sum(eq(point, i)*gate_form[j]*row[j] for i, row in enumerate(tables[0])
                        for j in range(widths[0])) % p  # SAME input table, not a trace PCS
    assert sum((1+3*beta) % 7 == 0 for beta in range(7)) == 1
    # Profile selection must be inside the MLE, not multiplied after folding.
    selector, r, u = [1, 0, 1, 0], [2, 3], [5, 7]
    correct = plan.mle([selector[i]*eq(r, i) % p for i in range(4)], u)
    wrong = plan.mle(selector, u)*sum(eq(r, i)*eq(u, i) for i in range(4)) % p
    assert correct != wrong
    by_intervals = sum(plan.shifted_eq_form(r, u, 0, i+1)-plan.shifted_eq_form(r, u, 0, i)
                       for i in (0, 2)) % p
    assert by_intervals == correct


def test_rms_public_profile_sweep_and_clear_field_accounting():
    rng = random.Random(7171)
    for op in ('and','xor','copy'):
        for _ in range(12):
            x0,x1,y0,y1,f0,f1,w = [rng.randrange(plan.P) for _ in range(7)]
            coeff = plan.rms_gkr_cell_pair_coefficients(op,x0,x1,y0,y1,f0,f1,w)
            for t in (0,1,2,3,5):
                x,y,f = x0+t*(x1-x0), y0+t*(y1-y0), f0+t*(f1-f0)
                gate = x*y if op == 'and' else x+y-2*x*y if op == 'xor' else x
                assert sum(c*pow(t,j,plan.P) for j,c in enumerate(coeff)) % plan.P == w*f*gate % plan.P
    intervals = [(0,2,0),(4,1,1),(6,0,0),(8,3,1)]  # cell 7 is padding
    for r,a in (([2,3,5,7],[11,13,17,19]), ([0,1,0,1],[1,0,1,0])):
        dense = [[0]*16 for _ in range(2)]
        for start,d,t in intervals:
            for c in range(start,start+(1 << d)):
                dense[t][c] = math.prod(v if c >> i & 1 else 1-v for i,v in enumerate(r)) % plan.P
        for h in range(5):
            events = plan.rms_gkr_profile_events(intervals,r,a[:h])
            assert len(events) == 2*len(intervals)
            weights, cursor = [0,0], 0
            for c in range(1 << (4-h)):
                while cursor < len(events) and events[cursor][0] <= c:
                    _,t,v = events[cursor]
                    weights[t] = (weights[t]+v) % plan.P
                    cursor += 1
                eq = math.prod(v if c >> i & 1 else 1-v for i,v in enumerate(r[h:])) % plan.P
                point = a[:h]+[c >> i & 1 for i in range(4-h)]
                assert [eq*v % plan.P for v in weights] == [plan.mle(row,point) for row in dense]
    for bad in ([(1,1,0)], [(0,2,0),(2,0,1)], [(4,0,0),(0,0,0)], [(16,0,0)], [(0,5,0)], [(0,0,True)]):
        with pytest.raises(ValueError):
            plan.rms_gkr_profile_events(bad,[2]*4,[3])
    for r,a in (([],[]), ([2],[3,5]), ([True],[]), ([2],[-1])):
        with pytest.raises(ValueError):
            plan.rms_gkr_profile_events([],r,a)
    with pytest.raises(ValueError):
        plan.rms_gkr_cell_pair_coefficients('bad',0,1,0,1,0,1,1)
    for bad in (-1,plan.P,True):
        with pytest.raises(ValueError):
            plan.rms_gkr_cell_pair_coefficients('and',bad,1,0,1,0,1,1)
    # One edge, two cells, one gate-index bit: hand count, not the large profile constants.
    small = plan.rms_gkr_field_work_screen(plan.rms_joint_gkr_screen([[2,1]],1),1)
    assert small['cell_pair_gate_terms'] == 1
    assert small['products_upper_by_stage']['index_coefficients'] == 30
    assert sum(small['products_upper_by_stage'].values()) == 78
    assert sum(small['additions_upper_by_stage'].values()) == 98
    assert small['combined_clear_replay_and_sumcheck_products_upper'] == 80
    assert small['combined_clear_replay_and_sumcheck_additions_upper'] == 99
    for bad in (-1,True):
        with pytest.raises(ValueError):
            plan.rms_gkr_field_work_screen(plan.rms_joint_gkr_screen([[2,1]],1),bad)


def test_bitpacked_replay_and_public_word_fold_preserve_all_low_prefixes():
    rng = random.Random(7164)
    words = [0, (1 << 64)-1, 1, 1 << 63, 0x0123456789ABCDEF]+[rng.getrandbits(64) for _ in range(20)]
    for point in ([2,3,5,7,11,13], [0]*6, [1]*6, [0,1,0,1,2,3]):
        for h in range(7):
            tables = plan.boolean_word_fold_tables(point[:h])
            assert sum(map(len,tables)) <= 2048
            for word in words:
                bits = [word >> j & 1 for j in range(64)]
                expected = [plan.mle(bits[j:j+(1 << h)],point[:h]) for j in range(0,64,1 << h)]
                assert plan.fold_boolean_word(word,tables) == expected
    # Four aligned words, followed by the remaining two prefix coordinates.
    point = [2,3,5,7,11,13,17,19]
    tables = plan.boolean_word_fold_tables(point[:6])
    folded = [plan.fold_boolean_word(word,tables)[0] for word in words[:4]]
    assert plan.mle(folded,point[6:]) == plan.mle([word >> j & 1 for word in words[:4] for j in range(64)],point)
    # Real RMS predicate, with unused physical bits ZERO, not biased-zero words.
    circuit = plan.rms_layered_circuit(plan.rms_boolean_circuit(256,0,0,0,False,True))
    cases = [(0,0,0), (1,0,1000), (-1,0,-1000), (1,1,16), (1,1,17), (-32768,0,0), (0,-1,0)]
    rows = [[0,1]+[(v+(1 << (size-1))) >> j & 1 for v,size in zip(row,(16,48,16)) for j in range(size)] for row in cases]
    planes = [sum(row[j] << i for i,row in enumerate(rows)) for j in range(circuit['input_ports'])]
    live = (1 << len(cases))-1
    packed = plan.rms_bitpacked_replay(circuit,planes,len(circuit['levels']),live)
    assert packed == [15]
    assert plan.rms_bitpacked_replay(circuit,planes,0,live) == planes
    for bad in ([*planes[:2], 1 << 63, *planes[3:]], [0,(1 << 64)-1,*planes[2:]], [0,live,True,*planes[3:]], planes[:-1]):
        with pytest.raises(ValueError):
            plan.rms_bitpacked_replay(circuit,bad,1,live)
    with pytest.raises(ValueError):
        plan.rms_bitpacked_replay(circuit,planes,len(circuit['levels'])+1,live)
    # Gate evaluation AFTER folding is wrong even for AND on two equal bit planes.
    tiny = {'input_ports': 4, 'levels': [[('and',2,3)]]}
    result = plan.rms_bitpacked_replay(tiny,[0,3,2,2],1,3)[0]
    table = plan.boolean_word_fold_tables([2])
    assert plan.fold_boolean_word(result,table)[0] == 2 != 2*2
    for op,a,b in (('invalid',2,3), ('copy',2,3), ('and',-1,3)):
        with pytest.raises(ValueError):
            plan.rms_bitpacked_replay({**tiny,'levels':[[(op,a,b)]]},[0,3,2,2],1,3)
    for point in ([2]*7, [True], [-1], [plan.P]):
        with pytest.raises(ValueError):
            plan.boolean_word_fold_tables(point)
    for word,tables in ((True,table), (-1,table), (1 << 64,table), (0,[]), (0,[[0,1]]*2)):
        with pytest.raises(ValueError):
            plan.fold_boolean_word(word,tables)
    for width in (1,2,4,8,16,32,64):
        word = rng.getrandbits(width)
        for h in range(width.bit_length()):
            point = [2,3,5,7,11,13][:h]
            got = plan.fold_boolean_word(word,plan.boolean_word_fold_tables(point),width)
            assert got == [plan.mle([word >> (i+j) & 1 for j in range(1 << h)],point)
                           for i in range(0,width,1 << h)]
    for width,word,tables in ((True,0,table), (3,0,table), (32,1 << 32,table), (32,0,plan.boolean_word_fold_tables([2]*6))):
        with pytest.raises(ValueError):
            plan.fold_boolean_word(word,tables,width)


def test_rms_first_word_moments_and_profile_pruning_preserve_cell_rounds():
    rng, p = random.Random(7172), plan.P
    def eq(point,index):
        return math.prod(v if index >> i & 1 else 1-v for i,v in enumerate(point)) % p
    full = (1 << 64)-1
    words = [0,full]+[1 << i for i in range(64)]+[rng.getrandbits(64) for _ in range(12)]
    for word in words:
        assert plan.split_boolean_word(word) == tuple(sum((word >> (2*i+b) & 1) << i for i in range(32)) for b in (0,1))
    for op in ('and','xor','copy'):
        for point in ([2,3,5,7,11,13], [0]*6, [1]*6, [0,1,2,3,0,1]):
            x,y = rng.getrandbits(64), rng.getrandbits(64)
            tables, expected = plan.boolean_word_fold_tables(point[1:]), [0]*4
            for c in range(32):
                edge = plan.rms_gkr_cell_pair_coefficients(op,x >> (2*c) & 1,x >> (2*c+1) & 1,
                    y >> (2*c) & 1,y >> (2*c+1) & 1,eq(point,2*c),eq(point,2*c+1),17)
                expected = [(a+b) % p for a,b in zip(expected,edge)]
            assert plan.rms_gkr_first_word_coefficients(op,plan.split_boolean_word(x),plan.split_boolean_word(y),tables,point[0],17,full) == expected
    # One shared-cell layer: two 64-cell profiles followed by two dummy words.
    point, coins, ops = [2,3,5,7,11,13,17,19], [23,29,31,37,41,43,47,53], ['and','xor']
    roles = [0]*64+[1]*64+[None]*128
    values = [[rng.randrange(2) if c < 128 else 0 for c in range(256)] for _ in range(2)]
    forms = [[eq(point,c) if role == t else 0 for c,role in enumerate(roles)] for t in range(2)]
    claim = sum(eq(point,c)*17*(values[0][c]*values[1][c] if role == 0 else values[0][c]^values[1][c])
                for c,role in enumerate(roles) if role is not None) % p
    for h in range(8):
        general, pruned = [0]*4, [0]*4
        for pair in range(1 << (7-h)):
            endpoints = [coins[:h]+[b]+[pair >> i & 1 for i in range(7-h)] for b in (0,1)]
            x,y = [[plan.mle(row,q) for q in endpoints] for row in values]
            active = roles[pair << (h+1)]
            for t,op in enumerate(ops):
                psi = [plan.mle(forms[t],q) for q in endpoints]
                edge = plan.rms_gkr_cell_pair_coefficients(op,*x,*y,*psi,17)
                general = [(a+b) % p for a,b in zip(general,edge)]
                if t == active:
                    pruned = [(a+b) % p for a,b in zip(pruned,edge)]
                elif h < 6:
                    assert psi == [0,0]
        if h == 0:
            fast = [0]*4
            tables = plan.boolean_word_fold_tables(point[1:6])
            for block in range(4):
                x,y = [plan.split_boolean_word(sum(row[64*block+j] << j for j in range(64))) for row in values]
                role = roles[64*block]
                edge = plan.rms_gkr_first_word_coefficients(ops[role or 0],x,y,tables,point[0],
                                                          17*eq(point[6:],block) % p,0 if role is None else full)
                fast = [(a+b) % p for a,b in zip(fast,edge)]
            assert fast == general
        elif h < 6:
            assert pruned == general
        elif h == 6:
            assert pruned != general  # the next pair can cross a profile boundary
        polynomial = lambda t: sum(c*pow(t,i,p) for i,c in enumerate(general)) % p
        assert (polynomial(0)+polynomial(1)) % p == claim
        claim = polynomial(coins[h])
    x,y = [plan.mle(row,coins) for row in values]
    psi0,psi1 = [plan.mle(form,coins) for form in forms]
    assert claim == 17*(psi0*x*y+psi1*(x+y-2*x*y)) % p
    tables = plan.boolean_word_fold_tables([2]*5)
    for bad in (-1,1 << 64,True):
        with pytest.raises(ValueError):
            plan.split_boolean_word(bad)
    for mask in (1,full-1,True,-1):
        with pytest.raises(ValueError):
            plan.rms_gkr_first_word_coefficients('and',(0,0),(0,0),tables,2,3,mask)
    for op,x,r,table in (('bad',(0,0),2,tables), ('and',(0,),2,tables), ('and',(0,1 << 32),2,tables),
                         ('and',(0,0),True,tables), ('and',(0,0),2,[])):
        with pytest.raises(ValueError):
            plan.rms_gkr_first_word_coefficients(op,x,(0,0),table,r,3,full)
    tiny = plan.rms_joint_gkr_screen([[2,1]],22)
    field = plan.rms_gkr_field_work_screen(tiny,1)
    small = plan.rms_gkr_aligned_word_screen(tiny,field)
    assert small['first_round_word_gate_terms_upper'] == 65536
    assert small['cell_coefficient_products_upper'] == 25755636
    assert small['reference_input_tuple_visits'] == tiny['reference_input_tuple_visits']
    for joint in (plan.rms_joint_gkr_screen([[2]],29), plan.rms_joint_gkr_screen([[2,1]],1), plan.rms_joint_gkr_screen([[2,1]],6)):
        with pytest.raises(ValueError):
            plan.rms_gkr_aligned_word_screen(joint,plan.rms_gkr_field_work_screen(joint,1))


def test_rms_row_multiplier_getter_matches_exact_rounding_and_prices_shared_cache():
    # The reference does division/isqrt PER OUTPUT; the cache does it once
    # per row, then one exact midpoint correction, never a float comparison.
    ratios = [(a,d) for a in range(1,13) for d in range(1,17)]
    ratios += [(1,36), (1, 1 << 80), (1 << 30, 1), ((1 << 94)-1, 1 << 64),
               (1 << 94, (1 << 64)+1), ((1 << 300)+1, (1 << 300)-1)]
    rng = random.Random(7132)
    ratios += [(rng.randrange(1, 1 << 80), rng.randrange(1, 1 << 96)) for _ in range(100)]
    products = list(range(-31,32))+[32767, -32767, 196605, -196605, 32767**2, -32767**2]
    corrections = 0
    for a, denominator in ratios:
        multiplier = plan.rms_row_multiplier(a, denominator)
        assert 0 <= multiplier <= 1 << 47 and multiplier < 1 << 48
        # Independent 47-step preparation, after the clipping comparison.
        binary = 1 << 47 if a >= denominator << 30 else 0
        if not binary:
            for bit in reversed(range(47)):
                trial = binary+(1 << bit)
                if denominator*trial**2 <= a << 64:
                    binary = trial
        assert multiplier == binary
        for value in products:
            try:
                expected = plan.rne_sqrt_ratio(a*value**2, denominator)
            except ValueError:
                with pytest.raises(ValueError, match='overflows'):
                    plan.rms_rne_from_multiplier(value, a, denominator, multiplier)
                continue
            actual = plan.rms_rne_from_multiplier(value, a, denominator, multiplier)
            assert actual == (-expected if value < 0 else expected)
            if multiplier < 1 << 47:
                scaled = abs(value)*multiplier
                q, remainder = divmod(scaled, 1 << 32)
                estimate = q+int(remainder > 1 << 31 or remainder == 1 << 31 and q & 1)
                assert 0 <= expected-estimate <= 1
                corrections += expected-estimate
    assert corrections > 0
    multiplier = plan.rms_row_multiplier(1,36)
    assert plan.rne_i48_to_i16(9*multiplier,32) == 1  # exact magnitude is 1.5 -> even 2
    assert plan.rms_rne_from_multiplier(9,1,36,multiplier) == 2
    assert plan.rms_rne_from_multiplier(15,1,36,multiplier) == 2  # 2.5 -> even 2
    assert plan.rne_i48_to_i16(196605*multiplier,32) == 32767  # correction MUST reject overflow
    with pytest.raises(ValueError, match='overflows'):
        plan.rms_rne_from_multiplier(196605,1,36,multiplier)
    # Binding Y to a root does not make an altered or stale cache correct.
    assert plan.rms_rne_from_multiplier(9,1,36,0) == 1 != plan.rne_sqrt_ratio(81,36)
    for width in (1,3,256,512,5376):
        for ex,ew,ey in ((0,0,0), (-10,-14,-8), (1000,-1000,0), (-1000,1000,0)):
            statistic = width*17**2
            a,b,c = plan.rms_integer_coefficients(width,ex,ew,ey)
            denominator = b+c*statistic
            multiplier = plan.rms_row_multiplier(a,denominator)
            for value in (0,-17,17*257,32767**2):
                try:
                    expected = plan.rms_rne_i16(value,statistic,width,ex,ew,ey)
                except ValueError:
                    with pytest.raises(ValueError, match='overflows'):
                        plan.rms_rne_from_multiplier(value,a,denominator,multiplier)
                else:
                    assert plan.rms_rne_from_multiplier(value,a,denominator,multiplier) == expected
    for a,d in ((0,1), (1,0), (True,1), (1,False), (1 << 4096,1)):
        with pytest.raises(ValueError):
            plan.rms_row_multiplier(a,d)
    for value,a,d,multiplier in ((True,1,1,0), (32767**2+1,1,1,0), (0,1,1,True),
                                 (0,1,1,-1), (0,1,1,(1 << 47)+1), (0,0,1,0)):
        with pytest.raises(ValueError):
            plan.rms_rne_from_multiplier(value,a,d,multiplier)


def test_rms_native_getter_bounds_cover_preparation_and_lane_temporaries():
    rng = random.Random(7173)
    profiles = [(1,1,1), ((1 << 128)-1,)*3]
    profiles += [plan.rms_integer_coefficients(d,0,0,0) for d in (256,512,5376)]
    for coefficients in profiles:
        a,b,c = coefficients
        screen = plan.rms_getter_integer_screen(coefficients)
        for s in (0,(1 << 47)-1,rng.randrange(1 << 47)):
            denominator = b+c*s
            multiplier = plan.rms_row_multiplier(a,denominator)
            for value in (0,1,-1,32767**2,-32767**2):
                temporaries = [c*s,denominator,denominator << 30,a << 64,
                               denominator*((1 << 47)-1)**2,abs(value)*multiplier,
                               value**2,65535**2,4*a*value**2,denominator*65535**2]
                assert max(v.bit_length() for v in temporaries) <= screen['maximum_intermediate_bits']
        assert screen['one_64_lane_wave_scratch_bytes'] == 64*screen['scalar_scratch_bytes']
        assert screen['row_preparation_mul64_wide_upper'] == 95*screen['u64_limbs']**2
        assert screen['lane_generation_mul64_wide_upper_with_denominator'] == 6*screen['u64_limbs']**2
        assert not screen['credit'] and screen['complete_reader_control_traffic_and_runtime'] is None
    neutral = plan.rms_getter_integer_screen(profiles[-1])
    assert neutral['maximum_intermediate_bits'] == 155 and neutral['u64_limbs'] == 3
    assert neutral['one_64_lane_wave_scratch_bytes'] == 65536
    assert ((1 << 64)-1)**2+2*((1 << 64)-1) == (1 << 128)-1  # schoolbook accumulator fits u128
    for coefficients in ([], [1,1], [True,1,1], [1,0,1], [1,1,1 << 128]):
        with pytest.raises(ValueError):
            plan.rms_getter_integer_screen(coefficients)


def test_rms_output_source_screen_counts_bytes_without_adopting_a_free_y_cut():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           'manifests/c7-d126-gemma31b-source-metadata-v1.json').read_bytes())
    cohorts = plan.gemma_weight_cohorts([t for t in metadata['tensors'] if t['disposition'] == 'private_text'])
    stats = plan.rms_statistic_cohorts(cohorts)
    outputs = plan.rms_output_byte_sources(cohorts)
    tiles, rq = plan.auxiliary_word_layout(outputs)
    assert all(t[-1]//2 % 64 == 0 and math.prod(t[3:6]) % 64 == 0 for t in tiles)
    s = plan.rms_boolean_cohort_screen(cohorts)
    assert s['rms_output_live_cells'] == 347937024 and s['joint_cell_bits'] == 29
    assert s['rms_output_packed_bytes_if_retained'] == 695874048
    assert len(outputs) == 421 and len(tiles) == 3612 and not rq
    assert 96*len(outputs)+72*len(tiles) == 300480
    bridge = plan.rms_byte_bridge_screen(cohorts)
    assert bridge['all_context_known_phase_max_upper_bytes']+s['rms_output_packed_bytes_if_retained'] == 7033652864 > 6442450944
    for case, total in zip(bridge['cases'], (6545959038, 13364647038)):
        sources = plan.auxiliary_word_sources(cohorts, case['old_tokens'])+plan.rms_statistic_byte_sources(cohorts)
        before, rq_before = plan.auxiliary_word_layout(sources)
        after, rq_after = plan.auxiliary_word_layout(sources+outputs)
        assert rq_before == rq_after and len(after) == len(before)+3612
        assert case['source_byte_cells']+s['rms_output_packed_bytes_if_retained'] == total
        assert (total-1).bit_length() == (case['source_byte_cells']-1).bit_length()
        block = 1 << 23
        extra_rows = (total+block-1)//block-(case['source_byte_cells']+block-1)//block
        assert extra_rows == 83 and 8*357*extra_rows == 237048
    old_initial = bridge['cases'][0]['source_byte_cells']
    changed = [o for o in range(3947) if (old_initial+1728000*o-1).bit_length() !=
               (old_initial+s['rms_output_packed_bytes_if_retained']+1728000*o-1).bit_length()]
    assert changed == list(range(1183, 1586))  # endpoint domains alone do NOT cover all contexts
    assert 1784*s['rms_output_live_cells'] == 620719650816

    extended = plan.rms_byte_bridge_screen(cohorts, True)
    assert extended['includes_rms_outputs'] and extended['rms_output_sources'] == 421
    assert extended['rms_output_live_bytes'] == 695874048 and extended['rms_output_retained_array_bytes'] == 0
    assert extended['requires_output_regeneration_or_new_cache_schedule']
    assert extended['rms_input_split_corrections'] == 2
    assert extended['all_context_known_phase_max_upper_bytes'] == 6341540224
    assert extended['remaining_arena_bytes_before_missing_components'] == 100910720
    assert extended['rms_row_multiplier_preparations'] == 576149
    assert extended['rms_row_multiplier_preparation_binary_rounds_upper'] == 27079003
    assert extended['rms_lane_exact_comparisons_upper'] == 1
    assert extended['additional_arrays_reserved_256_byte_aligned']['rms_row_multiplier_cache'] == 3457024
    assert extended['known_bulk_output_reads_before_gamma_and_rms_replay'] == 231
    split = extended['rms_input_split_honest_screen']
    readers = plan.rms_cut_reader_plan(cohorts)
    norms = plan.rms_statistic_cohorts(cohorts)
    stat_offset = 0
    for reader,norm in zip(readers,norms):
        source = cohorts[reader['product_source_id']]
        assert len(reader) == 7 and reader['statistic_byte_offset'] == stat_offset
        assert reader['product_byte_offset'] == source['cut_byte_offset']
        assert reader['rows']*reader['columns'] == source['rows']*source['columns']
        assert reader['product_byte_offset']+reader['product_word_bytes']*reader['rows']*reader['columns'] <= 5143044096
        if not norm['weighted']:
            assert source['operation'] == ('k_proj' if norm['layer'] % 6 == 5 else 'v_source')
            assert reader['rows'] == source['rows']*norm['heads']
        else:
            assert source['operation'] == norm['operation']
        stat_offset += 6*reader['rows']
    assert len(readers) == 421 and stat_offset == 3456894
    reader_screen = extended['rms_cut_reader_screen']
    assert reader_screen['descriptor_bytes'] == 23576
    assert reader_screen['product_B_bytes_per_full_visit'] == 1459332096
    assert reader_screen['live_64_lane_words_per_full_visit'] == 5436516
    assert reader_screen['statistic_and_multiplier_bytes_per_full_visit'] == 65238192
    assert reader_screen['logical_input_read_bytes_per_full_visit'] == 1524570288
    assert reader_screen['raw_rne_calls_per_full_visit'] == 33792000
    assert reader_screen['producer_replays_after_S_and_multiplier_preparation'] == 0
    assert reader_screen['weight_reads_after_S_and_multiplier_preparation'] == 0
    assert extended['rms_output_cell_cubes'] == 3612
    assert split['rne_output_cells'] == 33792000 and split['rne_cubes'] == 240
    assert split['raw_B_logical_bytes'] == 202752000
    assert split['field_products_upper'] == 642155789 and split['field_additions_upper'] == 574579562
    assert split['additional_sigma_source_scans'] == split['additional_weight_reads_given_raw_B'] == 0
    assert split['requires_final_cell_point_and_port_mix_before_read']
    assert not split['credit'] and split['complete_reader_and_framing'] is None
    programs = [plan.rms_boolean_circuit(d,0,0,0,w,True) for w,d in
                ((True,256),(True,512),(True,5376),(False,256),(False,512))]
    joint = plan.rms_joint_gkr_screen([plan.rms_layered_circuit(c)['summary']['level_widths'] for c in programs],29)
    field = plan.rms_gkr_field_work_screen(joint,3612)
    coefficients = [c['summary']['coefficients'] for c in programs]
    statistic_inputs = plan.rms_statistic_dependency_plan(cohorts,plan.gamma_barrier_plan(cohorts))['summary']
    lifetime = plan.rms_joint_lifetime_screen(joint,field,coefficients,extended,statistic_inputs)
    assert lifetime['retained_reservations_256_byte_aligned'] == {
        'public_gate_triples': 9576960, 'public_layer_offsets_and_lengths': 7936,
        'public_profile_descriptors': 512, 'public_norm_profile_map': 3584,
        'plaintext_and_tag_records': 819712, 'integer_getter_wave': 65536,
        'rms_cut_reader_descriptors': 23808, 'pointwise_profile_descriptors': 5888,
        'raw_shift_by_B_cohort': 6400, 'statistic_reader_token_vector': 10752, 'pointwise_integer_wave': 20480}
    assert lifetime['retained_reservation_bytes'] == 10541568 and lifetime['rms_kernel_phase_local_bytes'] == 57346304
    phases = lifetime['all_context_arena_phase_upper_bytes']
    assert len(phases) == 22 and phases['rms_joint_and_input_split'] == 5495069824
    assert phases['rms_statistic_prepare'] == phases['opening_first_pass']-80*(1 << 23) == 5437723520
    assert phases['rms_statistic'] == phases['rms_statistic_prepare']+100872192
    for phase,value in extended['all_context_arena_phase_upper_bytes'].items():
        assert phases[phase] == value+lifetime['retained_reservation_bytes']
    assert lifetime['known_phase_max_upper_bytes'] == max(phases.values()) == 6352081792
    assert lifetime['remaining_arena_before_uncompiled_components'] == 90369152
    assert lifetime['known_y_generations_before_gamma_without_cross_visit_reuse'] == 707044335360
    assert lifetime['row_preparation_mul64_wide_upper'] == 492607395
    assert lifetime['known_y_generation_mul64_wide_upper'] == 38180394109440
    assert lifetime['extra_input_split_rne_getter_words'] == split['rne_output_cells']
    assert lifetime['known_rms_input_logical_reads_with_row_reuse_before_gamma'] == 3100333843920
    assert lifetime['known_raw_rne_calls_before_gamma'] == 68625408000
    assert lifetime['known_pointwise_roundings_before_gamma'] == 9001036800
    assert lifetime['raw_rne_word_arithmetic_logic_comparisons_upper'] == 2196013056000
    assert lifetime['pointwise_word_arithmetic_logic_comparisons_upper'] == 576066355200
    assert lifetime['scalar_profile_logical_read_bytes_if_once_per_64_lane_word'] == 13078694400
    assert not lifetime['credit'] and lifetime['complete_gamma_liveness_pcg_and_runtime'] is None
    rope = plan.rope_byte_bridge_screen(cohorts)
    combined = plan.rms_joint_lifetime_screen(joint,field,coefficients,extended,statistic_inputs,rope)
    assert combined['includes_rope_reader'] and not lifetime['includes_rope_reader']
    assert combined['retained_reservations_256_byte_aligned']['rope_reader_word_buffers'] == 1024
    assert combined['retained_reservation_bytes'] == 10542592
    for k,v in lifetime['all_context_arena_phase_upper_bytes'].items():
        assert combined['all_context_arena_phase_upper_bytes'][k] == v+7020288+(23040 if k == 'rne_top' else 0)
    assert combined['all_context_arena_phase_upper_bytes']['rope_linear'] == 5646070400
    assert combined['known_phase_max_upper_bytes'] == 6359102080
    assert combined['remaining_arena_before_uncompiled_components'] == 83348864
    assert combined['known_y_generations_before_gamma_without_cross_visit_reuse'] == 847099887360
    assert combined['known_y_generation_mul64_wide_upper'] == 45743393917440
    assert combined['known_rms_input_logical_reads_with_row_reuse_before_gamma'] == 3686816467920
    assert combined['known_raw_rne_calls_before_gamma'] == lifetime['known_raw_rne_calls_before_gamma']
    assert combined['known_source_and_rms_joint_payload_before_remaining_gamma_framing'] == 33480168
    for bad in ({**rope,'extends_source':'S'}, {**rope,'base_rms_output_layout_sha256':['wrong']}):
        with pytest.raises(ValueError):
            plan.rms_joint_lifetime_screen(joint,field,coefficients,extended,statistic_inputs,bad)
    for j,f,cs,b,si in ((joint,field,coefficients,bridge,statistic_inputs),
                        (joint,field,coefficients[:-1],extended,statistic_inputs),
                        (joint,{**field,'profile_interval_count':1},coefficients,extended,statistic_inputs),
                        (joint,field,coefficients,extended,{**statistic_inputs,'initial_S_kappa_write_bytes':12})):
        with pytest.raises(ValueError):
            plan.rms_joint_lifetime_screen(j,f,cs,b,si)
    for before, after, total in zip(bridge['cases'], extended['cases'], (25668776,32644752)):
        assert after['known_partial_payload_before_rms_circuit_gamma_and_framing'] == total
        assert total-before['known_partial_payload_before_rms_circuit_gamma_and_framing'] == 237096
        assert after['rq_cubes'] == before['rq_cubes'] and after['byte_cubes']-before['byte_cubes'] == 3612
    comparison = extended['rms_output_all_context_comparison']
    assert comparison['contexts_checked'] == 3947
    assert comparison['old_lengths_with_changed_padding_from_s'] == changed
    assert comparison['maximum_source_path_payload_delta'] == 2627520
    assert comparison['complete_all_context_total_payload'] is None and not comparison['credit']
    deltas = comparison['source_path_payload_deltas_including_input_split']
    # Independent full component calls at every domain boundary, not an
    # extrapolation of the two end-context sizes or the cached delta formula.
    for old in (0, 1182, 1183, 1585, 1586, 1587, 1588, 3946):
        costs = []
        for live in (old_initial+1728000*old, old_initial+1728000*old+695874048):
            n = (live-1).bit_length()
            zero = (1 << n)//(1 << 23)-(live+(1 << 23)-1)//(1 << 23)
            cost = plan.wide_hash_joint_opening_screen([1 << n], 1 << 23, 357, [zero])
            costs.append(cost['private_component_payload_before_framing_and_caller']+
                         plan.byte_range_tree_screen(n)['payload_before_framing_and_shared_closures']+
                         plan.byte_bit_lift_screen(n)['payload_before_incoming_claims_framing_and_shared_closures'])
        assert deltas[old] == costs[1]-costs[0]+48
    sources = plan.auxiliary_word_sources(cohorts)+plan.rms_statistic_byte_sources(cohorts)+outputs
    byte_tiles, _ = plan.auxiliary_word_layout(sources)
    forms = plan.rms_joint_input_pullback(stats, sources, byte_tiles, list(range(2,31)))
    assert forms['summary']['compact_sigma_byte_views'] == 42384
    assert forms['summary']['compact_rne_output_views'] == 240
    assert forms['summary']['honest_split_rne_output_cells'] == split['rne_output_cells']
    assert forms['summary']['input_split_extension_corrections'] == 2
    assert forms['summary']['complete_gamma_callers_and_reader'] is None
    assert not forms['summary']['credit']
    for _, source, claim in forms['rne_output_views']:
        raw = sources[source]
        assert raw['operation'] == ('k_proj' if raw['layer'] % 6 == 5 else 'v_source')
        assert len(claim[1]) == 8 and len(claim[2]) == (11 if raw['layer'] % 6 == 5 else 12)
    with pytest.raises(ValueError):
        plan.rms_byte_bridge_screen(cohorts, 1)


def test_rms_joint_input_views_bind_p_s_y_and_rne_bits_with_head_and_padding_rules():
    p = plan.P
    def eq(point, i):
        return math.prod(v if i >> k & 1 else 1-v for k,v in enumerate(point)) % p
    def source(role, i, layer, operation, rows, cols, size, rne=False):
        return {'source': role, 'source_id': i, 'layer': layer, 'operation': operation,
                'shape': (1,rows,cols), 'word_bytes': size, 'rne': rne, 'token_offset': 0}
    norms = [{'weighted': True, 'layer': 0, 'operation': 'input_rms', 'heads': 1,
              'statistic_rows': 3, 'columns': 3},
             {'weighted': False, 'layer': 1, 'operation': 'v_norm', 'heads': 2,
              'statistic_rows': 6, 'columns': 2,
              'source_producer': {'layer': 1, 'operation': 'v_source'}}]
    sources = [source('B',0,0,'input_rms',3,3,4), source('B',1,1,'v_source',3,4,6,True),
               source('RMS_statistics',0,0,'input_rms',3,1,6), source('RMS_statistics',1,1,'v_norm',6,1,6),
               source('RMS_outputs',0,0,'input_rms',3,3,2), source('RMS_outputs',1,1,'v_norm',6,2,2)]
    raw = [[4*r+c-5 for c in range(4)] for r in range(3)]
    def rne(raw):
        q, remainder = divmod(raw, 2)
        return q+int(remainder == 1 and q & 1)
    x1 = [[rne(v) for v in row] for row in raw]
    ps = [[3*(r-c) for c in range(3)] for r in range(3)]
    statistics = [[[sum((r-c)**2 for c in range(3))] for r in range(3)],
                  [[sum(x1[r//2][2*(r%2)+c]**2 for c in range(2))] for r in range(6)]]
    products = [ps, [[x1[r//2][2*(r%2)+c] for c in range(2)] for r in range(6)]]
    ys = [[[plan.rms_rne_i16(v, statistics[i][r][0], norms[i]['columns'], 0, 0, 0)
            for v in row] for r, row in enumerate(values)] for i, values in enumerate(products)]
    values = [ps, raw, *statistics, *ys]
    b_bytes = b''.join(v.to_bytes(size,'little',signed=True) for table,size in ((ps,4),(raw,6)) for row in table for v in row)
    s_bytes = b''.join((s+(1 << 47)).to_bytes(6,'little') for table in statistics for row in table for s in row)
    coefficients = [plan.rms_integer_coefficients(n['columns'],0,0,0) for n in norms]
    k_bytes = b''.join(plan.rms_row_multiplier(a,b+c*row[0]).to_bytes(6,'little')
                       for (a,b,c),table in zip(coefficients,statistics) for row in table)
    readers = [{'norm_source_id': i, 'product_source_id': i, 'product_byte_offset': bo,
                'statistic_byte_offset': so, 'rows': n['statistic_rows'], 'columns': n['columns'],
                'product_word_bytes': 4 if n['weighted'] else 6}
               for i,(n,bo,so) in enumerate(zip(norms,(0,36),(0,18)))]
    for i,reader in enumerate(readers):
        for row in range(reader['rows']):
            word = plan.rms_read_input_word(reader,row*reader['columns'],reader['columns'],
                                            (b_bytes,s_bytes,k_bytes),coefficients[i],None if i == 0 else 1)
            assert word == [(products[i][row][col],statistics[i][row][0],ys[i][row][col]) for col in range(reader['columns'])]
    buffers = (b_bytes,s_bytes,k_bytes)
    for first,count,bufs,shift in ((0,65,buffers,None), (2,2,buffers,None), (-1,1,buffers,None),
                                   (9,1,buffers,None), (0,1,(b'',s_bytes,k_bytes),None),
                                   (0,1,(b_bytes,s_bytes,b''),None), (0,1,buffers,1)):
        with pytest.raises(ValueError):
            plan.rms_read_input_word(readers[0],first,count,bufs,coefficients[0],shift)
    with pytest.raises(ValueError):
        plan.rms_read_input_word(readers[1],0,1,buffers,coefficients[1])
    with pytest.raises(ValueError):
        plan.rms_read_input_word(readers[0],0,1,(b_bytes,bytes(6),k_bytes),coefficients[0])  # negative decoded S
    byte_tiles, _ = plan.auxiliary_word_layout(sources)
    live = sum(math.prod(s['shape'])*s['word_bytes'] for s in sources)
    packed = [0]*(1 << (live-1).bit_length())
    for i,r,c,a,h,d,j,count,offset in byte_tiles:
        for row in range(h):
            for col in range(d):
                word = values[i][r+row][c+col]+(1 << (8*sources[i]['word_bytes']-1))
                for k in range(count):
                    packed[offset+k+count*(col+d*row)] = word >> (8*(j+k)) & 255
    beta_planes = [[byte >> k & 1 for byte in packed] for k in range(8)]
    y_tiles, _ = plan.auxiliary_word_layout(sources[4:])
    input_table = [[0]*128 for _ in range(32)]
    for i,r,c,a,h,d,j,count,offset in y_tiles:
        for row in range(h):
            for col in range(d):
                rr, cc = r+row, c+col
                words = [(products[i][rr][cc],32 if i == 0 else 16), (statistics[i][rr][0],48), (ys[i][rr][cc],16)]
                bits = [0,1]+[(v+(1 << (w-1))) >> k & 1 for v,w in words for k in range(w)]
                input_table[offset//2+col+d*row] = bits+[0]*(128-len(bits))
    a, b, mix = list(range(2,9)), list(range(11,18)), 7
    weights = [(eq(a,j)+mix*eq(b,j)) % p for j in range(128)]
    rne_planes = [[((x1[r][c]+32768) >> k & 1) if r < 3 else 0 for r in range(4) for c in range(4)]
                  for k in range(16)]
    for point in ([2,3,5,7,11], [0]*5, [1]*5):
        pulled = plan.rms_joint_input_pullback(norms, sources, byte_tiles, point)
        expected = sum(eq(point,i)*sum(w*v for w,v in zip(weights,row)) for i,row in enumerate(input_table)) % p
        sigma = sum(scale*sum(weights[port+k]*plan.mle(beta_planes[k][offset:offset+(1 << len(q))],q)
                              for k in range(8)) for port,offset,q,scale in pulled['sigma_byte_views']) % p
        from_rne = sum(claim[3]*sum(weights[port+k]*plan.mle(rne_planes[k],claim[2]+claim[1]) for k in range(16))
                       for port,i,claim in pulled['rne_output_views']) % p
        assert expected == (weights[1]*pulled['public_one']+sigma+from_rne) % p
        # Fresh subset read after u/lambda are known. Visit every v_norm raw
        # once; reconstruct the Sigma component from a0, not another read.
        fresh, seen = 0, set()
        for i,r,c,_,height,width,_,_,offset in y_tiles:
            if norms[i]['weighted']:
                continue
            for row in range(height):
                for col in range(width):
                    rr,cc = r+row,c+col
                    address = rr//2,2*(rr%2)+cc
                    assert address not in seen
                    seen.add(address)
                    value = plan.rms_rne_bit_linear_value(raw[address[0]][address[1]],1,weights[2:18])
                    fresh = (fresh+eq(point,offset//2+col+width*row)*value) % p
        assert len(seen) == pulled['summary']['honest_split_rne_output_cells'] == 12
        assert fresh == from_rne
        reconstructed_sigma = (expected-weights[1]*pulled['public_one']-fresh) % p
        assert reconstructed_sigma == sigma
        # Preserving the split equation with compensating errors does NOT
        # bind either branch; the same R3/R2 source checks are still required.
        assert (reconstructed_sigma-1+fresh+1) % p == (sigma+from_rne) % p
        assert (fresh+1) % p != from_rne and (reconstructed_sigma-1) % p != sigma
        if point == [1]*5:
            assert expected == pulled['public_one'] == 0  # no biased-zero bit on nonexistent RMS cells
        else:
            assert pulled['public_one'] == sum(eq(point,i) for i in range(21)) % p
    half = pow(2,-1,p)
    assert plan.mle([1,0],[half]) == plan.mle([0,1],[half])  # same folded shared port
    assert plan.mle([0,0],[half]) != plan.mle([0,1],[half])  # different v_norm component
    for raw_value,shift,ws in ((0,1,[0]*15), (0,1,[True]*16), (1 << 47,1,[0]*16), (1,-15,[0]*16)):
        with pytest.raises(ValueError):
            plan.rms_rne_bit_linear_value(raw_value,shift,ws)
    # Native point consumers see this SAME Y, with bias only on live words.
    for i,norm in enumerate(norms):
        rows, heads, cols = norm['statistic_rows']//norm['heads'], norm['heads'], norm['columns']
        cb, rb = (heads*cols-1).bit_length(), (rows-1).bit_length()
        point = list(range(2,2+cb+rb))
        native = [ys[i][r*heads+c//cols][c%cols] if r < rows and c < heads*cols else 0
                  for r in range(1 << rb) for c in range(1 << cb)]
        claim = plan.rms_output_source_point(norm, point)
        terms, bias = plan.auxiliary_probe_terms(byte_tiles, sources, {4+i: claim})
        reconstructed = (sum(scale*plan.mle(packed[offset:offset+(1 << len(q))],q) for offset,q,scale in terms)-bias) % p
        assert reconstructed == plan.mle(native,point)
    # One altered Y byte changes both the source input and consumer, but no
    # longer satisfies the uniquely determined RMS output. Binding is not correctness.
    address = next(t[-1] for t in byte_tiles if t[0] == 4 and t[1] == t[2] == t[6] == 0)
    cell = next(t[-1]//2 for t in y_tiles if t[0] == t[1] == t[2] == 0)
    point = [2,3,5,7,11]
    pulled = plan.rms_joint_input_pullback(norms, sources, byte_tiles, point)
    change = 1-2*beta_planes[0][address]
    delta = sum(scale*weights[port]*eq(q,address-offset)*change for port,offset,q,scale in pulled['sigma_byte_views']
                if offset <= address < offset+(1 << len(q))) % p
    assert delta == weights[82]*eq(point,cell)*change % p != 0
    changed_bytes = packed[:]
    changed_bytes[address] ^= 1
    native_point = [2,3,5,7]
    terms,bias = plan.auxiliary_probe_terms(byte_tiles,sources,{4: plan.rms_output_source_point(norms[0],native_point)})
    consumer_delta = sum(scale*(plan.mle(changed_bytes[offset:offset+(1 << len(q))],q)
                                -plan.mle(packed[offset:offset+(1 << len(q))],q)) for offset,q,scale in terms) % p
    assert consumer_delta == eq(native_point,0)*change % p != 0
    assert ys[0][0][0]+change != plan.rms_rne_i16(ps[0][0], statistics[0][0][0], 3, 0, 0, 0)
    for mutated in ([*sources, dict(sources[4])],
                    [*sources[:4], {**sources[4], 'token_offset': 1}, sources[5]],
                    [sources[0], {**sources[1], 'rne': False}, *sources[2:]]):
        with pytest.raises(ValueError):
            plan.rms_joint_input_pullback(norms, mutated, byte_tiles, [2]*5)
    with pytest.raises(ValueError):
        plan.rms_output_source_point({**norms[1], 'heads': 3}, [2]*4)


def test_rms_byte_extension_preserves_rq_and_recounts_padding_records_and_arrays():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           "manifests/c7-d126-gemma31b-source-metadata-v1.json").read_bytes())
    cohorts = plan.gemma_weight_cohorts([t for t in metadata['tensors'] if t['disposition'] == 'private_text'])
    stat_sources = plan.rms_statistic_byte_sources(cohorts)
    offset = 0
    for i, (s, r) in enumerate(zip(stat_sources, plan.rms_statistic_cohorts(cohorts))):
        assert (s['source_id'], s['physical_statistic_offset']) == (i, offset)
        assert s['source'] == 'RMS_statistics' and not s['rne'] and s['word_bytes'] == 6
        assert (s['layer'], s['operation'], s['shape']) == (r['layer'], r['operation'], (1, r['statistic_rows'], 1))
        offset += 6*r['statistic_rows']
    assert len(stat_sources) == 421 and offset == 3456894
    screen = plan.rms_byte_bridge_screen(cohorts)
    for old in (0, 1585, 1586, 1587, 1588, 3945, 3946):
        before = plan.auxiliary_word_sources(cohorts, old)
        old_tiles, old_rq = plan.auxiliary_word_layout(before)
        after = before+stat_sources
        tiles, rq = plan.auxiliary_word_layout(after)
        assert rq == old_rq and len(tiles)-len(old_tiles) == 3368
        assert sum(t[3]*t[4]*t[5]*t[7] for t in tiles if t[0] >= len(before)) == offset
        assert {t[:8] for t in tiles if t[0] < len(before)} == {t[:8] for t in old_tiles}
        assert {t[:8]: t[8] for t in tiles if t[0] < len(before)} != {t[:8]: t[8] for t in old_tiles}
        old_live = sum(math.prod(s['shape'])*s['word_bytes'] for s in before)
        live = sum(math.prod(s['shape'])*s['word_bytes'] for s in after)
        assert old_live == 5846628096+1728000*old and live == old_live+offset
        assert ((old_live-1).bit_length() != (live-1).bit_length()) == (old in (1586, 1587))
        if old in (0, 3946):
            case = screen['cases'][int(old != 0)]
            assert case['source_templates'] == len(after) == 4314
            assert case['byte_cubes'] == len(tiles) and case['source_byte_cells'] == live
            assert case['layout_sha256'] == plan.hashlib.sha256(json.dumps(
                [after, tiles, rq], sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    assert screen['old_lengths_with_changed_byte_padding'] == [1586, 1587]
    assert screen['statistic_probe_extension_coordinates'] == 4108
    assert screen['statistic_probe_and_sumcheck_extension_corrections'] == 36107
    assert screen['additional_payload_before_rms_circuit_gamma_and_framing'] == 866568
    assert screen['initial_statistic_i16_squares'] == 347937024
    assert screen['initial_statistic_integer_additions'] == 347360875
    assert screen['known_sigma_claims_before_future_gamma'] == 1323
    assert screen['fixed_input_probe_and_sumcheck_error_numerator'] == 30241
    arrays = screen['additional_arrays_reserved_256_byte_aligned']
    assert arrays == {'packed_statistics': 3457024, 'source_and_cube_descriptors': 283136,
                      'new_plaintext_and_tags': 1733376, 'probe_and_input_points': 307712,
                      'statistic_kernel_descriptors': 40448, 'kernel_control_reserve': 65536}
    assert screen['additional_array_reservation_bytes'] == sum(arrays.values()) == 5887232
    assert screen['known_bulk_statistic_reads_before_replay_and_normalizer'] == 232
    assert screen['known_bulk_statistic_read_and_initial_write_bytes'] == 233*3456894
    assert [c['public_zero_rows_joint_w_kv'] for c in screen['cases']] == [[218, 1], [218, 18, 18]]
    assert [c['public_zero_rows_sigma'] for c in screen['cases']] == [326, 537]
    assert [c['omitted_outer_base_corrections'] for c in screen['cases']] == [194565, 282387]
    assert [c['known_partial_payload_before_rms_circuit_gamma_and_framing'] for c in screen['cases']] == [25431680, 32407656]
    assert [c['remaining_payload_bytes_before_missing_components'] for c in screen['cases']] == [9568320, 2592344]
    assert screen['additional_common_sigma_batch_error_numerator'] == screen['additional_known_sigma_claims'] == 422
    assert screen['bit_lift_record_reservation_bytes'] == 74496
    assert screen['rne_output_bit_reservation_bytes'] == 63488
    for c in screen['cases']:
        b = c['byte_bit_lift']
        n = (c['source_padded_byte_cells']-1).bit_length()
        assert b == plan.byte_bit_lift_screen(n)
        assert b['extension_corrections_excluding_incoming_claims'] == 35*n+177
        assert b['payload_before_incoming_claims_framing_and_shared_closures'] == 24*(35*n+177)
        assert b['private_products'] == 24 and b['zero_residuals'] == 9*n+38
        assert b['extension_challenges'] == 9*n+48
        assert b['interactive_error_numerator_excluding_incoming_batch'] == 26*n+103
        assert b['source_endpoints'] == 1 and b['extra_trace_commitments'] == 0
        assert b['source_visits'] == 118 and not b['credit']
        assert b['incoming_claims_and_form_metadata'] is b['complete_rms_circuit'] is None
        assert b['top_array_bytes'] == sum(b['top_arrays_256_byte_aligned'].values())
        assert b['link_array_bytes'] == sum(b['link_arrays_256_byte_aligned'].values())
        rb = c['rne_output_bits']
        assert rb['additional_private_products'] == rb['additional_extension_corrections'] == 764
        assert sum(rb['additional_products_by_positive_shift']) == 764
        assert rb['additional_payload_before_incoming_claims_and_framing'] == 18336
        assert rb['additional_array_reservation_bytes'] == sum(rb['additional_arrays_256_byte_aligned'].values()) == 63488
        assert rb['additional_sumcheck_rounds'] == rb['additional_source_visits'] == 0
        assert rb['additional_sigma_claims'] == rb['additional_pcs_instances'] == 0
        assert rb['incoming_bit_claims_and_public_form_work'] is rb['complete_rms_circuit'] is None
    assert screen['cases'][-1]['byte_bit_lift']['link_array_bytes'] == 812751104
    assert screen['array_reservation_includes_omitted_records']
    # The pinned aligned KV cubes are each <= one RS row at every length.
    # Every cube has a live cell, so only the global padded tail contains
    # wholly zero rows. Packed live KV is NOT the prefix used by the codec.
    cfg = plan.pinned_model_config()
    widths = sorted([cfg[k+'_kv_heads']*cfg[k+'_head_dim'] for k in ('local', 'global')
                     for _ in range(2*cfg[k+'_layers'])], reverse=True)
    assert sum(widths) == 450560
    for length in range(1, 4097):
        padded, block, cursor = 1 << (length-1).bit_length(), 1 << 24, 0
        live_rows = set()
        for width in widths:
            size = width*padded
            assert size <= block and cursor % size == 0
            live_rows.add(cursor//block)
            cursor += size
        assert live_rows == set(range((cursor+block-1)//block))
    wrong_prefix = 450560*150
    assert (wrong_prefix+(1 << 24)-1)//(1 << 24) == 5  # true padded prefix needs seven rows
    upper = screen['all_context_arena_phase_upper_bytes']
    assert max(upper.values()) == screen['all_context_known_phase_max_upper_bytes'] == 6337778816
    assert len(upper) == 20 and upper['rms_statistic'] == 5524292736
    assert upper['byte_bit_top'] == 5826500480 and upper['byte_bit_link'] == 6236171648
    assert all(v <= upper[k] for c in screen['cases'] for k, v in c['arena_phase_upper_bytes'].items())
    assert screen['remaining_arena_bytes_before_missing_components'] == 104672128
    assert not screen['credit'] and screen['complete_rms_integer_circuit'] is None
    assert screen['complete_gamma_liveness'] is screen['complete_certificate_bytes'] is None
    assert screen['additional_weight_reads_given_w_free_reader'] == screen['additional_pcs_instances'] == 0
    with pytest.raises(ValueError, match=r'100\+50'):
        plan.rms_byte_bridge_screen(plan.gemma_weight_cohorts(
            [t for t in metadata['tensors'] if t['disposition'] == 'private_text'], 1, 1))
    for bad in (0, 36, True):
        with pytest.raises(ValueError):
            plan.byte_bit_lift_screen(bad)


def test_rms_statistic_and_byte_plane_pullbacks_share_one_fixed_source():
    # A tiny existing RNE source plus three S rows. X has a fourth REAL
    # producer row which must not contribute to the final norm's statistic.
    x = [[1, 2, 3, 4, 5], [32767]*5, [-9, 8, -7, 6, -5], [11, 12, 13, 14, 15]]
    statistics = [sum(v*v for v in row) for row in x[:3]]
    sources = [{'shape': (1, 1, 2), 'word_bytes': 6, 'rne': True, 'token_offset': 0},
               {'shape': (1, 3, 1), 'word_bytes': 6, 'rne': False, 'token_offset': 0},
               {'shape': (1, 1, 1), 'word_bytes': 4, 'rne': False, 'token_offset': 0},
               {'shape': (1, 1, 1), 'word_bytes': 2, 'rne': False, 'token_offset': 0}]
    words = [[-5, 257], statistics, [-32767**2], [-32767]]
    tiles, rq = plan.auxiliary_word_layout(sources)
    assert rq == plan.auxiliary_word_layout(sources[:1])[1]
    live = sum(math.prod(s['shape'])*s['word_bytes'] for s in sources)
    u, indices = [0]*(1 << (live-1).bit_length()), {}
    for i, r, c, heads, height, width, j, count, offset in tiles:
        for row, col, byte in product(range(height), range(width), range(count)):
            value = words[i][(r+row)*sources[i]['shape'][2]+c+col]+(1 << (8*sources[i]['word_bytes']-1))
            index = offset+count*(col+width*row)+byte
            u[index] = value >> (8*(j+byte)) & 255
            indices[i, r+row, c+col, j+byte] = index
    assert len(indices) == live == 36 and all(v == 0 for v in u[live:])
    def evaluate(terms, values):
        return sum(coef*plan.mle(values[start:start+(1 << len(point))], point)
                   for start, point, coef in terms) % plan.P
    q = [2, 3]
    point = {1: ([], q, [], 1)}
    terms, bias = plan.auxiliary_probe_terms(tiles, sources, point)
    initial_statistic_wire = (evaluate(terms, u)-bias) % plan.P
    assert initial_statistic_wire == plan.mle(statistics+[0], q)
    assert initial_statistic_wire != plan.mle(statistics+[sum(v*v for v in x[3])], q)
    assert bias != 1 << 47  # support is not the whole padded row cube
    for row, byte in product(range(3), range(6)):
        altered = u.copy()
        altered[indices[1, row, 0, byte]] ^= 1  # still byte-valid
        assert (evaluate(terms, altered)-bias) % plan.P != initial_statistic_wire
    for byte in range(6):
        byte_terms = plan.auxiliary_byte_terms(tiles, sources, point, byte)
        plane = [((s+(1 << 47)) >> (8*byte)) & 255 for s in statistics]+[0]
        assert evaluate(byte_terms, u) == plan.mle(plane, q)
        # Broadcast S over five live lanes, not over all eight padded lanes.
        lane_point = [5, 7, 11]
        support = plan.mle([1]*5+[0]*3, lane_point)
        broadcast_terms = plan.auxiliary_byte_terms(tiles, sources, {1: ([], q, [], support)}, byte)
        dense = [v if lane < 5 else 0 for v in plane for lane in range(8)]
        assert evaluate(broadcast_terms, u) == plan.mle(dense, lane_point+q)
    for byte in (-1, 6, True):
        with pytest.raises(ValueError):
            plan.auxiliary_byte_terms(tiles, sources, point, byte)
    for source, width in ((2, 4), (3, 2)):
        for byte in range(width):
            plane_terms = plan.auxiliary_byte_terms(tiles, sources, {source: ([], [], [], 1)}, byte)
            expected = (words[source][0]+(1 << (8*width-1))) >> (8*byte) & 255
            assert evaluate(plane_terms, u) == expected
        with pytest.raises(ValueError):
            plan.auxiliary_byte_terms(tiles, sources, {source: ([], [], [], 1)}, width)
    with pytest.raises(ValueError):
        plan.auxiliary_byte_terms(tiles, sources, {4: ([], q, [], 1)}, 0)
    with pytest.raises(ValueError):
        plan.auxiliary_byte_terms(tiles, sources, {1: ([], [], [], 1)}, 0)
    # Even a source-bound byte MLE is not a source-bound bit MLE.
    folded_byte = plan.mle([0, 1], [2])
    lsb_at_folded_byte = sum((j & 1)*v for j, v in enumerate(plan.byte_lagrange_basis(folded_byte))) % plan.P
    assert lsb_at_folded_byte == 0 != plan.mle([0, 1], [2])


def test_shared_byte_bit_pullback_and_quadratic_reduction_use_one_source():
    p = plan.P
    def eq(point, index):
        return math.prod(x if index >> j & 1 else 1-x for j, x in enumerate(point)) % p
    def fold(values, point):
        return [(a+point*(b-a)) % p for a, b in zip(values[::2], values[1::2])]
    sources = [{'shape': (1, 3, 1), 'word_bytes': width, 'rne': False, 'token_offset': 0}
               for width in (2, 4, 6)]
    words = [[-32767, 0, 32767], [-32767**2, 257, -7], [1, 1 << 40, 5772083729664]]
    tiles, _ = plan.auxiliary_word_layout(sources)
    u = [0]*64
    for i, r, c, heads, height, width, j, count, offset in tiles:
        for row, byte in product(range(height), range(count)):
            value = words[i][r+row]+(1 << (8*sources[i]['word_bytes']-1))
            u[offset+count*row+byte] = value >> (8*(j+byte)) & 255
    assert u[36:] == [0]*28
    bits = [[x >> k & 1 for x in u] for k in range(8)]
    phi, terms, claims = [[0]*64 for _ in range(8)], [[] for _ in range(8)], []
    for a, source in enumerate(sources):
        rp, bp = [2+a, 7+a], [3, 5, 11, 13, 17, 19][:(8*source['word_bytes']-1).bit_length()]
        incoming = sum(eq(rp, row)*eq(bp, bit)*((value+(1 << (8*source['word_bytes']-1))) >> bit & 1)
                       for row, value in enumerate(words[a]) for bit in range(8*source['word_bytes'])) % p
        claims.append(incoming)
        for byte, k in product(range(source['word_bytes']), range(8)):
            scale = pow(23, a, p)*eq(bp[:3], k)*eq(bp[3:], byte) % p
            for offset, point, coefficient in plan.auxiliary_byte_terms(tiles, sources, {a: ([], rp, [], scale)}, byte):
                terms[k].append((offset, point, coefficient))
                for j in range(1 << len(point)):
                    phi[k][offset+j] = (phi[k][offset+j]+coefficient*eq(point, j)) % p
    claim = sum(pow(23, a, p)*v for a, v in enumerate(claims)) % p
    original = claim
    assert claim == sum(plan.dot(f, b) for f, b in zip(phi, bits)) % p
    # Every live-byte LSB tamper changes the same incoming batch.
    for i in range(36):
        bad = [list(b) for b in bits]
        bad[0][i] ^= 1
        assert original != sum(plan.dot(f, b) for f, b in zip(phi, bad)) % p
    point = [29, 31, 37, 41, 43, 47]
    for k in range(8):
        rows = [eq(point[3:], j) for j in range(8)]
        assert plan.mle(phi[k], point) == sum(c*plan.folded_cube_form(o, r, rows, point[:3])
                                             for o, r, c in terms[k]) % p
    for r in point:
        coefficients = [0, 0, 0]
        for f, b in zip(phi, bits):
            for i in range(0, len(f), 2):
                c0, c2 = f[i]*b[i], (f[i+1]-f[i])*(b[i+1]-b[i])
                for j, value in enumerate((c0, f[i+1]*b[i+1]-c0-c2, c2)):
                    coefficients[j] = (coefficients[j]+value) % p
        assert claim == (coefficients[0]+sum(coefficients)) % p
        for z in (0, 1, 2, r):
            assert sum(c*pow(z, j, p) for j, c in enumerate(coefficients)) % p == (
                sum(plan.dot(fold(f, z), fold(b, z)) for f, b in zip(phi, bits)) % p)
        claim = sum(c*pow(r, j, p) for j, c in enumerate(coefficients)) % p
        phi, bits = [fold(f, r) for f in phi], [fold(b, r) for b in bits]
    endpoints = [b[0] for b in bits]
    assert claim == sum(f[0]*v for f, v in zip(phi, endpoints)) % p
    assert all(f[0] != 0 for f in phi)  # altering any terminal changes this residual
    rho = [53, 59, 61]  # AFTER eight terminal bit claims, never before them
    omega = [sum(eq(rho, k)*(j >> k & 1) for k in range(8)) % p for j in range(256)]
    trees = [plan.byte_lagrange_tree(x, omega) for x in u]
    assert sum(eq(rho, k)*v for k, v in enumerate(endpoints)) % p == plan.mle([s[1] for _, s in trees], point)
    assert plan.byte_lagrange_tree(256, omega)[1][1] != 0  # not eight low bits of an out-of-range integer


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


def test_rne_output_and_validity_forms_match_dense_rq_with_multiple_claims():
    sources = [
        {'shape': (1, 3, 3), 'word_bytes': 6, 'rne': True, 'token_offset': 0},
        {'shape': (2, 2, 3), 'word_bytes': 6, 'rne': True, 'token_offset': 0},
        {'shape': (2, 1, 4), 'word_bytes': 6, 'rne': True, 'token_offset': 2},
        {'shape': (2, 3, 2), 'word_bytes': 6, 'rne': True, 'token_offset': 0},
        {'shape': (1, 1, 2), 'word_bytes': 6, 'rne': True, 'token_offset': 0},
        {'shape': (1, 2, 1), 'word_bytes': 4, 'rne': False, 'token_offset': 0},
    ]
    _, rq = plan.auxiliary_word_layout(sources)
    shifts = {0: -1, 1: 1, 2: 1, 3: 3, 4: 0}
    qk = ([2], [3, 5], [7, 11], 13)
    # Native PV point is lane || head || token; RQ is lane || token || head.
    pv_native = [17, 19, 23, 29]
    pv = (pv_native[1:2], pv_native[2:], pv_native[:1], 31)
    claims = {0: [([], [2, 7], [3, 5], 11), ([], [13, 17], [19, 23], 29)],
              1: [qk], 2: [qk], 3: [pv]}  # source 4 intentionally has no output demand
    n = (sum(math.prod(s['shape']) for s in sources if s['rne'])-1).bit_length()
    r, u = list(range(2, 2+n)), list(range(11, 11+n))
    forms = plan.auxiliary_rne_forms(rq, sources, claims, shifts, r)
    dense = {s: {'output': [0]*(1 << n), 'validity': [0]*(1 << n)} for s in forms}
    values, cells = [0]*(1 << n), []
    def eq(point, index):
        return math.prod(x if (index >> j) & 1 else 1-x for j, x in enumerate(point)) % plan.P
    for i, row, col, heads, height, width, offset in rq:
        for h, a, b in product(range(heads), range(height), range(width)):
            index = offset+b+width*(a+height*h)
            rr, cc = row+a, col+b
            raw = -30+9*i+5*h+3*rr+cc
            values[index] = plan.rne_i48_to_i16(raw, shifts[i]) % plan.P
            cells.append((i, index, raw))
            dense[shifts[i]]['output'][index] = sum(
                scale*eq(hp,h)*eq(rp,sources[i]['token_offset']+rr)*eq(cp,cc)
                for hp,rp,cp,scale in claims.get(i, ())) % plan.P
            dense[shifts[i]]['validity'][index] = eq(r,index)
    for s, group in forms.items():
        for role, terms in group.items():
            actual = sum(scale*plan.folded_cube_form(o, q, [1], u) for o,q,scale in terms) % plan.P
            assert actual == plan.mle(dense[s][role], u)
            assert all(x == 0 for x in dense[s][role][len(cells):])
    assert forms[0]['output'] == [] and forms[0]['validity']
    assert sum(len(f['validity']) for f in forms.values()) == len(rq)
    # The lifted R2 equation agrees with the demanded rounded outputs.
    expected = sum(sum(x*y for x,y in zip(f['output'], values)) for f in dense.values()) % plan.P
    rhs = 0
    for i, index, raw in cells:
        digits = [((raw+(1 << 47)) >> (8*j)) & 255 for j in range(6)]
        y, valid = plan.rne48_byte_polynomials(digits, shifts[i])
        assert valid == 1 and y == values[index]
        rhs += dense[shifts[i]]['output'][index]*y + 7*dense[shifts[i]]['validity'][index]*(1-valid)
    assert rhs % plan.P == expected
    # Bit-point demands use the SAME tensor pullback; validity is kept once.
    bit_point, bit_rhs = [3, 5, 7, 11], 0
    bit_values = {index: plan.rne48_output_bit_polynomials(
        [[int(j == ((raw+(1 << 47)) >> (8*l) & 255)) for j in range(256)] for l in range(6)], shifts[i])
        for i, index, raw in cells}
    for k in range(16):
        scaled = {i: [(hp, rp, cp, scale*eq(bit_point, k) % plan.P) for hp,rp,cp,scale in cs]
                  for i, cs in claims.items()}
        bit_forms = plan.auxiliary_rne_forms(rq, sources, scaled, shifts, r)
        for s in forms:
            assert bit_forms[s]['validity'] == forms[s]['validity']
            for offset, point, coefficient in bit_forms[s]['output']:
                assert offset+(1 << len(point)) <= len(cells)  # no biased-zero bit in dummy rows
            assert sum(scale*plan.folded_cube_form(o,q,[1],u) for o,q,scale in bit_forms[s]['output']) % plan.P == (
                eq(bit_point,k)*plan.mle(dense[s]['output'],u)) % plan.P
        bit_rhs += sum(eq(bit_point,k)*dense[shifts[i]]['output'][index]*bit_values[index][k] for i,index,_ in cells)
    expected_bits = sum(dense[shifts[i]]['output'][index]*sum(eq(bit_point,k)*((values[index]+32768) % plan.P >> k & 1)
                        for k in range(16)) for i,index,_ in cells) % plan.P
    assert bit_rhs % plan.P == expected_bits
    # A rejected value in an unobserved source leaves outputs unchanged but
    # gives a nonzero validity residual; padding never receives such a probe.
    _, bad_index, _ = next(cell for cell in cells if cell[0] == 4)
    digits = [((32768+(1 << 47)) >> (8*j)) & 255 for j in range(6)]
    _, valid = plan.rne48_byte_polynomials(digits, 0)
    assert valid == 0 and (7*dense[0]['validity'][bad_index]) % plan.P != 0
    native_values = [0]*16
    for t,h,c in product(range(3), range(2), range(2)):
        native_values[c+2*(h+2*t)] = plan.rne_i48_to_i16(-3+5*h+3*t+c,3) % plan.P
    pv_dense = sum(eq(pv[0],h)*eq(pv[1],t)*eq(pv[2],c)
                   *native_values[c+2*(h+2*t)] for t,h,c in product(range(3),range(2),range(2))) % plan.P
    assert pv_dense == plan.mle(native_values, pv_native)
    assert pv_dense != plan.mle(native_values, pv_native[:1]+pv_native[2:]+pv_native[1:2])
    for points, scale_map, vp in ((claims, {k:v for k,v in shifts.items() if k != 4}, r),
                                 ({**claims, 5: [qk]}, shifts, r),
                                 (claims, {**shifts, 0: True}, r),
                                 (claims, shifts, r[:-1])):
        with pytest.raises(ValueError):
            plan.auxiliary_rne_forms(rq, sources, points, scale_map, vp)


def test_gemma_rne_shift_rules_use_actual_owners_and_distinct_q_k_exponents():
    metadata = json.loads((Path(__file__).resolve().parents[1] /
                           'manifests/c7-d126-gemma31b-source-metadata-v1.json').read_bytes())
    cohorts = plan.gemma_weight_cohorts([t for t in metadata['tensors'] if t['disposition'] == 'private_text'])
    logical = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'scripts/c7_d126_gemma_qspec_dag.py'))
    manifest = plan.pinned_gemma_manifest()
    nodes = logical['expand_dag'](manifest, logical['_expand_schedule'](manifest['workload_schedule']))
    owners = {n.activation_scale_owner for n in nodes if n.activation_scale_owner is not None}
    assert len(owners) == 1434
    # Synthetic exponents only: no modification of the uninstantiated profile.
    activation = {key: i % 11-5 for i,key in enumerate(sorted(owners))}
    weights = {c['weight_key']: i % 9-6 for i,c in enumerate(cohorts)}
    activation.update({'layer/5/q_rope': -7, 'layer/5/k_rope': -2, 'layer/5/qk_matmul': 1,
                       'layer/5/softmax': -5, 'layer/5/v_norm': -3, 'layer/5/pv_matmul': 0,
                       'model/final_rms': 3, 'model/lm_head': 0})
    weights[cohorts[-1]['weight_key']] = -2
    shifts = plan.gemma_rne_shift_classes(cohorts, weights, activation)
    gamma = plan.gamma_barrier_plan(cohorts)
    assert set(shifts) == {(r['layer'],r['operation']) for r in gamma['cohorts'] if r['kind'] == 'rne48'}
    assert len(shifts) == 531 and shifts[5,'qk_matmul'] == 10
    activation.update({'layer/5/q_norm':-3,'layer/5/k_norm':4})
    with_rope = plan.gemma_rne_shift_classes(cohorts,weights,activation,True)
    extended_gamma = plan.gamma_barrier_plan(cohorts,True,True)
    assert set(with_rope) == {(r['layer'],r['operation']) for r in extended_gamma['cohorts'] if r['kind'] == 'rne48'}
    assert len(with_rope) == 651 and (with_rope[5,'q_rope'],with_rope[5,'k_rope']) == (26,24)
    for value,expected in ((-10**9,-15),(10**9,48)):
        assert plan.gemma_rne_shift_classes(cohorts,weights,{**activation,'layer/5/q_rope':value},True)[5,'q_rope'] == expected
    with pytest.raises(ValueError):
        plan.gemma_rne_shift_classes(cohorts,weights,{k:v for k,v in activation.items() if k != 'layer/5/q_norm'},True)
    assert shifts[5,'pv_matmul'] == 8 and shifts[None,'lm_head'] == -1
    assert 'model/last_row_select' not in activation
    for old in (0, 3946):
        sources = plan.auxiliary_word_sources(cohorts, old)
        _, rq = plan.auxiliary_word_layout(sources)
        source_shifts, source_points, cohort_points = {}, {}, {}
        for i, source in enumerate(sources):
            if not source['rne']:
                continue
            operation = {'qk_raw': 'qk_matmul', 'pv_raw': 'pv_matmul'}.get(source['operation'], source['operation'])
            key = (source['layer'], operation)
            source_shifts[i] = shifts[key]
            heads, rows, cols = source['shape']
            if operation == 'qk_matmul':
                rows, cols = 150, old+150
            point = tuple(list(range(2, 2+(d-1).bit_length())) for d in (heads, rows, cols))
            claim = (*point, 7)
            assert cohort_points.setdefault(key, claim) == claim  # all QK executions use one point/class
            source_points[i] = [claim]
        assert len(cohort_points) == 531 and len(source_shifts) == 3531
        n = (sum(h*r*c for _,_,_,h,r,c,_ in rq)-1).bit_length()
        forms = plan.auxiliary_rne_forms(rq, sources, source_points, source_shifts, [3]*n)
        assert sum(len(g['output']) for g in forms.values()) == len(rq)
        assert sum(len(g['validity']) for g in forms.values()) == len(rq)
    for exponent, expected in ((-1000, -15), (1000, 48)):
        assert plan.gemma_rne_shift_classes(cohorts, weights, {**activation, 'layer/5/qk_matmul': exponent})[5,'qk_matmul'] == expected
    for actual_shift in range(-50, 71):
        clipped = max(-15, min(48, actual_shift))
        for value in (-(1 << 47), -32768, -1, 0, 1, 32767, (1 << 47)-1):
            def outcome(s):
                try:
                    return plan.rne_i48_to_i16(value, s)
                except ValueError:
                    return 'reject'
            assert outcome(actual_shift) == outcome(clipped)
    for ws, acts in (({}, activation), (weights, {}), (weights, {**activation, 'layer/5/k_rope': None}),
                     (weights, {**activation, 'layer/5/k_rope': True})):
        with pytest.raises(ValueError):
            plan.gemma_rne_shift_classes(cohorts, ws, acts)


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
    assert [s['rne_public_form_screen']['verifier_extension_products_at_one_rq_point_upper_if_one_point_per_cohort']
            for s in (first, last)] == [2928948, 6185383]
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
        forms = s['rne_public_form_screen']
        assert forms['output_cohorts'] == 531
        assert forms['output_terms_if_one_point_per_cohort'] == forms['whole_live_domain_validity_terms'] == s['rq_cubes']
        assert forms['additional_mac_corrections_for_public_pullback'] == 0
        assert not forms['credit'] and not forms['actual_gamma_claim_count_and_public_shifts_instantiated']
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


def test_public_dyadic_addition_uses_bounded_words_for_arbitrary_exponent_gaps():
    def check(call, want):
        if -32767 <= want <= 32767:
            assert call() == want
        else:
            with pytest.raises(ValueError):
                call()
    for a,b in product((-32767,-5,-3,-1,0,1,3,5,32767),repeat=2):
        for gap,shift in product((0,1,15,16,17,48,129),range(-17,18)):
            want = round((a*Fraction(2)**gap+b)/Fraction(2)**(gap+shift))
            check(lambda: plan.rne_dyadic_add_i16(a,b,(gap,0,gap+shift)), want)
            check(lambda: plan.rne_dyadic_add_i16(b,a,(0,gap,gap+shift)), want)
    for a in range(-5,6):
        for b in range(-5,6):
            for ea,eb,eo in product((-3,0,2,7),(-3,0,2,7),(-4,1,6)):
                want = round((a*Fraction(2)**ea+b*Fraction(2)**eb)/Fraction(2)**eo)
                check(lambda: plan.rne_dyadic_add_i16(a,b,(ea,eb,eo)), want)
    for a,b,exponents in ((32767,32767,(0,0,1)), (-32767,-32767,(0,0,1)),
                           (32767,-32767,(100,100,100)), (1,-1,(4079,0,4079)),
                           (1,1,(0,1,0)), (32767,1,(0,0,0)), (-32767,-1,(0,0,0))):
        ea,eb,eo = exponents
        check(lambda: plan.rne_dyadic_add_i16(a,b,exponents),
              round((a*Fraction(2)**ea+b*Fraction(2)**eb)/Fraction(2)**eo))
    assert plan.rne_dyadic_add_i16(1,-1,(0,0,-10**9)) == 0
    assert plan.rne_dyadic_add_i16(32767,-32767,(0,1,10**9)) == 0
    assert plan.rne_dyadic_add_i16(0,32767,(10**9,0,0)) == 32767
    assert plan.rne_dyadic_add_i16(0,0,(0,10**9,0)) == 0
    for a,b in product((-3,-1,1,3),(-1,0,1)):
        expected = a//2+(int(b > 0) if b else (a//2)&1)
        assert plan.rne_dyadic_add_i16(a,b,(10**9,0,10**9+1)) == expected
    # A distant negative operand CAN repair high-term overflow at shift -15.
    assert plan.rne_dyadic_add_i16(1,-2,(16,0,1)) == 32767
    assert plan.rne_dyadic_add_i16(1,-3,(16,0,1)) == 32766
    for args in ((True,0,(0,0,0)), (-32768,0,(0,0,0)), (0,32768,(0,0,0)),
                 (0,0,(0,0)), (0,0,(0,False,0)), (1,0,(0,0,-10**9)),
                 (1,-1,(16,0,1)), (1,-32767,(16,0,0)), (1,1,(10**9,0,0))):
        with pytest.raises(ValueError):
            plan.rne_dyadic_add_i16(*args)
    # Every BF16 mantissa product fits the unchanged i48 raw contract.
    for a,m,shift in product((-32767,-1,0,1,32767),(-255,-147,-1,0,1,147,255),(-1,0,1,8,24)):
        want = round(Fraction(a*m,1 << shift)) if shift >= 0 else a*m*(1 << -shift)
        check(lambda: plan.rne_i48_to_i16(a*m,shift), want)


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


def test_rne_output_bits_preserve_signed_ties_overflow_and_degree_six():
    rng, p = random.Random(20260920), plan.P
    def indicators(value):
        return [[int(j == ((value+(1 << 47)) >> (8*l) & 255)) for j in range(256)] for l in range(6)]
    for shift in range(-15, 49):
        values = {-(1 << 47), (1 << 47)-1, -32768, -32767, -1, 0, 1, 32767, 32768}
        values.update(rng.randrange(-(1 << 47), 1 << 47) for _ in range(3))
        if shift > 0:
            values.update(q*(1 << shift)+(1 << (shift-1))+delta
                          for q in (-32768,-32767,-3,-2,-1,0,1,2,32766,32767) for delta in (-1,0,1))
        else:
            edge = 32767 >> -shift
            values.update(sign*(edge+delta) for sign in (-1,1) for delta in (-1,0,1))
        for value in sorted(v for v in values if -(1 << 47) <= v < 1 << 47):
            basis = indicators(value)
            bits = plan.rne48_output_bit_polynomials(basis, shift)
            assert all(b in (0,1) for b in bits)
            if shift <= -15:
                rounded = 0  # public invalid-output dummy agrees with the existing F_s
            elif shift <= 0:
                rounded = value << -shift
            else:
                quotient, remainder = divmod(abs(value), 1 << shift)
                rounded = quotient+int(2*remainder > 1 << shift or (2*remainder == 1 << shift and quotient & 1))
                rounded *= -1 if value < 0 else 1
            assert bits == [((rounded+32768) >> k) & 1 for k in range(16)]
            _, valid = plan.rne48_indicator_polynomials(basis, shift)
            if valid:
                assert sum(b << k for k,b in enumerate(bits)) == plan.rne_i48_to_i16(value,shift)+32768
            else:
                with pytest.raises(ValueError):
                    plan.rne_i48_to_i16(value,shift)
    # Wrapping bits cannot replace the existing, whole-domain overflow proof.
    assert plan.rne48_output_bit_polynomials(indicators(1),0) == plan.rne48_output_bit_polynomials(indicators(65537),0)
    assert plan.rne48_indicator_polynomials(indicators(1),0)[1] == 1
    assert plan.rne48_indicator_polynomials(indicators(65537),0)[1] == 0
    # Bias/sign extension at high shifts are part of the polynomial, not a
    # late conversion of the field residue or an unsigned raw-bit lookup.
    for value in (-1, 0):
        assert plan.rne48_output_bit_polynomials(indicators(value),0)[15] == int(value >= 0)
    assert plan.rne48_output_bit_polynomials(indicators(-(1 << 47)),47) == [1]*15+[0]
    line = []
    for z in range(9):
        low = [0,0,0,0,128,0]
        basis = [[((1-z)*int(j==x)+z*int(j==x+1)) % p for j in range(256)] for x in low]
        bits = plan.rne48_output_bit_polynomials(basis,40)
        assert bits[0] == (1-z-pow(1-z,6,p)) % p
        line.append((3+5*z)*bits[0] % p)
    for _ in range(7):
        line = [(b-a) % p for a,b in zip(line,line[1:])]
    assert line[0] != 0 and (line[1]-line[0]) % p == 0  # top degree seven, not eight
    # A complete two-round top check starts from actual rounded output bits
    # and ends at the SAME source-derived indicator claims, not folded raw.
    raw = [-(1 << 47)+(1 << 39)+d for d in (-1,0,1)]+[(1 << 47)-1]
    tables, query = [indicators(a) for a in raw], [2,3]
    def poly(point):
        basis = [[plan.mle([t[l][j] for t in tables],point) for j in range(256)] for l in range(6)]
        weight = math.prod((1-x)*(1-y)+x*y for x,y in zip(query,point)) % p
        return weight*plan.rne48_output_bit_polynomials(basis,40)[0] % p
    claim = plan.mle([(plan.rne_i48_to_i16(a,40)+32768)&1 for a in raw],query)
    prefix = []
    for coin in (17,19):
        def partial(x):
            return sum(poly(prefix+[x]+list(t)) for t in product((0,1),repeat=1-len(prefix))) % p
        assert claim == (partial(0)+partial(1)) % p
        samples = [partial(x) for x in range(9)]  # fixed before the challenge
        for _ in range(8):
            samples = [(b-a) % p for a,b in zip(samples,samples[1:])]
        assert samples == [0]
        claim = partial(coin)
        prefix.append(coin)
    assert claim == poly(prefix)
    for value, shift in ((0,-10**6),(0,10**6)):
        assert plan.rne48_output_bit_polynomials(indicators(value),shift) == [0]*15+[1]
    good = indicators(0)
    for bad, shift in ((good[:-1],0),([good[0][:-1]]+good[1:],0),([[True]+good[0][1:]]+good[1:],48),(good,True)):
        with pytest.raises(ValueError):
            plan.rne48_output_bit_polynomials(bad,shift)
    # Independent constrained-byte count for the exact nominated carry graph.
    per_class = []
    for s in range(1,48):
        masks = [set(range(s+1))]
        masks += [{min(j,47) for j in range(s-1,s+k)} for k in range(1,17)]
        per_class.append(sum(len({j//8 for j in mask})-1 for mask in masks))
    assert per_class == plan.rne_output_bit_screen(31)['additional_products_by_positive_shift']
    assert sum(per_class) == 764
    for bad in (0,33,True):
        with pytest.raises(ValueError):
            plan.rne_output_bit_screen(bad)


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


@pytest.mark.parametrize('mode', ('indicators', 'bits'))
def test_ps_gkr_binds_source_functions_with_optional_public_dummy_lanes(mode):
    p, rng = plan.P, random.Random(20260911)
    def eq(point, index):
        return math.prod(x if (index >> j) & 1 else 1-x for j, x in enumerate(point)) % p
    def fold(vector, r):
        return [(a+r*(b-a)) % p for a, b in zip(vector[::2], vector[1::2])]
    rho_f, rho_lane = [3, 5, 7, 11, 13, 17, 19, 23], [29, 31, 37]
    omega = [eq(rho_f, j) for j in range(256)]
    if mode == 'bits':
        rho_lane = []
        omega = [sum(eq(rho_f[:3], k)*((j >> k) & 1) for k in range(8)) % p for j in range(256)]
    for last_selector in (0, 1, 19):
        planes = [[(17*l+3) % 256, (31*l+1) % 256] for l in range(6 if mode == 'indicators' else 1)]
        if last_selector == 19:
            planes[-1][0] = 256  # the link still holds without presuming valid byte inputs
        point = [41]
        bases = [[plan.byte_lagrange_basis(x) for x in row] for row in planes]
        indicator_claims = [[plan.mle([basis[j] for basis in row], point) for j in range(256)] for row in bases]
        dummy_planes = [[0, 0], [0, 0]] if mode == 'indicators' else []
        dummy = (eq(rho_lane, 6)+eq(rho_lane, 7))*omega[0] % p if dummy_planes else 0
        claim = (sum(eq(rho_lane, l)*plan.dot(omega, row) for l, row in enumerate(indicator_claims))+dummy) % p
        trees = [plan.byte_lagrange_tree(x, omega) for row in planes+dummy_planes for x in row]
        assert claim == plan.mle([s[1] for _, s in trees], point+rho_lane)
        if mode == 'indicators':
            assert dummy != 0  # omitting the public lanes would change even the honest claim
        else:
            bit_claims = [sum(((j >> k) & 1)*v for j, v in enumerate(indicator_claims[0])) % p for k in range(8)]
            assert claim == sum(eq(rho_f[:3], k)*v for k, v in enumerate(bit_claims)) % p
        selector, node_point, cell_point, lane_point = 1, [], point, rho_lane
        retained = None
        for depth in range(8):
            arrays = [[tree[which][2*((1 << depth)+j)+child] for tree in trees for j in range(1 << depth)]
                      for which, child in ((0, 0), (0, 1), (1, 0), (1, 1))]
            weights = [eq(node_point+cell_point+lane_point, j) for j in range(len(arrays[0]))]
            assert claim == sum(w*((1-selector)*pl*pr+selector*(sl*pr+pl*sr))
                                for w, pl, pr, sl, sr in zip(weights, *arrays)) % p
            challenges = []
            for round_index in range(depth+1+len(rho_lane)):
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
                    retained = [(x+constant) % p for x in arrays[0][:len(planes)]]
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
        if mode == 'bits':
            changed_bits = bit_claims.copy()
            changed_bits[0] = (changed_bits[0]+eq(rho_f[:3], 1)) % p
            changed_bits[1] = (changed_bits[1]-eq(rho_f[:3], 0)) % p
            assert changed_bits != bit_claims
            assert (sum(eq(rho_f[:3], k)*v for k, v in enumerate(changed_bits))
                    -sum(eq(rho_f[:3], k)*v for k, v in enumerate(bit_claims))) % p == 0


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
