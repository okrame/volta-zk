"""Small C7.1 accounting/algebra checks; no weights, compiler or GPU."""

import importlib.util
import math
import random
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
