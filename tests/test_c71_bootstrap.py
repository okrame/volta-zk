"""B8–B11 construction/premise checks; never a production OT or pool adapter.

The small P-521 exchange checks real curve equations/bytes, not UC security.
The Fp9 check uses explicitly ideal COPE correlations, not a real PCG.
"""

import hashlib
import importlib.util
from fractions import Fraction
from itertools import product
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "plan", Path(__file__).resolve().parents[1] / "scripts/c7_1_gemma_plan.py")
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)

# RFC 5903 section 3.3: independent check of the proposed auxiliary group.
Q = (1 << 521) - 1
B = int("0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF1"
        "09E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", 16)
G = (int("00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D"
         "3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", 16),
     int("011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E"
         "662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650", 16))


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % Q == 0:
        return None
    slope = ((3 * x * x - 3) * pow(2 * y, -1, Q) if a == b
             else (v - y) * pow(u - x, -1, Q)) % Q
    z = (slope * slope - x - u) % Q
    return z, (slope * (x - z) - y) % Q


def mul(a, n):
    result = None
    while n:
        if n & 1:
            result = add(result, a)
        a, n = add(a, a), n >> 1
    return result


def encode(a):
    return bytes(67) if a is None else bytes([2 + (a[1] & 1)]) + a[0].to_bytes(66, "big")


def decode(wire):
    if len(wire) != 67:
        raise ValueError("point length")
    if wire == bytes(67):
        return None
    x = int.from_bytes(wire[1:], "big")
    if wire[0] not in (2, 3) or x >= Q:
        raise ValueError("point encoding")
    square = (x**3 - 3*x + B) % Q
    y = pow(square, (Q + 1) // 4, Q)
    if y*y % Q != square:
        raise ValueError("off curve")
    if y & 1 != wire[0] & 1:
        y = (-y) % Q
    if y & 1 != wire[0] & 1:
        raise ValueError("noncanonical sign")
    return x, y


def group_hash(context, branch, point):
    # A decoded random point has no publicly known discrete log. Each valid
    # group element, including infinity, has exactly one 522-bit candidate.
    for trial in range(512):
        wire = b"C71B8/group/" + context + bytes([branch]) + encode(point) + trial.to_bytes(2, "big")
        candidate = int.from_bytes(hashlib.shake_256(wire).digest(66), "big") & ((1 << 522) - 1)
        x, sign = candidate >> 1, candidate & 1
        if x == Q:
            if sign == 0:
                return None
            continue
        try:
            return decode(bytes([2 + sign]) + x.to_bytes(66, "big"))
        except ValueError:
            pass
    raise ValueError("group sampling exhausted")


def test_receiver_first_MR19_chosen_seeds_and_canonical_points():
    order = plan.b8_bootstrap_selection()["profile"]["group_order"]
    assert mul(G, order) is None and decode(encode(G)) == G
    assert decode(encode(None)) is None
    for wire in (b"", encode(G) + b"\x00", b"\x04" + encode(G)[1:],
                 b"\x02" + Q.to_bytes(66, "big"), b"\x00" * 66 + b"\x01"):
        with pytest.raises(ValueError):
            decode(wire)
    for choice in (0, 1):
        # Fixed coins make the reference reproducible; never real keygen.
        b = int.from_bytes(hashlib.sha512(b"receiver coins").digest(), "big")
        a = [int.from_bytes(hashlib.sha512(bytes([j])).digest(), "big") for j in (0, 1)]
        ctx = bytes([choice]) + b"independent-session-and-instance"
        r = [None, None]
        r[1-choice] = mul(G, b + 5)
        h = group_hash(ctx, choice, r[1-choice])
        r[choice] = add(mul(G, b), None if h is None else (h[0], -h[1] % Q))
        # Sender receives both points BEFORE creating either DH response.
        r = [decode(encode(p)) for p in r]
        A = [add(r[j], group_hash(ctx, j, r[1-j])) for j in (0, 1)]
        responses = [mul(G, scalar) for scalar in a]
        keys = [mul(A[j], a[j]) for j in (0, 1)]
        selected = mul(decode(encode(responses[choice])), b)
        assert selected == keys[choice]
        kdf = lambda j, key: hashlib.shake_256(b"C71B8/seed/" + ctx + bytes([j]) + encode(key)).digest(32)
        seeds = [bytes([71+j]) * 32 for j in (0, 1)]
        ciphertexts = [bytes(x ^ y for x, y in zip(seeds[j], kdf(j, keys[j]))) for j in (0, 1)]
        assert bytes(x ^ y for x, y in zip(ciphertexts[choice], kdf(choice, selected))) == seeds[choice]
        # B7's unchanged-context relay premise is absent in the new group RO.
        assert group_hash(ctx + b"other channel", choice, r[1-choice]) != h
    # A scalar-times-generator "hash to group" would let a malicious receiver
    # know BOTH logarithms. Session/index labels do not repair this shortcut.
    r = [mul(G, n) for n in (11, 13)]
    logs = [(n + int.from_bytes(hashlib.sha512(encode(r[1-j])).digest(), "big")) % order
            for j, n in enumerate((11, 13))]
    for j in (0, 1):
        assert mul(mul(G, logs[j]), 17+j) == mul(mul(G, 17+j), logs[j])


def test_sender_chosen_compiler_simulates_even_biased_endemic_outputs():
    # Exhaustive two-bit pads: the selected endemic pad may be adversarial.
    for c, selected_pad, s0, s1 in product(range(2), range(4), range(4), range(4)):
        real, simulated = [], []
        for hidden in range(4):
            pads = [hidden, hidden]
            pads[c] = selected_pad
            real.append((s0 ^ pads[0], s1 ^ pads[1]))
            sent = [hidden, hidden]
            sent[c] = (s0, s1)[c] ^ selected_pad
            simulated.append(tuple(sent))
        assert sorted(real) == sorted(simulated)
    # Against a corrupt sender both endemic pads are extractable before the
    # wrapping message; arbitrary ciphertexts define both chosen inputs.
    for pads in product(range(4), repeat=2):
        for wire in product(range(4), repeat=2):
            extracted = tuple(p ^ c for p, c in zip(pads, wire))
            assert all(extracted[c] == wire[c] ^ pads[c] for c in (0, 1))


def test_fp9_check_full_masks_and_fp3_compression_in_ideal_COPE():
    p = plan.P
    zero = (0,) * 9
    plus = lambda a, b: tuple((x+y) % p for x, y in zip(a, b))
    scale = lambda a, b: tuple(x*b % p for x in a)

    def times(a, b):
        out = [0] * 9
        for i, x in enumerate(a):
            for j, y in enumerate(b):
                out[(i+j) % 9] += x*y*(2 if i+j >= 9 else 1)
        return tuple(x % p for x in out)

    basis = [tuple(int(i == j) for i in range(9)) for j in range(9)]
    delta = tuple(p-3-2*i for i in range(9))
    plaintexts = (17, 19, 23)
    masks = tuple(range(29, 38))
    keys, tags = [], []
    for row, r in enumerate(plaintexts + masks):
        key, tag = [0]*9, [0]*9
        for limb in range(9):
            for bit in range(64):
                # Ideal OT delivers exactly the selected pad. These fixed
                # pads check COPE's equations, not PRF or OT security.
                q0 = (limb + bit + 3)*(row + 11)
                q1 = (limb + bit + 13)*(row + 19)
                c = (delta[limb] >> bit) & 1
                d = (q0 - q1 - r) % p
                tag[limb] += (1 << bit)*q0
                key[limb] += (1 << bit)*((q0, q1)[c] + c*d)
        tags.append(tuple(v % p for v in tag))
        keys.append(tuple(v % p for v in key))
        assert tags[-1] == plus(keys[-1], scale(delta, r))
    chi = [tuple(range(2+i, 11+i)) for i in range(3)]
    x, y, z = masks, zero, zero
    for i in range(3):
        x = plus(x, scale(chi[i], plaintexts[i]))
        y = plus(y, times(chi[i], keys[i]))
        z = plus(z, times(chi[i], tags[i]))
    for j in range(9):
        y = plus(y, times(basis[j], keys[3+j]))
        z = plus(z, times(basis[j], tags[3+j]))
    assert z == plus(y, times(delta, x))
    assert plus(z, basis[0]) != plus(y, times(delta, x))
    # Nine fresh Fp masks span all nine challenge-response coordinates.
    # This also checks the malicious-verifier simulator z=y+Delta*x.
    for j in range(9):
        changed = plus(x, basis[j])
        simulated = plus(y, times(delta, changed))
        assert simulated == plus(z, times(delta, basis[j]))
    # With one mask, an unmasked coordinate exposes the corresponding input
    # under a verifier-chosen challenge (the old base-field check is not used).
    assert scale(basis[1], plaintexts[0])[1] == plaintexts[0]

    alpha = ((2, 3, 5), (7, 11, 13), (17, 19, 23))
    add3 = lambda a, b: tuple((x+y) % p for x, y in zip(a, b))
    def compress(a):
        result = (0, 0, 0)
        for t in range(3):
            result = add3(result, plan.fp3_mul_six(alpha[t], (a[t], a[t+3], a[t+6])))
        return result
    for r, tag, key in zip(plaintexts, tags, keys):
        assert compress(tag) == add3(compress(key), tuple(c*r % p for c in compress(delta)))


def test_B8_source_selection_costs_and_conditional_security_are_separate():
    r = plan.baseline_budget()
    b8 = r["B8_bootstrap_selection"]
    assert b8["construction_selected"] and not b8["native_bootstrap_implemented"]
    assert not b8["security_admitted"] and not r["security_admitted"]
    assert r["B7_bootstrap_admission"]["baseline_stopped"]
    assert r["active_baseline_status"] == "stopped_after_failed_B7"
    assert r["next_authorized_goal"] is None and "B11" in r["next_proposed_goal"]
    security = b8["conditional_security"]
    terms = {k: Fraction(v) for k, v in security["terms_at_required_primitive_advantages"].items()}
    assert sum(terms.values()) == Fraction(security["sum_at_required_primitive_advantages"])
    assert sum(terms.values()) < Fraction(1, 1 << 82)
    assert not security["primitive_advantages_established_for_runtime"]
    order = b8["profile"]["group_order"]
    q = security["queries_including_honest_and_simulator_allowance"]
    count = security["OT_instances_upper"]
    assert q * (1 - Fraction(order, 1 << 522))**512 < terms["bounded_group_RO_sampler"]
    assert 4 * count * (1 - Fraction(order, 1 << 521))**8 < terms["bounded_scalar_sampler"]
    for case, wire in zip(b8["costs"], (383_065, 128_984_785)):
        n = case["wanted_base_svole"]
        assert case["bootstrap_protocol_wire_bytes"] == sum(case["wire_parts"].values()) == wire
        assert case["wire_parts"]["OT_receiver_points"] == 576*2*67
        assert case["wire_parts"]["OT_chosen_seed_ciphertexts"] == 576*2*32
        assert case["wire_parts"]["COPE_corrections"] == 576*(n+9)*8
        assert case["wire_parts"]["check_challenges"] == 72*n
        assert 3*case["full_fp3_after_packing"] + case["unpacked_base_rows"] == n
        assert case["complete_connection_bytes"]["admission_bound"] == "infinity"


def test_B9_native_boundary_counts_and_preserved_history():
    r = plan.baseline_budget()
    b9 = r["B9_bootstrap_component"]
    assert b9["native_bootstrap_implemented"]
    assert not any(b9[k] for k in ("security_admitted", "pool_PCS_integration_admitted", "production_runtime_admitted"))
    assert r["B7_bootstrap_admission"]["baseline_stopped"]
    assert r["active_baseline_status"] == "stopped_after_failed_B7"
    assert r["replacement_bootstrap_status"] == "B11_local_repairs_rejected_selection_open"
    assert r["next_authorized_goal"] is None and "B11" in r["next_proposed_goal"]
    assert b9["native_OT_call_counts_both_roles"] == {
        "fixed_base_scalar_multiplications": 2304, "variable_base_scalar_multiplications": 2304,
        "hash_to_group": 2304, "KDF": 2304, "point_additions": 1728, "scalar_candidates": 18432}
    assert b9["complete_connection_and_PCG_bytes"]["admission_bound"] == "infinity"
    assert len(b9["measured_cases"]) == 12
    assert sum(case["accepted"] for case in b9["measured_cases"]) == 2
    for case in b9["measured_cases"]:
        heap = case["heap"]
        assert heap["live_start_bytes"] + heap["allocated_bytes"] - heap["freed_bytes"] == heap["live_end_bytes"]
        assert case["process"]["sampled_peak_process_threads"] <= 2
        if not case["accepted"]:
            assert case["prover_error"] or case["verifier_error"]
            continue
        n, detail = case["rows"], case["details"]
        assert detail["protocol_wire_bytes"] == 191232 + 576*(n+9)*8 + 72*n + 601
        assert detail["all_base_rows_checked"] == n
        a, b = (detail[role]["work"] for role in ("prover", "verifier"))
        assert a["group_candidates"] == b["group_candidates"]
        assert a["prf_field_outputs"] + b["prf_field_outputs"] == 3*576*(n+9)
        assert a["field_candidates"] + b["field_candidates"] == 8*(3*576*(n+9)+10*n+27)
        assert a["check_fp9_products"] + b["check_fp9_products"] == 2*n+19
        assert a["compression_fp3_products"] + b["compression_fp3_products"] == 3*(2*n+1)


def test_B10_concrete_resources_do_not_turn_conditional_bounds_into_admission():
    report = plan.baseline_budget()
    b10 = report["B10_composition_admission"]
    assert not any(b10[k] for k in ("credit", "security_admitted", "production_runtime_admitted",
                                    "pool_PCS_integration_admitted"))
    resource = b10["primitive_resources"]
    assert resource["COPE_XOF_bytes_per_key_upper"] == 1_761_280
    assert resource["COPE_message_bytes"] == 215
    assert resource["COPE_field_evaluations_both_roles_per_setup"] == 47_554_560
    assert resource["COPE_distinct_key_message_pairs_per_setup"] == 31_703_040
    assert resource["COPE_XOF_bytes_both_roles_per_setup"] == 3_043_491_840
    assert resource["COPE_XOF_bytes_both_roles_lifetime"] == 3_043_491_840 * (1 << 20)
    # The actual B9 32-row count independently agrees with the maximum-row formula.
    case = next(c for c in report["B9_bootstrap_component"]["measured_cases"] if c["rows"] == 32)
    calls = sum(case["details"][role]["work"]["prf_field_outputs"] for role in ("prover", "verifier"))
    assert Fraction(calls, 32 + 9) == Fraction(resource["COPE_field_evaluations_both_roles_per_setup"], 27_520)
    assert resource["honest_SHAKE_calls_lifetime_upper"] < 1 << 64
    assert resource["adversary_environment_offline_work_bound"] is None
    assert not resource["primitive_advantages_established"]
    search = b10["legacy_AES_GGM_seed_search"]
    assert search["AES_public_permutation_calls"] == 1 << 64
    assert search["FS_queries_required"] == 0
    assert Fraction(search["advantage_lower_bound"]) == Fraction(1, 1 << 65) - Fraction(1, 1 << 193)
    assert Fraction(search["advantage_lower_bound"]) > Fraction(1, 1 << 78)
    assert b10["AES_PCG_composition"]["complete_connection_bytes"]["admission_bound"] == "infinity"
    assert not b10["same_W_lifecycle_contract"]["bootstrap_alone_binds_W"]
    assert report["G2_disposition"]["status"] == "archived_unselected_research"
    assert report["B7_bootstrap_admission"]["baseline_stopped"]


def test_B10_seed_enumeration_lower_bound_even_with_colliding_generator_outputs():
    # Exhaust ALL maps from two seed bits to four output bits. This is a
    # cardinality argument for any deterministic generator, not toy AES security.
    seeds, outputs, guesses = 4, 16, 2
    lower = Fraction(guesses, seeds) - Fraction(guesses, outputs)
    for table in product(range(outputs), repeat=seeds):
        recognized = set(table[:guesses])
        real = Fraction(sum(x in recognized for x in table), seeds)
        ideal = Fraction(len(recognized), outputs)
        assert real - ideal >= lower


def test_B10_valid_MAC_does_not_bind_weights_and_native_sign_is_opposite():
    p = plan.P
    add3 = lambda a, b: tuple((x + y) % p for x, y in zip(a, b))
    neg3 = lambda a: tuple(-x % p for x in a)
    mul3 = plan.fp3_mul_six
    delta, mask, key = (2, 3, 5), (7, 11, 13), (17, 19, 23)
    tag = add3(key, mul3(delta, mask))
    # The wrong W evaluation can be validly authenticated without knowing Delta.
    w, other_w, form = (2, 3, 5), (2, 4, 5), (7, 11, 13)
    expected, substituted = plan.dot(w, form), plan.dot(other_w, form)
    assert expected != substituted
    # Alternative executions, not permission to emit twice with one mask.
    for value in (expected, substituted):
        target = (value, 0, 0)
        correction = add3(target, neg3(mask))
        transferred = add3(key, neg3(mul3(delta, correction)))
        assert tag == add3(transferred, mul3(delta, target))
        # Existing c7_fp3_transfer_verifier adds Delta_native * correction.
        assert transferred == add3(key, mul3(neg3(delta), correction))
        assert transferred != add3(key, mul3(delta, correction))
    # If the PCS and GKR return separate handles, their equality is an obligation.
    residual = ((substituted - expected) % p, 0, 0)
    assert mul3(delta, residual) != (0, 0, 0)


def test_B10_fresh_masks_NoPeek_and_disjoint_key_epochs_are_distinct_premises():
    # G2's ideal correction simulator: every fixed x gives the same distribution,
    # including a malicious verifier's Delta=0. Reuse and mask-dependent x fail.
    p = 7
    for delta, key, x in product(range(p), repeat=3):
        real = sorted(((x-u) % p, (key-delta*(x-u)) % p) for u in range(p))
        simulated = sorted((d, (key-delta*d) % p) for d in range(p))
        assert real == simulated
    x0, x1 = 2, 5
    fresh = {((x0-u) % p, (x1-v) % p) for u, v in product(range(p), repeat=2)}
    reused = {((x0-u) % p, (x1-u) % p) for u in range(p)}
    assert len(fresh) == p*p and len(reused) == p
    assert all((a-b) % p == (x0-x1) % p for a, b in reused)
    assert {(u-u) % p for u in range(p)} == {0}  # x=u violates NoPeek
    # A fresh B9 setup has another Delta: even ideal rows cannot be mixed.
    deltas, values, keys = (2, 3), (4, 5), (1, 6)
    tags = tuple((k+d*x) % p for d, x, k in zip(deltas, values, keys))
    assert all(t == (k+d*x) % p for d, x, k, t in zip(deltas, values, keys, tags))
    assert sum(tags) % p != (sum(keys) + deltas[0]*sum(values)) % p


def test_B11_public_domains_and_single_use_epochs_retain_seed_search_bound():
    # Exhaust two independently labelled maps {0,1} -> {0,...,7}.
    # Record one target output, then search its public map after any renewal.
    # The other epoch is independent distraction, not a lifetime multiplier.
    maps = tuple(product(range(8), repeat=2))
    for domains in product(maps, repeat=2):
        for target in range(2):
            recognized = {domains[target][0]}  # one distinct seed guess
            real = Fraction(sum(domains[target][s[target]] in recognized
                                for s in product(range(2), repeat=2)), 4)
            ideal = Fraction(len(recognized), 8)
            assert real - ideal >= Fraction(1, 2) - Fraction(1, 8)


def test_B11_necessary_seed_and_work_thresholds_do_not_admit_a_profile():
    report = plan.baseline_budget()
    b11 = report["B11_local_repair_admission"]
    assert not any(b11[k] for k in ("credit", "security_admitted", "production_runtime_admitted",
                                    "pool_PCS_integration_admitted", "B11_positive_selection_complete"))
    assert b11["quantitatively_admissible_expansion_selected"] is None
    search = b11["single_target_search"]
    assert search["epochs_needed"] == search["samples_needed"] == 1
    assert search["FS_queries"] == 0 and not search["lifetime_multiplier_applied"]
    assert Fraction(search["advantage_lower_bound"]) > Fraction(1, 1 << 78)
    for case, width, work_bits in zip(search["necessary_conditions_only"], (141, 145), (51, 47)):
        assert case["minimum_seed_bits_not_excluded_at_fixed_guesses"] == width
        assert case["legacy_AES_calls_at_that_guess_count"] == 1 << work_bits
        target = Fraction(1, 1 << case["advantage_target_bits"])
        for s, passes in ((width-1, False), (width, True)):
            lower = Fraction((1 << (2*s)) - (1 << s), 1 << (3*s-63))
            assert (lower <= target) == passes
        q = case["maximum_128_bit_seed_guesses_not_excluded"]
        unit = Fraction((1 << 128) - 1, 1 << 256)
        assert q * unit <= target < (q+1) * unit
        assert not case["sufficient_security_condition"]
    assert not b11["resources"]["adversary_model_restricted"]
    assert b11["resources"]["offline_work_memory_preprocessing_advice_caps"] is None
    assert report["B7_bootstrap_admission"]["baseline_stopped"]
    assert report["G2_disposition"]["status"] == "archived_unselected_research"
    assert report["B10_composition_admission"]["status"] == "assessment_complete_integration_not_admitted"


def test_B11_bypasses_price_removed_dependencies_without_security_credit():
    report = plan.baseline_budget()
    b11 = report["B11_local_repair_admission"]
    direct = b11["direct_B9_bypass_screen"]
    assert not direct["selected"] and not direct["implements_required_AES_expansion"]
    # Reconcile the affine wire census with BOTH existing native measured sizes.
    for measured in report["B9_bootstrap_component"]["measured_cases"]:
        if measured["accepted"]:
            assert measured["details"]["protocol_wire_bytes"] == (
                direct["fixed_bootstrap_wire_bytes"] + measured["rows"] * direct["wire_bytes_per_base_row"])
    for case, rows, wire in zip(direct["cases"], (180, 207), (1_075_705, 1_202_065)):
        assert case["base_rows"] == rows == 3 * case["capacity_fp3"]
        assert case["bootstrap_wire_bytes"] == wire
        assert case["one_fresh_setup_per_slot_wire_bytes"] - wire == 466_610
        assert case["complete_connection_bytes"]["admission_bound"] == "infinity"
    ots = b11["direct_MR19_puncture_OT_screen"]
    assert ots["additional_independent_OTs"] == 37_211
    assert ots["additional_OT_payload_bytes_excluding_frames"] == 12_354_052
    assert ots["OTs_per_setup_including_B9"] == 37_787
    assert not ots["selected"] and not ots["secure_Fp3_parameters"]
    assert b11["published_extension_boundary"]["complete_concrete_error_bound"] is None


def test_B11_same_W_quantifier_survives_fresh_roots_and_key_epochs():
    # Ideal binding roots for this algebra fixture; no concrete hash/PCS claim.
    roots = {"installed": (1, 2), "fresh_same_W": (1, 2), "fresh_other_W": (3, 4)}
    form, p = (1, 0), 7
    openings = []
    for root, delta, mask, key in (("installed", 2, 6, 3), ("fresh_other_W", 5, 1, 4)):
        value = sum(a*b for a, b in zip(roots[root], form)) % p
        tag = (key + delta*mask) % p
        correction = (value-mask) % p
        transferred_key = (key-delta*correction) % p
        assert tag == (transferred_key + delta*value) % p
        openings.append((form, value))  # locally valid PCS and same MAC endpoint
    assert all(any(sum(a*b for a, b in zip(w, f)) % p == v
                   for w in product(range(p), repeat=2)) for f, v in openings)
    assert not any(all(sum(a*b for a, b in zip(w, f)) % p == v for f, v in openings)
                   for w in product(range(p), repeat=2))
    # Renewing randomness is compatible with same-W; activating an unrelated
    # root requires rejecting its link, even though both local proofs above pass.
    assert roots["fresh_same_W"] == roots["installed"]
    assert roots["fresh_other_W"] != roots["installed"]


def test_B9_native_hash_vectors_against_independent_python_curve():
    ctx, index, branch = b"native-source-vector", 17, 1
    suffix = ctx + index.to_bytes(4, "little") + bytes([branch]) + encode(G)
    for trial in range(512):
        raw = hashlib.shake_256(b"C71B9/group/receiver/" + suffix + trial.to_bytes(2, "little")).digest(66)
        candidate = int.from_bytes(raw, "big") & ((1 << 522) - 1)
        x, sign = candidate >> 1, candidate & 1
        if x == Q:
            if sign == 0:
                point = None
                break
            continue
        try:
            point = decode(bytes([2 + sign]) + x.to_bytes(66, "big"))
            break
        except ValueError:
            pass
    else:
        raise AssertionError("native vector group sampler exhausted")
    assert encode(point).hex() == (
        "0201d6ff4beab451430d54a88b7601ba34efe9d84d0406e74704e7bd367c54ede0f00"
        "d51a1f864a7f317c4dbdee5355f0513aabfd12fa97ecbebcc64815a6b559e915e")
    assert hashlib.shake_256(b"C71B9/seed/sender/" + suffix).hexdigest(32) == (
        "06893ac0862d2f3bc2241c8222de51d9f45b65d70e73ac762081df0a2c0d1347")
