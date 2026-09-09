"""B8 construction checks. Variable-time reference algebra; never a production OT.

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
    assert r["next_authorized_goal"] is None and "B9" in r["next_proposed_goal"]
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
