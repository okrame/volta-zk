"""Finite algebra for two concrete streaming schedules; no native prover credit."""
import hashlib
import sys
from fractions import Fraction
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_streaming_screen as screen


def table(factors, p):
    out = [1]
    for a, b in factors:
        out = [x*y % p for x in out for y in (a, b)]
    return out


def fold(values, r, p):
    h = len(values)//2
    return [(a+r*(b-a)) % p for a, b in zip(values[:h], values[h:])]


def coefficients(a, b, p):
    h = len(a)//2
    c = [0, 0, 0]
    for a0, a1, b0, b1 in zip(a[:h], a[h:], b[:h], b[h:]):
        da, db = a1-a0, b1-b0
        c[0] += a0*b0
        c[1] += a0*db+da*b0
        c[2] += da*db
    return [x % p for x in c]


def challenge(transcript, c, p):
    transcript.append(c)
    return int.from_bytes(hashlib.sha256(repr(transcript).encode()).digest(), 'big') % p


def two_pass(source, factors, k, p):
    """Reference algebra only: pass 1 explicitly pays rank*N contractions."""
    d = len(factors[0])
    suffix = 1 << (d-k)
    u = [table(f[:k], p) for f in factors]
    v = [table(f[k:], p) for f in factors]
    a = [[0]*(1 << k) for _ in factors]
    for index, value in source():
        i, j = divmod(index, suffix)
        for row, weight in zip(a, v):
            row[i] = (row[i]+value*weight[j]) % p
    transcript, point = [], []
    for _ in range(k):
        cs = [coefficients(x, y, p) for x, y in zip(a, u)]
        c = [sum(x[t] for x in cs) % p for t in range(3)]
        r = challenge(transcript, c, p)
        point.append(r)
        a, u = ([fold(x, r, p) for x in rows] for rows in (a, u))
    prefix_weights = table([(1-r, r) for r in point], p)
    b = [0]*suffix
    for index, value in source():
        i, j = divmod(index, suffix)
        b[j] = (b[j]+prefix_weights[i]*value) % p
    public = [sum(x[0]*y[j] for x, y in zip(u, v)) % p for j in range(suffix)]
    for _ in range(d-k):
        c = coefficients(b, public, p)
        r = challenge(transcript, c, p)
        point.append(r)
        b, public = fold(b, r, p), fold(public, r, p)
    return transcript, point, b[0], public[0]


def test_two_pass_matches_dense_and_support_pruning_is_unsound():
    p = 97
    for d, k in ((2, 1), (5, 2), (6, 3)):
        values = [(i*i+7*i+11) % p for i in range(1 << d)]
        factors = [[(1-z, z) for z in [(r+3*j) % p for j in range(d)]]
                   for r in (0, 1, 7)]
        # Fixed prefix selectors include disjoint aligned cubes.
        factors[0][0], factors[1][0] = (1, 0), (0, 1)
        scans = []
        def source():
            scans.append(0)
            for item in enumerate(values):
                scans[-1] += 1
                yield item
        actual = two_pass(source, factors, k, p)
        a = values[:]
        b = [sum(xs) % p for xs in zip(*(table(f, p) for f in factors))]
        transcript, point = [], []
        for _ in range(d):
            r = challenge(transcript, coefficients(a, b, p), p)
            point.append(r)
            a, b = fold(a, r, p), fold(b, r, p)
        assert actual == (transcript, point, a[0], b[0])
        assert scans == [1 << d, 1 << d]
    # W(x,y)=x*(1-y), L(x,y)=(1-x)*(1-y). Boolean target is zero,
    # but the first sumcheck polynomial is x-x^2. Dropping A(1), just
    # because the original cube has prefix zero, wrongly sends all zeros.
    assert coefficients([0, 0, 1, 0], [1, 0, 0, 0], p) == [0, 1, p-1]
    assert coefficients([0, 0], [1, 0], p) == [0, 0, 0]


def test_coset_encoding_is_exact_but_replays_full_coefficients():
    p, height, size = 97, 32, 4
    g = pow(5, (p-1)//height, p)
    coeffs = [2, 7, 11, 13, 17, 23, 29, 31, 37, 41]
    values = {}
    for coset in range(height//size):
        z = pow(g, coset, p)
        reduced = [0]*size
        for i, a in enumerate(coeffs):
            reduced[i % size] = (reduced[i % size]+a*pow(z, i, p)) % p
        for j in range(size):
            y = pow(g, (height//size)*j, p)
            index = coset+(height//size)*j
            values[index] = sum(a*pow(y, i, p) for i, a in enumerate(reduced)) % p
    assert values == {j: sum(a*pow(g, j*i, p) for i, a in enumerate(coeffs)) % p
                      for j in range(height)}
    r = screen.report()
    assert [x['body_wire_interval'][0] for x in r['wire']] == [47841180, 54868318, 61797384]
    assert r['wire'][0]['known_primitives_plus_body_interval'] == [109682470, 126894534]
    assert r['canonical_required_base_rows'] == 11466948 < r['Dory_base_capacity']
    by_d = {x['dimension']: x for x in r['coset_replay']}
    assert by_d[35]['full_source_scans_lower'] == 683
    assert by_d[34]['full_source_scans_lower'] == 342
    assert by_d[35]['buffer_bytes_needed_for_four_scans_lower'] == 1 << 40
    assert by_d[34]['buffer_bytes_needed_for_four_scans_lower'] == 1 << 39
    assert all(Fraction(x) < Fraction(1, 1 << 78)
               for x in r['conditional_B12_plus_bootstrap_union'].values())
    assert not r['goal_complete'] and not r['physical_schedule_admitted']
    suffix = r['suffix_first_W_linear_reducer']
    assert suffix['cube_count'] == 3622
    assert suffix['named_arrays_simultaneous_bytes'] == 2898788352 < r['arena_bytes']
    assert suffix['first_scan_update_model'] == 280138842112
    assert suffix['both_scans_update_model'] == 314498580480
    assert not suffix['includes_PCS_range_witness_or_runtime']


def test_suffix_first_restores_the_original_PCS_endpoint():
    p, d, suffix_bits = 97, 6, 2
    values = [(11*i+i*i+3) % p for i in range(1 << d)]
    # Two aligned cubes: prefix selectors stay in the contracted half.
    factors = [[(1, 0), (0, 1), (1, 0), (1-7, 7), (1-11, 11), (1-19, 19)],
               [(0, 1), (1, 0), (1, 0), (1-13, 13), (1-17, 17), (1-23, 23)]]
    reordered = [f[-suffix_bits:]+f[:-suffix_bits] for f in factors]
    scans = []
    def source():
        scans.append(0)
        for index, value in enumerate(values):
            prefix, suffix = divmod(index, 1 << suffix_bits)
            scans[-1] += 1
            yield (suffix << (d-suffix_bits))+prefix, value
    _, new_point, value, public = two_pass(source, reordered, suffix_bits, p)
    original_point = new_point[suffix_bits:]+new_point[:suffix_bits]
    eq = table([(1-r, r) for r in original_point], p)
    original_L = [sum(xs) % p for xs in zip(*(table(f, p) for f in factors))]
    assert value == sum(x*w for x, w in zip(values, eq)) % p
    assert public == sum(x*w for x, w in zip(original_L, eq)) % p
    assert scans == [1 << d, 1 << d]
