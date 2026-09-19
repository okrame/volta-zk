"""Small independent checks; no native proof, GPU, or full workspace claim."""
from random import Random
from test_c71_whir_trace import Fp3, fold
import c71_exp30_alternatives as alt


def test_tiled_patterns_preserve_every_original_cubic_in_prefix():
    rng = Random(71030)
    for bits, tile in ((2, 2), (3, 4), (4, 8)):
        n = (1 << bits) * 4
        # Nontrivial public padding, including a completely absent suffix.
        live = [j < (1 << bits)-1-(k % 2) and k != 3
                for j in range(1 << bits) for k in range(4)]
        rows = [[rng.randrange(2) if live[c] else 0 for _ in range(5)] for c in range(n)]
        gates = [('And', 0, 1), ('Xor', 2, 3), ('Copy', 4, 4), ('And', 0, 0)]
        weights = [Fp3(2+i, 3+i, 7+i) for i in range(len(gates))]
        point = [Fp3(3+i, 5, 9) for i in range(bits+2)]
        bins = alt.pattern_histogram(rows, live, gates, weights, point, bits, tile)
        original = alt.equality(point)
        for challenges in ([Fp3(0)]*bits, [Fp3(1)]*bits,
                           [Fp3(9+i, 2, 4) for i in range(bits)]):
            columns = [[Fp3(row[w]) for row in rows] for w in range(5)]
            selectors = [x * int(flag) for x, flag in zip(original, live)]
            for r in range(bits):
                # Four points identify a degree <=3 polynomial, plus non-base.
                for trial in [Fp3(i) for i in range(4)] + [Fp3(8, 2, 3)]:
                    wires = [fold(c, trial) for c in columns]
                    ss = fold(selectors, trial)
                    expected = 0
                    for (op, x, y), weight in zip(gates, weights):
                        for a, b, s in zip(wires[x], wires[y], ss):
                            v = a if op == 'Copy' else a*b if op == 'And' else a+b-2*a*b
                            expected += weight*s*v
                    assert alt.pattern_round_value(bins, point[:bits], challenges[:r],
                                                   trial, tile) == expected
                columns = [fold(c, challenges[r]) for c in columns]
                selectors = fold(selectors, challenges[r])


def test_ratio_residual_ties_and_original_histogram_counterexample():
    unit = 1 << 30
    # All nearby claimed outputs for a reduced grid and explicit half ties.
    for fractional in (0, 1, 2, 14):
        for denominator in range(1, 9):
            z = denominator * unit
            for e in range(0, unit+1, unit//16):
                q, r = divmod(e << fractional, z)
                rounded = q + (2*r > z or (2*r == z and q % 2 == 1))
                for pi in range(max(0, rounded-2), rounded+3):
                    assert alt.exact_ratio_predicate(e, z, pi, fractional) == (pi == rounded)
    # Same E/D histogram, Z and sum Pi; wrong positionwise Pi remains wrong.
    es = [unit, unit//2]
    z = sum(es)
    good = [10923, 5461]
    bad = list(reversed(good))
    assert sum(good) == sum(bad)
    assert all(alt.exact_ratio_predicate(e, z, p) for e, p in zip(es, good))
    assert not all(alt.exact_ratio_predicate(e, z, p) for e, p in zip(es, bad))


def test_prefix_component_screen_has_no_complete_or_hardware_credit():
    report = alt.report()
    assert not report['credit'] and not report['complete_work'] and not report['complete_peak']
    last = report['cases'][-1]['variants']
    assert [v['histogram_payload_bytes'] for v in last] == [1975296, 3548160]
    assert 8.4 < last[0]['unchanged_scalar_tail_lower_seconds'] < 8.5
    assert 4.2 < last[1]['unchanged_scalar_tail_lower_seconds'] < 4.3
    assert last[1]['weight_Fp3_products'] == 642858403200
