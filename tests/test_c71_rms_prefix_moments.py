"""Independent small field oracle and original-support projection checks."""
from random import Random

import pytest
from test_c71_whir_trace import Fp3, eq_table, fold
import c71_rms_prefix_moments as rms
from c71_exp30_bmma import moment_round_value


def dense_value(rows, assignments, programs, weights, point, challenges):
    wires = [[Fp3(value) for value in row] for row in rows]
    selectors = [[weight if p == program else Fp3()
                  for p, weight in zip(assignments, eq_table(point))]
                 for program in range(len(programs))]
    for challenge in challenges:
        half = len(wires) // 2
        wires = [[x + challenge * (y - x) for x, y in zip(lo, hi)]
                 for lo, hi in zip(wires[:half], wires[half:])]
        selectors = [fold(values, challenge) for values in selectors]
    total = Fp3()
    for k, row in enumerate(wires):
        for p, gates in enumerate(programs):
            for (op, x, y), weight in zip(gates, weights):
                value = row[x] if op == 'Copy' else row[x] * row[y]
                if op == 'Xor':
                    value = row[x] + row[y] - 2 * value
                total += selectors[p][k] * weight * value
    return total


def test_mixed_moments_preserve_all_cubic_values_and_other_program_wires():
    rng = Random(710511)
    programs = [[('And', 0, 1), ('Xor', 1, 2), ('Copy', 3, 3)],
                [('Xor', 0, 3), ('And', 2, 2)], [('Copy', 1, 1)]]
    weights = [Fp3(2 + i, 7, 9) for i in range(3)]
    for bits in (2, 3, 4):
        n = 4 << bits
        assignments = [None if i % 7 == 0 else (i * 5 + i // 3) % 3 for i in range(n)]
        rows = [[rng.randrange(2) if assignments[i] is not None else 0 for _ in range(4)]
                for i in range(n)]
        for point in ([Fp3(3 + i, 2, 5) for i in range(bits + 2)],
                      [Fp3(i % 2) for i in range(bits + 2)]):
            moments = rms.mixed_moments(rows, assignments, programs, weights, point, bits)
            for challenges in ([Fp3()] * bits, [Fp3(1)] * bits,
                               [Fp3(4 + i, 3, 9) for i in range(bits)]):
                for r in range(bits):
                    # Five distinct values independently identify the cubic over F97.
                    for trial in [Fp3(i) for i in range(4)] + [Fp3(9, 2, 4)]:
                        assert moment_round_value(moments, point[:bits], challenges[:r], trial) == dense_value(
                            rows, assignments, programs, weights, point, [*challenges[:r], trial])


def test_support_projection_matches_every_original_cell_without_field_pruning():
    rng = Random(710889)
    for n in (8, 16, 64, 256):
        assigned = [rng.choice([None, 0, 1, 2]) for _ in range(n)]
        spans = [[(i, i + 1) for i, p in enumerate(assigned) if p == program] for program in range(3)]
        for bits in range(1, min(8, n.bit_length() - 1) + 1):
            suffix = n >> bits
            for start, end, masks in rms.support_sections(n, spans, bits):
                for k in range(start, end):
                    assert dict(masks) == {p: mask for p in range(3)
                                          if (mask := sum((assigned[j * suffix + k] == p) << j
                                                          for j in range(1 << bits)))}
            assert rms.geometry(n, spans, bits)['live_cells'] == sum(p is not None for p in assigned)
    for n, spans, bits in [(7, [[(0, 1)]], 1), (8, [[(-1, 2)]], 1),
                          (8, [[(0, 4)], [(3, 5)]], 1), (8, [[(0, 1)]], 4)]:
        with pytest.raises(ValueError):
            list(rms.support_sections(n, spans, bits))


def test_moment_oracle_rejects_nonzero_padding_and_bad_original_parents():
    args = ([[0, 1], [0, 0]], [0, None], [[('Copy', 1, 1)]], [Fp3(3)], [Fp3(2)], 1)
    assert rms.mixed_moments(*args)
    with pytest.raises(ValueError):
        rms.mixed_moments([[0, 1], [1, 0]], *args[1:])
    with pytest.raises(ValueError):
        rms.mixed_moments(args[0], args[1], [[('And', 2, 1)]], *args[3:])
