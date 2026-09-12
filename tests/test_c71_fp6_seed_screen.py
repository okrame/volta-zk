"""Exact candidate field/compression/accounting checks; no native execution."""
import importlib.util
from fractions import Fraction
from itertools import product
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    'c7_1_gemma_plan', Path(__file__).resolve().parents[1]/'scripts/c7_1_gemma_plan.py')
plan = importlib.util.module_from_spec(spec)
spec.loader.exec_module(plan)


def test_fp6_seed_parameter_boundary_compression_and_complete_seed_count():
    p = plan.P
    # ell=2 works for rho=95 but NOT 96. The extension degree 3 is odd,
    # so a base nonsquare remains a nonsquare in Fp3.
    assert 2**190 < p**3 < 2**192
    assert pow(7, (p-1)//2, p) == p-1
    assert pow(7, (p**3-1)//2, p) == p-1
    add = lambda a, b: tuple((x+y) % p for x, y in zip(a, b))
    scale = lambda a, x: tuple(y*x % p for y in a)
    def compress(x, alpha):
        return add(plan.fp3_mul_six(x[:3], alpha[0]),
                   plan.fp3_mul_six(x[3:], alpha[1]))
    delta = (1, 2, 3, 4, 5, 6)
    key = (p-1, 13, 17, 19, 23, 29)
    for alpha in product(((0, 0, 0), (1, 0, 0), (2, 3, 5)), repeat=2):
        for x in (0, 1, 7, p-1):
            tag = add(key, scale(delta, x))
            assert compress(tag, alpha) == add(compress(key, alpha), scale(compress(delta, alpha), x))
    for rows in (1, 32, 25763, 2**24-9):
        screen = plan.c71_fp6_seed_screen(rows)
        assert screen['tree_depth'] <= 24
        assert screen['wire_total_both_directions'] == 146489+3120*rows
        assert sum(screen['wire_bytes_both_directions'].values()) == 146489+3120*rows
        assert screen['COPE_data_only_received_lower'] == 3072*rows
        error = Fraction(screen['conditional_seed_component']['sum'])
        reference = plan.b12_fixed_run_bootstrap()
        assert error == (Fraction(reference['conditional_component']['sum'])
                         - Fraction(1, 2**128)+Fraction(1, 2**95))
        assert Fraction(1, 2**91) < error < Fraction(1, 2**90)
        assert screen['primitive_hypotheses'] == reference['primitive_hypotheses']
        assert not screen['credit'] and not screen['native_implemented']
        assert not screen['complete_bootstrap_admitted']
    seed = plan.c71_fp6_seed_screen(25763)
    assert seed['wire_total_both_directions']+8*1120*23+24*1120*18+48 == 81_217_017
    assert seed['COPE_data_only_received_lower']+8*1120*23+48 == 79_350_064
    for rows in (0, 2**24-8):
        with pytest.raises(ValueError):
            plan.c71_fp6_seed_screen(rows)
