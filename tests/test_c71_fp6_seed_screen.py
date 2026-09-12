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
    seed = plan.c71_fp6_seed_screen(12883)
    assert seed['wire_total_both_directions']+8*560+8*560*22+24*560*19+48 == 40_699_897
    assert seed['COPE_data_only_received_lower']+8*560+8*560*22+48 == 39_679_664
    for rows in (0, 2**24-8):
        with pytest.raises(ValueError):
            plan.c71_fp6_seed_screen(rows)


def test_guarded_bootstrap_partial_screen_keeps_missing_costs_open():
    screen = plan.c71_dory_guarded_bootstrap_screen()
    assert screen['seed_base_rows'] == 12883
    assert screen['geometry'] == {
        't': 560, 'h': 19, 'N': 293_601_280,
        'published_base_capacity': 58_720_256,
        'noise': 'large-field regular with honest beta in Fp*',
        'canonical_fiber_positions': 153_931_627_888_640}
    assert screen['partial_wire_both_directions'] == 40_699_897
    assert screen['partial_margin_under_first_130MB'] == 89_300_103
    assert screen['received_lower'] == 39_679_664
    assert screen['received_plus_retained_PCS_and_other_body_lower'] == 62_310_716
    assert screen['first_cap_margin_after_that_lower'] == 67_689_284
    errors = screen['conditional_known_errors']
    assert Fraction(errors['path_guard']) == Fraction(10641, plan.P**3)
    assert Fraction(errors['domain_separated_ROM_prequeries']) == Fraction(2**74, plan.P**3)
    assert Fraction(errors['ROM_malformed_equality']) == Fraction(1, plan.P**3-2**74)
    assert Fraction(errors['split_check'])*2**74 > Fraction(1, 2**72)
    assert Fraction(errors['sum']) < Fraction(1, 2**90)
    assert not screen['credit'] and not screen['complete_bootstrap_admitted']
    assert len(screen['missing_for_admission']) == 6
