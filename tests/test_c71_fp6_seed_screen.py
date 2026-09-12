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
    seed = plan.c71_fp6_seed_screen(15528)
    assert seed['wire_total_both_directions']+8*675+8*675*22+24*675*19+48 == 49_025_897
    assert seed['COPE_data_only_received_lower']+8*675+8*675*22+48 == 47_826_264
    for rows in (0, 2**24-8):
        with pytest.raises(ValueError):
            plan.c71_fp6_seed_screen(rows)


def test_guarded_bootstrap_partial_screen_keeps_missing_costs_open():
    screen = plan.c71_dory_guarded_bootstrap_screen()
    assert screen['seed_base_rows'] == 15528
    assert screen['geometry'] == {
        't': 675, 'h': 19, 'ell': 11, 'N': 353_894_400,
        'candidate_base_capacity': 70_778_880,
        'noise': 'large-field regular with honest beta in Fp*',
        'canonical_fiber_positions': 185_542_587_187_200}
    assert screen['partial_wire_both_directions'] == 49_025_897
    assert screen['partial_margin_under_first_130MB'] == 80_974_103
    coin = screen['coin_toss']
    assert coin['FRand_wire_bytes'] == 128
    assert coin['three_frame_headers_bytes'] == 18
    assert coin['wire_bytes_both_directions'] == 146
    assert screen['rejected_equality_candidate']['wire_bytes_both_directions'] == 32_482
    assert screen['partial_with_coin_wire'] == 49_026_043
    assert screen['margin_after_coin'] == 80_973_957
    feq = screen['private_equality_candidate']
    assert feq['wire_bytes_both_directions'] == 12_815_247
    assert feq['forward_extra_auth_rows'] == feq['reverse_seed_rows'] == 2025
    assert feq['seed_wire_bytes'] == 12_782_489
    assert feq['input_correction_wire_bytes'] == 32_412
    assert feq['second_coin_wire_bytes'] == 146
    assert feq['share_commit_open_wire_bytes'] == 200
    assert not feq['new_computational_assumption']
    assert screen['partial_with_coin_and_private_equality_wire'] == 61_841_290
    assert screen['margin_after_coin_and_private_equality'] == 68_158_710
    assert screen['partial_plus_current_first_body_upper'] == 114_079_141
    assert screen['margin_after_current_first_body_upper'] == 15_920_859
    assert screen['partial_coin_plus_current_first_body_upper'] == 114_079_287
    assert screen['margin_after_coin_and_current_first_body_upper'] == 15_920_713
    assert screen['partial_coin_private_equality_plus_current_first_body_upper'] == 126_894_534
    assert screen['margin_after_coin_private_equality_and_current_first_body_upper'] == 3_105_466
    assert screen['received_lower'] == 47_826_264
    assert screen['received_plus_retained_PCS_and_other_body_lower'] == 70_457_316
    assert screen['first_cap_margin_after_that_lower'] == 59_542_684
    errors = screen['conditional_known_errors']
    assert Fraction(errors['path_guard']) == Fraction(12826, plan.P**3)
    assert Fraction(errors['domain_separated_ROM_prequeries']) == Fraction(2**74, plan.P**3)
    assert Fraction(errors['ROM_malformed_equality']) == Fraction(1, plan.P**3-2**74)
    assert Fraction(errors['FRand_ROM_commitment']) < Fraction(1, 2**108)
    assert Fraction(errors['FRand_XOF_seed_prequery']) == Fraction(2**74, 2**256)
    assert Fraction(errors['FRand_bounded_Fp3_sampling']) < Fraction(1, 2**226)
    assert Fraction(errors['private_FEq_information_theoretic']) < Fraction(1, 2**107)
    assert Fraction(errors['private_FEq_reverse_seed']) == Fraction(errors['seed'])
    assert Fraction(errors['split_check'])*2**74 > Fraction(1, 2**72)
    assert Fraction(1, 2**90) < Fraction(errors['sum']) < Fraction(1, 2**89)
    assert not screen['credit'] and not screen['complete_bootstrap_admitted']


def test_private_equality_from_opposite_mac_keys():
    p = 5
    for value_v, value_w in product(range(p), repeat=2):
        delta0, delta1 = 2, 4
        random_w, key_w = 1, 3
        random_v, key_v = 2, 1
        tag_w = (key_w+delta0*random_w) % p
        tag_v = (key_v+delta1*random_v) % p
        correction_w = (value_w-random_w) % p
        correction_v = (value_v-random_v) % p
        key_w = (key_w-delta0*correction_w) % p
        key_v = (key_v-delta1*correction_v) % p
        assert tag_w == (key_w+delta0*value_w) % p
        assert tag_v == (key_v+delta1*value_v) % p
        share0 = (-key_w-delta0*value_v-tag_v) % p
        share1 = (tag_w+delta1*value_w+key_v) % p
        opened = (share0+share1) % p
        assert opened == (delta0+delta1)*(value_w-value_v) % p
        assert (opened == 0) == (value_w == value_v)

    # With one honest key, every nonzero difference opens uniformly; the
    # other party learns only zero/nonzero (up to the 1/|K| zero mask).
    for corrupt_delta, difference in product(range(p), range(1, p)):
        assert sorted((corrupt_delta+honest_delta)*difference % p
                      for honest_delta in range(p)) == list(range(p))
