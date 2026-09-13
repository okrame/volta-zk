"""Finite algebra only; no native PCS or hardware credit."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_query_remainder as remainder


def evaluate(coefficients, point, p):
    value = 0
    for coefficient in reversed(coefficients):
        value = (value*point+coefficient) % p
    return value


def naive_remainder(coefficients, modulus, p):
    value = coefficients[:]
    for degree in range(len(value)-1, len(modulus)-2, -1):
        quotient = value[degree]
        for i, coefficient in enumerate(modulus):
            value[degree-len(modulus)+1+i] = (
                value[degree-len(modulus)+1+i]-quotient*coefficient) % p
    return (value[:len(modulus)-1]+[0]*(len(modulus)-1))[:len(modulus)-1]


def test_fixed_cap_block_remainder_matches_division_and_selected_rs_rows():
    p = remainder.base.P
    for cap, source_len in ((8, 19), (16, 64)):
        domain_size = 1 << (source_len-1).bit_length()
        omega = pow(7, (p-1)//domain_size, p)
        selected_indices = [domain_size-1] + list(range(0, source_len, 3))
        selected_indices = selected_indices[:cap//2]
        selected = [pow(omega, i, p) for i in selected_indices]
        dummy_indices = [i for i in range(domain_size)
                         if i not in selected_indices][:cap-len(selected)]
        dummy = [pow(omega, i, p) for i in dummy_indices]
        points = selected+dummy
        modulus = remainder.product_polynomial(points)
        payload = [(11*i*i+5*i+7) % p for i in range(source_len-3)]
        private_pad = [p-17, 23, p-31]
        coefficients = payload+private_pad+[0]*(domain_size-source_len)
        actual, blocks = remainder.remainder_by_blocks(coefficients, modulus, cap)
        assert actual == naive_remainder(coefficients, modulus, p)
        assert blocks == (len(coefficients)+cap-1)//cap
        if cap == 8:
            partial_actual, partial_blocks = remainder.remainder_by_blocks(
                coefficients[:source_len], modulus, cap)
            assert partial_actual == naive_remainder(
                coefficients[:source_len], modulus, p)
            assert source_len % cap and partial_blocks == 3
        assert [evaluate(actual, point, p) for point in selected] == [
            evaluate(coefficients, point, p) for point in selected]
        if source_len < domain_size:
            assert selected_indices[0] >= source_len  # padded-domain RS row
        budget = remainder.report()
        assert budget['fixed_point_cap'] == 1 << 21
        assert budget['selected_rows_upper'] == 512*4096
        assert budget['pointwise_products_per_source_cell'] == 4
        assert budget['inverse_normalizations_per_source_cell'] == 4
        assert budget['online_ffts_per_block_with_shared_fixed_transforms'] == 4
        assert budget['small_test_ffts_per_block'] == 4
        assert budget['source_passes'] == 1 and budget['native_or_runtime_upper'] is None
