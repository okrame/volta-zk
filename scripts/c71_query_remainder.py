#!/usr/bin/env python3
"""Small algebra/count screen for a fixed-cap query remainder encoder."""
import json

import c7_1_gemma_plan as base


def inverse_fft(values):
    if len(values) == 1:
        return values[:]
    scale = pow(len(values), base.P-2, base.P)
    return [x*scale % base.P
            for x in base.small_goldilocks_fft([values[0], *values[:0:-1]])]


def convolution(left, right, size):
    a = base.small_goldilocks_fft(left+[0]*(size-len(left)))
    b = base.small_goldilocks_fft(right+[0]*(size-len(right)))
    return inverse_fft([x*y % base.P for x, y in zip(a, b)])


def product_polynomial(points):
    """Small-test helper; production needs a balanced product tree."""
    result = [1]
    for point in points:
        result = convolution(result, [-point % base.P, 1],
                             1 << (len(result)+1).bit_length())[:len(result)+1]
    return result


def reciprocal_reversed(monic, cap):
    reverse = monic[::-1]
    inverse = [pow(reverse[0], base.P-2, base.P)]
    for degree in range(1, cap):
        inverse.append(-inverse[0]*sum(reverse[i]*inverse[degree-i]
                                      for i in range(1, min(degree, len(reverse)-1)+1))
                       % base.P)
    return inverse


def reduce_block_fft(remainder, block, modulus, fixed_transforms):
    cap, size = len(modulus)-1, 2*(len(modulus)-1)
    dividend = block+[0]*(cap-len(block))+remainder
    # Only the B high coefficients determine the degree-<B quotient.
    # Including the low half would turn the length-2B FFT into a cyclic
    # convolution and alias unused high coefficients into this prefix.
    inverse_spectrum, modulus_spectrum = fixed_transforms
    high_spectrum = base.small_goldilocks_fft(dividend[::-1][:cap]+[0]*cap)
    quotient_reverse = inverse_fft([
        x*y % base.P for x, y in zip(high_spectrum, inverse_spectrum)])[:cap]
    quotient = quotient_reverse[::-1]
    quotient_spectrum = base.small_goldilocks_fft(quotient+[0]*cap)
    product = inverse_fft([
        x*y % base.P for x, y in zip(quotient_spectrum, modulus_spectrum)])
    reduced = [(dividend[i]-product[i]) % base.P for i in range(cap)]
    assert all((dividend[i]-product[i]) % base.P == 0 for i in range(cap, size))
    return reduced


def remainder_by_blocks(coefficients, modulus, cap):
    if len(modulus) != cap+1 or modulus[-1] != 1:
        raise ValueError('fixed-cap monic modulus required')
    inverse = reciprocal_reversed(modulus, cap)
    fixed_transforms = (base.small_goldilocks_fft(inverse+[0]*cap),
                        base.small_goldilocks_fft(modulus+[0]*(cap-1)))
    blocks = [coefficients[i:i+cap] for i in range(0, len(coefficients), cap)]
    remainder = [0]*cap
    for block in reversed(blocks):
        remainder = reduce_block_fft(remainder, block, modulus, fixed_transforms)
    return remainder, len(blocks)


def report():
    # Fixed algorithm cap, not a function of runtime query count/source size.
    cap, columns, leaf_rows = 1 << 21, 128, 1 << 12
    output = cap*columns*8
    levels = cap.bit_length()-1
    # Store every fixed product, reciprocal and spectral factor. This avoids
    # relying on a clever lifetime overlap before a native allocator exists.
    named_buffers = {
        'selected_rows_output': output,
        'full_product_tree': 8*((levels+3)*cap-1),
        'reciprocal_coefficients_all_levels': 8*(levels+1)*cap,
        'two_length_2degree_spectra_per_node_all_levels': 32*(levels+1)*cap,
        'four_length_2B_FFT_work_arrays': 64*cap,
        'evaluation_remainders_pingpong': 16*cap,
        'source_column_remainder': 8*cap,
        'selected_and_dummy_points': 8*cap,
        'FFT_twiddles': 16*cap,
        'W_and_three_A_persistent_cache': 188_743_552,
        'metadata_slot_cap': 128 << 20,
        'hash_and_reader_slot_cap': 256 << 20,
        'W_histogram': 65535*8,
        'PCG_output_batch': 4096*16,
        'proof_output_cap': 130_000_000,
    }
    return {
        'credit': False,
        'fixed_point_cap': cap,
        'maximum_private_queries': 512,
        'leaf_rows_per_cached_subtree': leaf_rows,
        'selected_rows_upper': cap,
        'output_base_field_bytes': output,
        'source_passes': 1,
        'butterflies_per_source_cell': 88,
        # Two length-2B convolution products per block give 4B products.
        # Eight is retained as an explicit conservative accounting cap.
        'pointwise_products_per_source_cell': 4,
        'inverse_normalizations_per_source_cell': 4,
        'pointwise_products_per_source_cell_upper': 8,
        'online_ffts_per_block_with_shared_fixed_transforms': 4,
        'small_test_ffts_per_block': 4,
        'shared_fixed_precomputed_FFTs': 2,
        'five_pass_fft_cross_twiddle_products_per_source_cell': 8,
        'fixed_FFT_length': 2*cap,
        'W_and_three_A_top_Merkle_bytes': 167_772_032,
        'W_and_three_A_salt_start_offsets_bytes': 20_971_520,
        'persistent_cache_bytes': 188_743_552,
        'query_evaluation_butterflies_upper_128_columns':
            2*cap*levels*(levels+1)*columns,
        'query_named_buffer_plan': named_buffers,
        'query_named_peak_bytes': sum(named_buffers.values()),
        'query_margin_before_other_live_state': 6_442_450_944-sum(named_buffers.values()),
        'buffer_slot_caps_and_smaller_FFT_kernels_not_natively_verified': True,
        'query_work': 'subproduct-tree remainder evaluation; independent of source length',
        'native_or_runtime_upper': None,
    }


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
