#!/usr/bin/env python3
"""Two EXP30 research screens; no native protocol or hardware admission."""

from collections import defaultdict
import json

import c71_gkr_screen as gkr
from c71_main_cell_screen import NATIVE_RECORD, SCALAR_RESULT_CEILING


def equality(point):
    values = [1]
    for r in point:
        one = r * 0 + 1
        values = [v * factor for v in values for factor in (one - r, r)]
    return values


def pattern_histogram(rows, live, gates, weights, selector_point, prefix_bits, tile_bits):
    """Internal weighted bins, built before the current layer's cell challenges.

    Gates are (And/Xor/Copy, x, y). Rows are original Boolean wires in
    existing MSB cell order. This small oracle does not implement a packed
    producer; its scalar Python input-reading cost earns no speed credit.
    """
    n, block = len(rows), 1 << prefix_bits
    assert n == 1 << len(selector_point) and 0 < prefix_bits <= len(selector_point)
    assert len(live) == n and len(gates) == len(weights) and tile_bits > 0
    assert all(v in (0, 1) for row in rows for v in row)
    assert all(flag or not any(row) for flag, row in zip(live, rows))
    suffix = n // block
    suffix_weights = equality(selector_point[prefix_bits:])
    bins = defaultdict(int)
    for k in range(suffix):
        mask = sum(int(live[j * suffix + k]) << j for j in range(block))
        if not mask:
            continue
        patterns = []
        for wire in range(len(rows[0])):
            patterns.append([
                sum(rows[(start + j) * suffix + k][wire] << j
                    for j in range(min(tile_bits, block - start)))
                for start in range(0, block, tile_bits)])
        for (op, x, y), gate_weight in zip(gates, weights):
            assert op in ('And', 'Xor', 'Copy')
            weight = gate_weight * suffix_weights[k]
            if op != 'Copy':
                # XOR = x+y-2xy; consolidate all gates in the same two bins.
                bilinear = weight if op == 'And' else weight * -2
                for a, px in enumerate(patterns[x]):
                    for b, py in enumerate(patterns[y]):
                        bins[(mask, a, px, b, py)] += bilinear
            if op != 'And':
                for wire in ((x,) if op == 'Copy' else (x, y)):
                    for a, px in enumerate(patterns[wire]):
                        bins[(mask, a, px, -1, 0)] += weight
    return dict(bins)


def pattern_round_value(bins, selector_prefix, prefix, trial, tile_bits):
    """Value of the *original cubic* at trial, with earlier challenges fixed."""
    bits = len(selector_prefix)
    assert len(prefix) < bits
    original = equality(selector_prefix)
    total = 0
    for tail in range(1 << (bits - len(prefix) - 1)):
        tail_bits = [(tail >> j) & 1 for j in reversed(range(bits - len(prefix) - 1))]
        folded = equality([*prefix, trial, *tail_bits])
        for (mask, a, px, b, py), weight in bins.items():
            selector = sum(v * w for j, (v, w) in enumerate(zip(original, folded))
                           if mask >> j & 1)
            def value(tile, pattern):
                return sum(folded[j] for j in range(tile * tile_bits,
                           min((tile + 1) * tile_bits, len(folded)))
                           if pattern >> (j - tile * tile_bits) & 1)
            product = value(a, px)
            if b >= 0:
                product *= value(b, py)
            total += weight * selector * product
    return total


def exact_ratio_predicate(e, z, pi, fractional_bits=14):
    """Candidate 1's integer predicate, NOT a field proof or new verifier."""
    if not (0 <= e <= 1 << 30 and 1 << 30 <= z <= 450 << 30
            and 0 <= pi <= 1 << fractional_bits):
        return False
    residual = (e << fractional_bits) - pi * z
    return 2 * abs(residual) < z or (2 * abs(residual) == z and pi % 2 == 0)


def late_weights(old):
    """Native B=16, live mask 15/16, tiles 5+5+5; all gates coexist.

    Retaining the gate axis eliminates weight products on input items.
    It does not require another producer replay per gate or gate batch.
    """
    case = next(c for c in gkr.ratio_cases() if c['old_tokens'] == old)
    native = gkr.native_record(NATIVE_RECORD, 'EXP30', old)
    ops = {op:sum(l[op] for l in native['layers']) for op in ('and','xor','copy')}
    blocks = case['rounds'][3]['supported_pairs']
    packed_groups = 4*32*sum((old+q+1+3)//4 for q in range(150))
    size, tiles, depth = 96, 3, native['depth']
    scale = (ops['and']+ops['xor'])*size**2 + ops['copy']*size
    raw_slots = max((l['and']+l['xor'])*size**2+l['copy']*size for l in native['layers'])
    updates = blocks*((ops['and']+ops['xor'])*tiles**2+ops['copy']*tiles)
    prefix_gates = 0
    packed_gates = 0
    for layer in native['layers']:
        packed_gates += prefix_gates*packed_groups
        prefix_gates += sum(layer[op] for op in ops)
    return dict(old_tokens=old, block=16, live_per_block=15, tile_live_bits=[5,5,5],
        raw_histogram_peak_bytes=36*raw_slots,
        raw_low_limb_bytes=24*raw_slots, raw_carry_bytes=12*raw_slots,
        aggregate_histogram_bytes=24*(size**2+size),
        late_weight_Fp3_products=scale,
        old_weight_Fp3_products=blocks*sum(ops.values()),
        histogram_Fp3_additions=0, histogram_updates=updates,
        histogram_u64_additions=3*updates, histogram_u32_carry_additions=3*updates,
        deferred_base_reductions=3*scale,
        max_contributions_per_raw_slot=blocks,
        reduction_Fp3_add_or_sub=scale+ops['xor']*2*32*size,
        reduction_XOR_doublings=ops['xor']*size**2,
        position_weight_Fp3_products=depth*(2*(case['padded_cells']//16)-2),
        prefix_selector_Fp3_products=30*depth,
        cubic_Fp3_products=depth*(22+15*(7*size**2+2*size+2*15+6)),
        packed_replays=packed_groups*depth, packed_boolean_word_gates=packed_gates,
        cached_frame_calls=case['live_cells']*depth,
        original_ratio_cache_bytes=6*(case['live_cells']+60*32*150),
        original_ratio_source_byte_calls=6*(case['live_cells']+60*32*150),
        logical_frame_bytes=12*case['live_cells']*depth,
        logical_raw_histogram_rmw_bytes=72*updates,
        logical_bytes_are_not_HBM=True,
        all_gates_resident_no_per_gate_replay=True,
        complete_work=False, complete_peak=False)


def report():
    cases = []
    for case in gkr.ratio_cases():
        native = gkr.native_record(NATIVE_RECORD, 'EXP30', case['old_tokens'])
        ops = {op: sum(layer[op] for layer in native['layers'])
               for op in ('and', 'xor', 'copy')}
        per_pair = gkr.factored_arithmetic(ops, native['depth'])['Fp3_mul']
        variants = []
        for bits in (3, 4):
            block, tile = 1 << bits, 8
            tiles = block // tile
            blocks = case['rounds'][bits - 1]['supported_pairs']
            tail_pairs = sum(r['supported_pairs'] for r in case['rounds'][bits:])
            # First bits are layer bits: layer l = j*(64/B)+suffix_layer.
            masks = {tuple(j * (64 // block) + base < 60 for j in range(block))
                     for base in range(64 // block)}
            bins = sum((sum(1 << sum(mask[a:a+tile]) for a in range(0, block, tile)))**2
                       + sum(1 << sum(mask[a:a+tile]) for a in range(0, block, tile))
                       for mask in masks)
            variants.append(dict(
                prefix_bits=bits, block=block, tile_bits=tile, public_masks=len(masks),
                histogram_entries=bins, histogram_payload_bytes=24*bins,
                supported_blocks=blocks,
                weight_Fp3_products=blocks*sum(ops.values()),
                bin_Fp3_additions=blocks*((ops['and']+ops['xor'])*tiles**2
                                            +(2*ops['xor']+ops['copy'])*tiles),
                xor_doublings=blocks*ops['xor'],
                tail_Fp3_products=tail_pairs*per_pair,
                unchanged_scalar_tail_lower_seconds=tail_pairs*per_pair*24/SCALAR_RESULT_CEILING,
            ))
        cases.append(dict(old_tokens=case['old_tokens'], live_cells=case['live_cells'],
                          circuit_gates=sum(ops.values()), variants=variants,
                          late_gate_weights=late_weights(case['old_tokens'])))
    return dict(credit=False, scope='two EXP30 algebra/cost screens; no protocol replacement',
                cases=cases, complete_work=False, complete_peak=False,
                missing=['packed Boolean producer/replay and checkpoint liveness',
                         'histogram reduction and contention, exact field kernel',
                         'all-bin evaluation, original tail getter and original MAC/FS',
                         'joint canonical time and allocated/reserved peak'],
                conditional_tail_ceiling=SCALAR_RESULT_CEILING,
                asymptotics='B=2b, M public masks <=2^B: O(S/B + M*B*2^(2b)) field work per layer; b=Theta(log S) small enough, packed input assumed',
                spending_gate='NO-GO for spending; reduced algebra only')


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
