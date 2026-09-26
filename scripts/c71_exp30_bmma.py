"""Exact private Gram replacement for EXP30 prefix bins; no hardware credit."""
import json
from functools import lru_cache
import c71_exp30_alternatives as alt


def moments(rows, live, gates, weights, point, bits):
    """Algebra oracle, retaining public support masks and ORIGINAL suffix Eq."""
    block, suffix = 1 << bits, len(rows) >> bits
    by_mask = {}
    for k, weight in enumerate(alt.equality(point[bits:])):
        mask = tuple(live[j*suffix+k] for j in range(block))
        if not any(mask):
            continue
        if mask not in by_mask:
            by_mask[mask] = ([[0]*block for _ in range(block)], [0]*block)
        gram, linear = by_mask[mask]
        for (op, x, y), gate_weight in zip(gates, weights):
            xs = [rows[j*suffix+k][x] if mask[j] else 0 for j in range(block)]
            ys = [rows[j*suffix+k][y] if mask[j] else 0 for j in range(block)]
            w = weight*gate_weight  # Oracle only; production weights AFTER moments.
            for i in range(block):
                if op in ('Copy', 'Xor'):
                    linear[i] += w*(xs[i] + (ys[i] if op == 'Xor' else 0))
                if op != 'Copy':
                    for j in range(block):
                        gram[i][j] += w*xs[i]*ys[j]*(-2 if op == 'Xor' else 1)
    return by_mask


def moment_round_value(by_mask, selector_point, prefix, trial):
    block = 1 << len(selector_point)
    remaining = len(selector_point)-len(prefix)-1
    select = alt.equality(selector_point)
    folds = alt.equality([*prefix, trial])
    out = 0
    for tail in range(1 << remaining):
        v = [folds[j >> remaining] if j % (1 << remaining) == tail else 0
             for j in range(block)]
        for mask, (gram, linear) in by_mask.items():
            selector = sum(select[j]*v[j]*int(mask[j]) for j in range(block))
            value = sum(linear[i]*v[i] + sum(gram[i][j]*v[i]*v[j]
                        for j in range(block)) for i in range(block))
            out += selector*value
    return out


@lru_cache(maxsize=1)
def geometry():
    native = alt.gkr.native_record(alt.NATIVE_RECORD, 'EXP30', 0)
    levels = native['layers']
    widths = [98]+[l['and']+l['xor']+l['copy'] for l in levels[:-1]]
    states = [dict(depth=i+1, count_bytes=(l['and']+l['xor'])*192*256*4,
                   copy_count_bytes=((l['copy']*15+7)//8)*8*192*4,
                   stage_bytes=widths[i]*64*16*32,
                   Eq_bitplanes_bytes=192*64*32,
                   gate_map_bytes=(l['and']+l['xor'])*8+l['copy']*4,
                   moment_output_bytes=((l['and']+l['xor'])*256+(l['copy']*15+7)//8*8)*24)
              for i,l in enumerate(levels)]
    return levels, widths, states


def report():
    levels, widths, states = geometry()
    binary = sum(l['and']+l['xor'] for l in levels)
    peak = max(max(
        sum(v for k,v in s.items() if k not in ('depth','moment_output_bytes'))+alt.REPLAY_DAG_RESIDENT_BYTES,
        s['count_bytes']+s['copy_count_bytes']+s['gate_map_bytes']+s['moment_output_bytes'])
        for s in states)+24*(256+16)
    cases = []
    for old in (0,150,300):
        base = alt.late_weights(old)
        n = base['max_contributions_per_raw_slot']
        tiles, batches = (n+255)//256, (n+16383)//16384
        mma = binary*384*tiles
        warp_tiles = binary*48*tiles
        counts = sum(s['count_bytes']+s['copy_count_bytes'] for s in states)
        copy_mma = sum((l['copy']*15+7)//8 for l in levels)*12*tiles
        # Deliberately favorable envelope; NOT the IMAD-specific ceiling.
        mask_lower = mma*32*2/(132*128*2_000_000_000)
        cache = 256 << 20  # Conditional total retained-count cache allowance.
        count_hbm = 2*(batches-1)*sum(max(0,s['count_bytes']+s['copy_count_bytes']-cache) for s in states)
        cases.append(dict(old_tokens=old, supported_suffix_positions=n,
            signed_count_safe=n<2**31, K_tiles=tiles,
            B_mask_compute_lower_seconds_conditional=mask_lower,
            count_cross_batch_HBM_lower_bytes_conditional=count_hbm,
            count_bandwidth_lower_seconds_conditional=count_hbm/3.35e12,
            kernel_partial_lower_seconds_conditional=max(mask_lower,count_hbm/3.35e12), fenced_batches_per_level=batches,
            warp_BMMA_instructions=mma,
            binary_dot_bit_pairs=mma*16*8*256,
            B_mask_u32_AND_results=mma*32*2,
            Copy_wide_updates=0,
            Copy_warp_BMMA_instructions=copy_mma,
            Copy_load_logical_bytes=copy_mma*32*6*4,
            remaining_scattered_binary_histogram_updates=0,
            count_load_store_logical_bytes=2*counts*batches,
            A_Y_load_logical_bytes=warp_tiles*32*6*4,
            Eq_load_logical_bytes=mma*32*2*4,
            producer_packed_stage_write_bytes=sum(widths)*((n+3)//4)*8,
            inplace_transpose_read_bytes=sum(widths)*((n+3)//4)*8,
            inplace_transpose_write_bytes=sum(widths)*tiles*16*32,
            transpose_shared_bytes_per_CTA=512,
            Eq_canonical_input_read_bytes=len(levels)*n*24,
            Eq_pack_warp_votes=len(levels)*tiles*8*192,
            Eq_stage_write_bytes=len(levels)*tiles*192*32,
            counts_zero_fill_bytes=counts,
            final_count_read_bytes=counts,
            canonical_moment_output_bytes=sum(s['moment_output_bytes'] for s in states),
            final_moment_base_reductions=(binary*256+sum((l['copy']*15+7)//8*8 for l in levels))*3,
            final_count_shift_add_terms=counts//4,
            late_gate_Fp3_products=sum(l['and']*225+l['xor']*255+l['copy']*15 for l in levels),
            replay_word_operations=base['packed_boolean_word_gates'],
            source_frame_cache_bytes=base['original_ratio_cache_bytes'],
            phase_payload_bytes=peak,
            logical_bytes_are_not_HBM=True))
    return dict(credit=False, scope='same four EXP30 cubics, candidate BMMA consumer',
        batch_suffix_capacity=16384, states=states, cases=cases,
        fixed_kernel_sm90=True, complete_time=False, complete_peak=False,
        lower_conditions=['132 SM, clock <=2 GHz, grant 128 bitwise results/cycle/SM',
                          '3.35 TB/s HBM, <=256 MiB retained count cache between fenced batches',
                          'max of compute and bandwidth lower; no bandwidth-derived upper'],
        missing=['parallel packed producer and original-index compact schedule adapter',
                 'GPU moment weighting and native prefix integration',
                 'GPU validation/service rates and complete physical arena'],
        time_metrics=dict(T_inference='unmeasured', T_proof_only='unmeasured',
                          T_response_total='unmeasured', target_total_seconds=65))


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
