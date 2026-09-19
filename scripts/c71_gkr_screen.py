#!/usr/bin/env python3
"""Public MSB-fold support census for the canonical C7.1 RMS programs."""

from collections import Counter
from functools import lru_cache
import itertools
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import c7_1_gemma_plan as plan


def merge(intervals):
    out = []
    for begin, end in sorted(intervals):
        if begin >= end:
            continue
        if out and begin <= out[-1][1]:
            out[-1] = (out[-1][0], max(end, out[-1][1]))
        else:
            out.append((begin, end))
    return out


def modulo_union(intervals, period):
    """Merged intervals for {i mod period | i occurs in an input interval}."""
    if period <= 0:
        raise ValueError('positive period required')
    projected = []
    for begin, end in intervals:
        if not 0 <= begin <= end:
            raise ValueError('invalid support interval')
        length = end - begin
        if length >= period:
            return [(0, period)]
        first = begin % period
        if first + length <= period:
            projected.append((first, first + length))
        else:
            projected.extend(((first, period), (0, first + length - period)))
    return merge(projected)


def modulo_union_length(intervals, period):
    return sum(end - begin for begin, end in modulo_union(intervals, period))


def runs(values, wanted):
    result, begin = [], None
    for i, value in enumerate([*values, object()]):
        if value == wanted and begin is None:
            begin = i
        elif value != wanted and begin is not None:
            result.append((begin, i))
            begin = None
    return result


def tiny_checks():
    # Exhaust every one-profile support mask through N=8.
    for n in (2, 4, 8):
        for mask in range(1 << n):
            values = [0 if mask >> i & 1 else None for i in range(n)]
            intervals = runs(values, 0)
            for h in range(n.bit_length() - 1):
                half = n >> (h + 1)
                expected = len({i % half for i, value in enumerate(values) if value == 0})
                assert modulo_union_length(intervals, half) == expected
    # Exhaust two profiles plus padding at N=8, including interleaving.
    for values in itertools.product((None, 0, 1), repeat=8):
        for profile in (0, 1):
            intervals = runs(values, profile)
            for h in range(3):
                half = 8 >> (h + 1)
                expected = len({i % half for i, value in enumerate(values) if value == profile})
                assert modulo_union_length(intervals, half) == expected


@lru_cache(maxsize=None)
def native_record(path, kind='RMS', old=0):
    text = Path(path).read_text()
    try:
        record = json.loads(text)
    except json.JSONDecodeError:
        texts = [text]
    else:
        texts = [run['stdout'] for run in record.get('rust_runs', []) if 'stdout' in run]
    for line in itertools.chain.from_iterable(item.splitlines() for item in texts):
        match = re.search(rf'canonical_{kind}_GKR O={old} (\{{.*\}})', line)
        if match:
            return json.loads(match.group(1))
    raise ValueError(f'native O={old} {kind} census missing')


def factored_arithmetic(ops, program_pairs):
    return {
        'Fp3_mul':7*(ops['and']+ops['xor'])+2*ops['copy']+6*program_pairs,
        'Fp3_add':4*ops['and']+9*ops['xor']+2*ops['copy']+6*program_pairs,
        'Fp3_sub':2*ops['and']+4*ops['xor']+ops['copy']+program_pairs,
        'Fp3_neg':ops['xor'],
    }


def canonical(native):
    cohorts = plan.gemma_weight_cohorts(plan.pinned_private_tensors())
    norms = plan.rms_statistic_cohorts(cohorts)
    shapes = [(norm['statistic_rows'], norm['columns']) for norm in norms]
    tiles = plan.dyadic_weight_layout(shapes)
    cells = sum(rows * cols for rows, cols in shapes)
    n = 1 << (cells - 1).bit_length()

    profile_keys, profile_of_norm = [], []
    for norm in norms:
        key = (norm['columns'], 0, 0, 0, norm['weighted'])
        if key not in profile_keys:
            profile_keys.append(key)
        profile_of_norm.append(profile_keys.index(key))
    intervals = [[] for _ in profile_keys]
    for tensor, _row, _col, rows, cols, offset in tiles:
        intervals[profile_of_norm[tensor]].append((offset, offset + rows * cols))
    intervals = [merge(item) for item in intervals]

    circuits = []
    for columns, ex, ew, ey, weighted in profile_keys:
        circuit = plan.rms_boolean_circuit(columns, ex, ew, ey, weighted, True)
        circuits.append(plan.rms_layered_circuit(circuit))
    depth = max(len(circuit['levels']) for circuit in circuits)
    op_by_profile = []
    layer_ops = []
    for circuit in circuits:
        per_layer = []
        for d in range(depth):
            gates = circuit['levels'][d] if d < len(circuit['levels']) else [('copy', 0, 0)]
            per_layer.append(Counter(gate[0] for gate in gates))
        layer_ops.append(per_layer)
        op_by_profile.append(sum(per_layer, Counter()))

    assert native['padded_cells'] == n and native['depth'] == depth == len(native['layers'])
    assigned = [sum(end - begin for begin, end in item) for item in intervals]
    assert assigned == native['assigned_cells_by_program']
    for d, layer in enumerate(native['layers']):
        combined = sum((layer_ops[p][d] for p in range(len(profile_keys))), Counter())
        assert [combined['and'], combined['xor'], combined['copy']] == [
            layer['and'], layer['xor'], layer['copy']]

    rounds = []
    totals = Counter()
    per_profile_totals = [Counter() for _ in profile_keys]
    for h in range(n.bit_length() - 1):
        half = n >> (h + 1)
        profiles = []
        for p, item in enumerate(intervals):
            spans = modulo_union(item, half)
            pairs = sum(end - begin for begin, end in spans)
            gate_ops = {op: pairs * op_by_profile[p][op] for op in ('and', 'xor', 'copy')}
            gate_ops['all'] = sum(gate_ops.values())
            profiles.append({'profile': p, 'supported_pairs': pairs,
                             'support_span_count': len(spans),
                             'gate_iterations_across_layers': gate_ops})
            per_profile_totals[p].update(gate_ops)
            totals.update(gate_ops)
        rounds.append({'round': h, 'pair_domain': half, 'profiles': profiles,
                       'supported_gate_iterations_across_layers':
                           sum(v['gate_iterations_across_layers']['all'] for v in profiles)})

    assert [[p['supported_pairs'] for p in r['profiles']] for r in rounds] == native[
        'public_supported_pairs_by_round_and_profile']
    unpruned_ops = Counter()
    for counter in op_by_profile:
        for op in ('and', 'xor', 'copy'):
            unpruned_ops[op] += counter[op] * (n - 1)
    result = {
        'credit': False,
        'scope': 'exact public structural support; fixed support-bool schedule; no runtime credit',
        'padded_cells': n,
        'live_cells': cells,
        'profiles': [
            {'profile': p, 'columns': key[0], 'weighted': key[4],
             'assigned_cells': assigned[p], 'merged_interval_count': len(intervals[p]),
             'gates_across_all_layers': dict(op_by_profile[p]),
             'supported_gate_iterations_all_rounds': dict(per_profile_totals[p])}
            for p, key in enumerate(profile_keys)
        ],
        'rounds': rounds,
        'support_span_descriptors_all_rounds_profiles': sum(
            profile['support_span_count'] for round_ in rounds for profile in round_['profiles']),
        'maximum_support_spans_one_round_profile': max(
            profile['support_span_count'] for round_ in rounds for profile in round_['profiles']),
        'supported_gate_iterations_all_rounds': dict(totals),
        'factored_arithmetic_before_support_pruning': factored_arithmetic(unpruned_ops,depth*len(profile_keys)*(n-1)),
        'factored_arithmetic_after_structural_support_pruning': factored_arithmetic(totals,
            depth*sum(p['supported_pairs'] for r in rounds for p in r['profiles'])),
        'logical_unpruned_gate_iterations': sum(
            sum(counter.values()) * (n - 1) for counter in op_by_profile),
        'schedule': ('For each public profile and cell-round, execute its gates exactly on the '
                     'precomputed union of pair residues; do not branch on field selector values.'),
        'challenge_or_witness_dependent': False,
        'full_hardware_or_service_lower': False,
    }
    return result


def ratio_cases():
    # Python has no independent compile_ratio entry point. Gate totals come
    # directly from the native public census; only causal support is derived.
    results = []
    for old in (0, 150, 300):
        key_domain = 1 << ((old + 150 - 1).bit_length())
        domain = 60 * 32 * 256 * key_domain
        n = 1 << (domain - 1).bit_length()
        intervals = []
        rows = 32 * 256
        for layer in range(60):
            for head in range(32):
                base_row = (layer * rows + head * 256) * key_domain
                for query in range(150):
                    intervals.append((base_row + query * key_domain,
                                      base_row + query * key_domain + old + query + 1))
        live = sum(end - begin for begin, end in intervals)
        assert live == 60 * 32 * (150 * old + 150 * 151 // 2)
        supported = []
        for h in range(n.bit_length() - 1):
            half = n >> (h + 1)
            spans = modulo_union(intervals, half)
            pairs = sum(end - begin for begin, end in spans)
            supported.append({'round': h, 'pair_domain': half, 'supported_pairs': pairs,
                              'support_span_count': len(spans)})
        results.append({'old_tokens': old, 'padded_cells': n, 'live_cells': live,
                        'public_live_interval_count': len(intervals),
                        'rounds': supported,
                        'gate_iterations_need_native_ratio_profile': True})
    return results


@lru_cache(maxsize=None)
def ratio_supported_pair_totals():
    return tuple((case['old_tokens'], sum(item['supported_pairs'] for item in case['rounds']))
                 for case in ratio_cases())


def ratio_supported_pair_total(old):
    try:
        return dict(ratio_supported_pair_totals())[old]
    except KeyError as error:
        raise ValueError('unsupported EXP30 old-token count') from error


def ratio_factored_arithmetic(native, old):
    pairs = ratio_supported_pair_total(old)
    ops = {op:sum(layer[op] for layer in native['layers'])*pairs
           for op in ('and', 'xor', 'copy')}
    return factored_arithmetic(ops, native['depth']*pairs)


def byte_source_trace(view_bits, lanes):
    """MSB regeneration with shared prefix weights and a four-child getter.

    Count source expressions, never infer HBM transactions or a service rate.
    The fixed LUT replaces a domain-sized tree without reducing regeneration.
    """
    if lanes not in (1, 2, 4, 8, 16) or not lanes.bit_length()-1 <= view_bits <= 34:
        raise ValueError('byte source geometry')
    totals = Counter()
    layers = []
    for layer in range(8):
        d = view_bits + layer
        n = 1 << d
        eq_mul = eq_add = eq_sub = 0
        for r in range(d):
            calls = n >> r
            eq_mul += calls * (d + 2*r)
            eq_add += calls * r
            eq_sub += calls * 2*r + calls * (d-r)//2
        eq_mul += 3*d
        eq_add += d
        eq_sub += 2*d
        # Ascending binary prefixes update only the suffix changed by carry.
        # One q-prefix scan uses 2^(q+1)-2 products and 2^q-1 complements.
        prefix_mul = 2*n*(d-1)+2
        prefix_sub = n*(d-1)+1
        calls = n*(d+1)
        item = dict(getter_calls=calls, getter_scalar_values=4*calls, prefix_terms=calls,
            equality_multiplications=prefix_mul+eq_mul,
            equality_additions=eq_add,
            equality_subtractions=prefix_sub+eq_sub,
            cubic_multiplications=27*(n-1), cubic_additions=18*(n-1),
            cubic_subtractions=5*(n-1), fold_multiplications=4*calls,
            fold_additions=4*calls, fold_subtractions=0)
        totals.update(item)
        layers.append(dict(layer=layer, dimensions=d, **item))
    return dict(credit=False, view_bits=view_bits, lanes=lanes, layers=layers,
        getter_returns_four_children=True,
        max_prefix_weight_payload_bytes=24*(view_bits+8),
        counted_work=dict(totals), lut_nodes=lanes*256*511,
        lut_capacity_bytes=lanes*256*511*48,
        lut_build_multiplications=3*lanes*256*255,
        lut_build_additions=lanes*256*255,
        lut_leaf_subtractions=lanes*256*256,
        dense_tree_payload_bytes=(1 << view_bits)*511*48,
        dense_bottom_payload_bytes=(1 << view_bits)*256*48,
        complete_work=False, complete_physical_peak=False,
        logical_accesses_are_not_HBM=True,
        missing=['coefficient factorial/inverse generation', 'MAC/FS/serialization',
                 'original byte getter work', 'proof/correlation/allocator/stack liveness'])


def source_prover_trace(native):
    """Join the implemented cell replay with its original-byte obligation."""
    c = native['padded_cells'].bit_length()-1
    widths = [layer['input_width'] for layer in native['layers']]
    terminal = 0 if c == 0 else sum(widths)+native['programs']*native['depth']
    derived = {
        'field_fold_multiplications_active_boolean_rows':
            native['live_cells']*c*native['depth']+terminal,
        'field_fold_additions_active_boolean_rows':
            native['live_cells']*c*(sum(widths)+native['depth'])+terminal,
        'field_fold_subtractions_terminal':terminal,
        'boolean_fold_masks_active':native['live_cells']*c*sum(widths),
    }
    for key, value in derived.items():
        if key in native and native[key] != value:
            raise ValueError(f'native {key} disagrees with active Boolean fold')
    fields = ('cell_first_logical_frame_callbacks', 'cell_first_scalar_boolean_replay_gates',
              'field_value_source_scalars',
              'field_fold_multiplications_active_boolean_rows',
              'field_fold_additions_active_boolean_rows',
              'field_fold_subtractions_terminal', 'boolean_fold_masks_active',
              'prefix_weight_multiplications', 'prefix_weight_subtractions',
              'structural_selector_callbacks', 'structural_selector_assigned_terms')
    cell_phase = {k:native.get(k, derived.get(k)) for k in fields}
    if any(value is None for value in cell_phase.values()):
        raise ValueError('native source prover census is incomplete')
    return dict(credit=False, canonical_calibrated_profile=False,
        cell_phase=cell_phase,
        assignment_bytes_absorbed=native['padded_cells']*(2 if native['programs'] > 255 else 1),
        assignment_stream_scratch_bytes=4096,
        dense_assignment_payload_removed_bytes=native['dense_assignment_bytes'],
        public_program_heap_bytes=native['public_program_inner_vec_capacity_bytes']+
                                  native['public_program_descriptor_bytes'],
        byte_endpoint=byte_source_trace(c+4, 16),
        complete_work=False, complete_physical_peak=False,
        missing=['index/terminal/authentication work', 'full proof and allocator capacity',
                 'original frame getter work', 'measured fused kernel service rate'])


def sass_gate_census(path):
    text=Path(path).read_text()
    result={}
    for op in ('and','xor','copy'):
        name='c71_gkr_'+op+'_gate'
        body=text.split('Function : '+name)[1].split('Function : ')[0]
        lines=[line for line in body.splitlines() if re.search(r'/\*[0-9a-f]+\*/',line)]
        before=[]
        for line in lines:
            if 'EXIT' in line and '@' not in line:break
            if 'BRA ' in line or 'CALL' in line:
                raise ValueError('gate probe contains a branch/call; manual control-flow census required')
            if '@' not in line and 'NOP' not in line:
                before.append(line)
        result[op]=dict(instructions=len(before),IMAD_WIDE_U32=sum('IMAD.WIDE.U32' in line for line in before))
    return result


def probe_screen(rms, ratios, sass):
    # Only this separately compiled gate-probe schedule inherits its SASS.
    # Load/address/control instructions are never counted per inlined Fp3 mul.
    issue=132*4*32*2_000_000_000
    multiply=132*64*2_000_000_000
    def cost(ops):
        instructions=sum(ops[k]*sass[k]['instructions'] for k in sass)
        imad=sum(ops[k]*sass[k]['IMAD_WIDE_U32'] for k in sass)
        return dict(instructions=instructions,IMAD_WIDE_U32=imad,
                    conditional_issue_lower_seconds=instructions/issue,
                    conditional_multiply_lower_seconds=imad/multiply,
                    conditional_compute_lower_seconds=max(instructions/issue,imad/multiply))
    tails=[]
    for skipped in (0,6,8,9):
        ops=Counter()
        for r in rms['rounds'][skipped:]:
            for p in r['profiles']:
                ops.update({k:p['gate_iterations_across_layers'][k] for k in sass})
        tails.append(dict(first_rounds_granted_free=skipped,**cost(ops)))
    return dict(credit=False,conditions=['132 SM','clock <=2 GHz',
        '<=4 warp issues/cycle/SM','<=64 INT32 multiply results/cycle/SM',
        'exact separately compiled weighted-gate kernels; no arbitrary fusion credit'],
        RMS_probe_tails=tails,ratio_probe=[dict(old_tokens=r['old_tokens'],
            **cost(r['supported_gate_iterations_all_rounds'])) for r in ratios],
        complete_prover_lower=False,applies_to_new_fused_or_bitpacked_kernels=False)


def report(rms_log,ratio_log,sass_path):
    rms_native=native_record(rms_log)
    rms=canonical(rms_native)
    rms['source_prover']=source_prover_trace(rms_native)
    ratios=ratio_cases()
    for r in ratios:
        native=native_record(ratio_log,'EXP30',r['old_tokens'])
        assert native['padded_cells']==r['padded_cells'] and native['live_cells']==r['live_cells']
        ops={op:sum(layer[op] for layer in native['layers']) for op in ('and','xor','copy')}
        pairs=sum(h['supported_pairs'] for h in r['rounds'])
        r['supported_gate_iterations_all_rounds']={op:v*pairs for op,v in ops.items()}
        r['source_prover']=source_prover_trace(native)
        del r['gate_iterations_need_native_ratio_profile']
    sass=sass_gate_census(sass_path)
    return dict(credit=False,canonical_calibrated_profile=False,
        RMS=rms,EXP30=ratios,gate_kernel_SASS=sass,probe_screen=probe_screen(rms,ratios,sass),
        complete_work=False,complete_physical_peak=False,H100_ready=False)


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--rms-log',required=True)
    parser.add_argument('--ratio-log',required=True)
    parser.add_argument('--sass',required=True)
    args=parser.parse_args()
    tiny_checks()
    print(json.dumps(report(args.rms_log,args.ratio_log,args.sass),indent=2,sort_keys=True))
