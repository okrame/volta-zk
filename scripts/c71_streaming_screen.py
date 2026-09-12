#!/usr/bin/env python3
"""Small arithmetic screen for authorized C7.1 continuation work; not a prover."""
import json
import math
from fractions import Fraction

import c7_1_gemma_plan as base


def error_upper(value):
    """Outward 256-bit rounding keeps the diagnostic readable."""
    return str(Fraction(((value.numerator << 256)+value.denominator-1)
                        // value.denominator, 1 << 256))


def coset_replay_budget(domain_rows, width, arena):
    """Full-row RS coset buffers, each batch reconstructed by a full source scan.

    Excludes FFT workspace, masks, row reordering and Merkle paths. The bound
    applies only to this replay construction, not to every streaming encoder.
    """
    if min(domain_rows, width, arena) <= 0 or domain_rows & (domain_rows-1):
        raise ValueError('positive power-of-two domain and positive width/arena required')
    row_bytes = 8*width
    rows_per_scan = arena//row_bytes
    if not rows_per_scan:
        raise ValueError('one complete row must fit')
    return {
        'encoded_bytes': domain_rows*row_bytes,
        'full_source_scans_lower': (domain_rows+rows_per_scan-1)//rows_per_scan,
        'buffer_bytes_needed_for_four_scans_lower': ((domain_rows+3)//4)*row_bytes,
        'all_row_hash_states_at_32_bytes': 32*domain_rows,
        'includes_opening_replay': False,
        'universal_streaming_lower_bound': False,
    }


def suffix_first_weight_budget():
    """Public descriptor census; arrays and contraction updates, not runtime.

    Non-Boolean sample points retain every cube; lookup IDs are 0..149.
    The vocabulary is one dyadic row tile, so every admitted token vector
    has the same maximal cube geometry; zero coefficients only remove terms.
    No witness, field table or native transcript is allocated.
    """
    tensors = base.pinned_private_tensors()
    bits = lambda n: (n-1).bit_length()
    points = []
    for c in base.gemma_weight_cohorts(tensors):
        if c['kind'] == 'matrix':
            points.append(([2]*bits(c['columns']), [3]*bits(c['inner'])))
        elif c['kind'] == 'norm':
            points.append(([], [3]*bits(c['columns'])))
        else:
            points.append(([2]*bits(c['rows']), [3]*bits(c['columns'])))
    forms = base.gemma_weight_opening_forms(tensors, points, range(150))
    dims = [len(point) for form in forms for _, point, _ in form]
    live = sum(math.prod(t['shape']) for t in tensors)
    d, offset = bits(live), live
    dims.append(d)  # Full-domain range endpoint.
    while offset < 1 << d:
        size = offset & -offset
        dims.append(size.bit_length()-1)
        offset += size
    suffix = 15
    contraction = len(dims)*(1 << suffix)*24
    terminal = 2*(1 << (d-suffix))*24
    updates = sum(1 << max(dim, suffix) for dim in dims)
    return {
        'cube_count': len(dims),
        'lookup_ids': '0..149',
        'uniform_upper_over_admitted_token_vectors': True,
        'suffix_bits_first': suffix,
        'contraction_bytes': contraction,
        'terminal_W_and_L_bytes': terminal,
        'named_arrays_simultaneous_bytes': contraction+terminal,
        'first_scan_update_model': updates,
        'both_scans_update_model': updates+(1 << d),
        'W_source_scans_for_linear_reducer': 2,
        'PCS_endpoint_order': 'original prefix then suffix',
        'includes_PCS_range_witness_or_runtime': False,
    }


def report():
    assessment = base.b12_pcs_binding_assessment()
    bootstrap = base.c71_dory_guarded_bootstrap_screen()
    arena = 6_442_450_944
    boot_wire = bootstrap['partial_with_coin_and_private_equality_wire']
    boot_error = (Fraction(1, 1 << 80)
                  + Fraction(bootstrap['conditional_known_errors']['sum']))
    complete = assessment['complete_fixed_run_composition']
    # Conservative union: leave the old B12 bootstrap error in the reference
    # sum, rather than claiming a proved cancellation/composition theorem.
    composed = {name: error_upper(Fraction(complete[name])+boot_error)
                for name in ('conditional_soundness_sum', 'conditional_ZK_sum')}
    wire = []
    for i, case in enumerate(assessment['native_canonical_certificate_wire']['cases']):
        body = case['total_wire_interval']
        wire.append({
            'old_tokens': case['old_tokens'],
            'body_wire_interval': body,
            'known_primitives_plus_body_interval': [x+(boot_wire if i == 0 else 0) for x in body],
            'native_positive_certificate_bytes': None,
            'lower_omits': ['joint GKR', 'Merkle siblings'],
        })
    profiles = []
    for p in assessment['native_canonical_linear_PCS_wire']:
        # B12's common first fold=7, initial pad=3*512 and inverse rate=8.
        # The exported ideal profiles omit the separate A/D34 geometry.
        d, width = p['log_message_cells'], 1 << 7
        domain = 1 << (8*((1 << d)//width+1536)-1).bit_length()
        profiles.append({'dimension': d,
                         **coset_replay_budget(domain, width, arena)})
    return {
        'credit': False,
        'trust_model': 'B12 + owner-authorized EA-LPN-SL-reg* at T121/M93, one leakage',
        'EA_assumed_advantage': str(Fraction(1, 1 << 80)),
        'conditional_bootstrap_error': error_upper(boot_error),
        'conditional_B12_plus_bootstrap_union': composed,
        'conditional_union_bits': {name: -math.log2(float(Fraction(x)))
                                   for name, x in composed.items()},
        'union_requires_complete_MAC_interface_and_composition': True,
        'conditional_union_below_2_to_minus_78': all(
            Fraction(x) < Fraction(1, 1 << 78) for x in composed.values()),
        'canonical_required_base_rows': complete['initial_base_rows_upper'],
        'Dory_base_capacity': bootstrap['geometry']['candidate_base_capacity'],
        'wire': wire,
        'fallback_authorization': 'body lower bounds as analytic proof-size result only',
        'coset_replay': profiles,
        'suffix_first_W_linear_reducer': suffix_first_weight_budget(),
        'arena_bytes': arena,
        'native_Dory_implemented': False,
        'physical_schedule_admitted': False,
        'complete_prover_seconds_upper': None,
        'goal_complete': False,
    }


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
