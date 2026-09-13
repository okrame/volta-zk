#!/usr/bin/env python3
"""Small arithmetic screen for authorized C7.1 continuation work; not a prover."""
import json
import math
from fractions import Fraction

import c7_1_gemma_plan as base
import c71_query_remainder as remainder


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


def range_checkpoint_budget(d, cut, retained_C=0):
    """Literal top-tree retention, excluding the unresolved lower-layer prover.

    Build one subtree of 2**cut leaves at a time, retain its root and the
    upper tree. During upper GKR retain four children and an equality array.
    The replay bound concerns rebuilding discarded layers independently.
    """
    if not 0 <= cut < d or retained_C < 0:
        raise ValueError('require 0 <= cut < d and nonnegative retained bytes')
    roots = 1 << (d-cut)
    tree = 48*(2*roots-1)
    return {
        'cut_bottom_levels': cut,
        'retained_top_tree_bytes': tree,
        'upper_GKR_children_and_eq_bytes': 60*roots,
        'named_peak_with_C_bytes': tree+60*roots+retained_C,
        'excludes': ['equality construction scratch', 'allocator/metadata', 'staging'],
        'independent_lower_layer_rebuild_W_scans_lower': cut,
        # One initial post-alpha tree scan, two linear scans, one PCS scan.
        # Excludes initial commitment, extra sumcheck/PCS replays and A.
        'partial_W_scans_lower_with_cached_histogram': cut+4,
        'lower_layers_fit_or_time_proved': False,
    }


def checkpoint_round_replay_budget(d, cut, packed_bytes, retained_bits=None):
    """Explicit gather/rebuild per lower GKR round; no bandwidth/time model.

    Each suffix bucket rebuilds the child roots for all Boolean prefixes,
    folds them with already-known challenges and immediately consumes them.
    With retained_bits, stop replaying when the folded tables fit, rebuild
    them once and finish in-place; release the canopy before lower layers.
    Source payload is not physical HBM transaction traffic.
    """
    if (not 1 <= cut < d or packed_bytes <= 0
            or retained_bits is not None and not 0 <= retained_bits < d):
        raise ValueError('positive source bytes and 1 <= cut < d required')
    n = 1 << d
    rounds = sum(range(d-cut, d))
    visits = {m: m if retained_bits is None else 1+max(0, m-retained_bits)
              for m in range(d-cut, d)}
    scans = 1+sum(visits.values())
    merges = sum(v*(n-(1 << (m+1))) for m, v in visits.items())
    child_accumulations = sum(v*(1 << (m+2)) for m, v in visits.items())
    coefficient_buckets = n-1-d
    folded_cells = 5*sum((1 << m)-1 for m in range(d-cut))
    if retained_bits is not None:
        folded_cells += 5*sum((1 << min(m, retained_bits))-1 for m in visits)
    return {
        'lower_layer_rounds': rounds,
        'retained_folded_bits': retained_bits,
        'retained_children_and_eq_bytes': 0 if retained_bits is None else 120*(1 << retained_bits),
        'lower_layer_source_visits': visits,
        'range_W_visits_with_cached_histogram': scans,
        'range_W_payload_bytes': scans*packed_bytes,
        'reconstruction_leaf_evaluations': scans*n,
        'fraction_merges_initial_and_replay': n-1+merges,
        'fraction_merge_Fp3_mul_expressions': 3*(n-1+merges),
        'fraction_merge_Fp3_add_expressions': n-1+merges,
        'lower_child_weighted_accumulations': child_accumulations,
        'accumulation_Fp3_mul_and_add_each': child_accumulations,
        'all_range_coefficient_buckets': coefficient_buckets,
        'coefficient_Fp3_mul_expressions': 27*coefficient_buckets,
        'coefficient_Fp3_add_sub_expressions': 23*coefficient_buckets,
        'resident_scalar_interpolations': folded_cells,
        'remaining_field_work': ['prefix/equality weights', 'round/terminal MAC bookkeeping',
                                 'MAC products and inversions'],
        'HBM_W_payload_if_resident': scans*packed_bytes,
        'external_W_bytes_if_resident': 0,
        'HBM_transactions_and_scratch_bytes': None,
        'source_order': 'gather by suffix bucket then Boolean prefix; not sequential packed order',
        'runtime_upper': None,
        'rejected_for_read_count': False,
    }


def integrated_schedule_screen(suffix):
    arena, packed_W = 6_442_450_944, 61_394_690_560
    C = suffix['contraction_bytes']
    phases = [
        {'phase': 'linear_first_15_rounds', 'named_arrays_bytes': C},
        {'phase': 'linear_second_scan_and_last_20_rounds',
         'named_arrays_bytes': suffix['terminal_W_and_L_bytes']},
    ]
    for phase in phases:
        phase['remaining_arena_before_other_state'] = arena-phase['named_arrays_bytes']
    return {
        'arena_bytes': arena,
        'W_read_policy': 'four is an optimization target, not a cap (2026-09-13)',
        'old_simultaneous_arrays_margin': arena-suffix['named_arrays_simultaneous_bytes'],
        'old_simultaneous_arrays_fraction': suffix['named_arrays_simultaneous_bytes']/arena,
        'HBM_cap_bytes': 80_000_000_000,
        'HBM_after_W_and_full_arena_before_other_residents': 80_000_000_000-packed_W-arena,
        'phase_liveness': phases,
        'release_C': 'after round 15 target is authenticated; before second W scan',
        'PCS_after_linear': 'reuses arena after B/L release; retained PCS state still counts',
        'private_global_W_histogram_u64_bytes': 65535*8,
        'histogram_reuse': 'counts only; fresh MAC corrections before each alpha/rho',
        'full_range_source_visible_core_peak': 180*(1 << 35)-48,
        'checkpoint_top_only': [range_checkpoint_budget(35, 10),
                                range_checkpoint_budget(35, 11, C)],
        'checkpoint_round_replay': checkpoint_round_replay_budget(35, 11, packed_W),
        'checkpoint_replay_then_retain': checkpoint_round_replay_budget(35, 10, packed_W, 25),
        'checkpoint_Gram_windows': gram_window_budget(35, 10, packed_W, 25),
        'legal_early_C': 'P0 after P0 challenges; padding after range histogram/rho',
        'full_range_C_requires': 'adaptive range terminal point',
        'linear_batch_lambda_requires': 'all W targets plus intervening A range transcript',
        'second_W_scan_requires': 'first 15 linear challenges',
        'PCS_opening_requires': 'all 35 linear challenges and original-order terminal',
        'unpriced': ['lower range layers and their replays', 'private PCS encode/open',
                     'A/KV witness production and liveness', 'PCG/MAC retained state',
                     'reader/staging/allocator', 'complete time and prefix work comparison'],
        'complete_W_scans_upper': None,
        'complete_seconds_upper': None,
        'admitted': False,
    }


def gram_window_budget(d, cut, packed_bytes, retained_bits, max_window=None):
    """Private nonsymmetric Gram windows; same cubic messages and MAC endpoints.

    Minimize a stated partial Fp3-multiplication count over ordered window
    compositions, NOT runtime or all possible range algorithms. Small public
    planner only. max_window selects the fixed-width comparison when given.
    """
    if not (1 <= cut < d and 0 <= retained_bits < d and packed_bytes > 0):
        raise ValueError('invalid checkpoint geometry')
    if max_window is not None and max_window < 1:
        raise ValueError('positive window required')
    n, layers = 1 << d, []
    merges, accum, gram_mul, gram_add, h_folds = n-1, 0, 0, 0, 0
    for m in range(d-cut, d):
        g = max(0, m-retained_bits)
        best = {g: (0, [])}
        for p in reversed(range(g)):
            choices = range(1, g-p+1) if max_window is None else [min(max_window, g-p)]
            best[p] = min((3*(n-(1 << (m+1))) + (4 << m)
                           + (4+2*(1 << b))*(1 << (m-p))
                           + (1 << (2*b))-1 + best[p+b][0],
                           [b]+best[p+b][1]) for b in choices)
        widths = best[0][1]
        visits = 1+len(widths)
        merges += visits*(n-(1 << (m+1)))
        accum += visits*(4 << m)
        p = 0
        for b in widths:
            length = 1 << b
            gram_mul += (4+2*length)*(1 << (m-p))
            gram_add += (1+2*length)*(1 << (m-p))
            h_folds += length*length-1
            p += b
        layers.append({'child_bits': m, 'window_bits': widths, 'W_visits': visits})
    scans = 1+sum(x['W_visits'] for x in layers)
    buckets = sum((1 << m)-1 for m in range(d-cut))
    buckets += sum((1 << min(m, retained_bits))-1 for m in range(d-cut, d))
    largest = max((b for x in layers for b in x['window_bits']), default=0)
    return {
        'credit': False, 'layers': layers,
        'optimization': 'partial Fp3 mul plus H folds; not runtime optimum',
        'range_W_visits_with_cached_histogram': scans,
        'range_W_payload_bytes': scans*packed_bytes,
        'external_W_bytes_if_resident': 0,
        'fraction_merges_initial_and_replay': merges,
        'fraction_merge_Fp3_mul_expressions': 3*merges,
        'lower_child_weighted_accumulations': accum,
        'Gram_build_Fp3_mul_expressions': gram_mul,
        'Gram_build_Fp3_add_expressions': gram_add,
        'resident_coefficient_buckets': buckets,
        'resident_coefficient_Fp3_mul_expressions': 27*buckets,
        'factored_resident_coefficient_Fp3_mul_expressions': 18*buckets,
        'resident_scalar_interpolations': 5*buckets,
        'H_scalar_interpolations': h_folds,
        'comparable_core_Fp3_mul_expressions': 3*merges+accum+gram_mul+27*buckets,
        'factored_core_Fp3_mul_expressions': 3*merges+accum+gram_mul+18*buckets,
        'largest_H_bytes': 24*(1 << (2*largest)),
        'largest_bucket_children_bytes': 96*(1 << largest),
        'retained_children_and_eq_bytes': 120*(1 << retained_bits),
        'unpriced': ['H trace/cubic extraction', 'prefix/equality generation',
                     'bounded partial-H reduction', 'gather/staging/allocator',
                     'MAC/PCS/PCG', 'A/KV/inference/serialization'],
        'HBM_transactions_and_scratch_bytes': None,
        'runtime_upper': None,
    }


def local_preflight(gram, suffix):
    """Necessary rates and explicit missing evidence, never a hardware upper."""
    work = {
        'range_fraction_merges': gram['fraction_merges_initial_and_replay'],
        'range_child_accumulations': gram['lower_child_weighted_accumulations'],
        'range_Gram_build_Fp3_mul': gram['Gram_build_Fp3_mul_expressions'],
        'range_resident_coefficient_buckets': gram['resident_coefficient_buckets'],
        'range_scalar_folds': gram['resident_scalar_interpolations']+gram['H_scalar_interpolations'],
        'range_comparable_core_Fp3_mul': gram['comparable_core_Fp3_mul_expressions'],
        'W_linear_contraction_updates': suffix['both_scans_update_model'],
        'PCS_complete_operations': None, 'PCG_complete_operations': None,
        'A_range_operations': None, 'inference_operations': None,
        'serialization_complete_bytes': None,
    }
    visits = gram['range_W_visits_with_cached_histogram']+2
    return {
        'credit': False, 'spending_authorized': False, 'decision': 'NO_GO',
        'counted_work': work,
        'necessary_per_second_if_component_had_all_65_seconds': {
            k: None if v is None else v/65 for k, v in work.items()},
        'rates_are_not_sufficient_and_overlapping_work_must_not_be_added': True,
        'W_visits_range_plus_linear': visits,
        'W_visits_complete': None, 'A_visits_complete': None, 'KV_visits_complete': None,
        'W_range_plus_linear_payload_bytes': visits*61_394_690_560,
        'HBM_W_range_lower_seconds_conditional_no_compression_cache_at_most_256MiB':
            gram['range_W_visits_with_cached_histogram']*(61_394_690_560-(256 << 20))/3.35e12,
        'compute_lower_seconds_formula': 'I_min / (132 * 64 * f_max_Hz)',
        'compute_lower_requires': 'instruction-class census of compiled kernels and verified clock ceiling',
        'compute_lower_numeric_unconditional': None,
        'external_W_bytes_for_counted_resident_visits': 0,
        'global_load_W_bytes_separate': 61_394_690_560,
        'HBM_transactions_total': None, 'external_transfers_complete': None,
        'planned_arena_reservation_bytes': 6_442_450_944,
        'physical_allocated_peak': None, 'physical_reserved_peak': None,
        'complete_seconds_upper': None,
        'missing_before_paid_integrated_run': [
            'bounded CUDA gather correctness and representative remainder/hash kernels',
            'private PCS encode/open replay with original pads/salts and MAC endpoint',
            'A/KV producer/replay liveness and complete visit census',
            'complete real PCG and serialization costs',
            'allocated/reserved global peak and complete non-overlapped time budget',
            'published clean SHA, provider deadline, live price and explicit owner authorization'],
    }


def coset_frontier_budget():
    """First W oracle only, conditional on exact private salt replay.

    Natural leaf index = c + Q*j. Keep a Q-leaf frontier for each j;
    their roots arrive in natural j order on the last coset. Later PCS
    oracles and all A commitments/openings are deliberately unpriced.
    """
    L, Q, width, arena = 1 << 22, 1 << 10, 128, 6_442_450_944
    coset = 8*L*width
    frontier = 32*L*10
    # Full four-step twiddle table plus exact start/current salt-stream offsets.
    named = coset+frontier+32*23+8*L+8*1536*width+16*L
    # Generic nonzero coefficient scaling, including virtual message padding;
    # actual packed W contains fewer live coefficients and can be specialized.
    scaling = Q*width*((1 << 28)+1536)
    butterflies = Q*width*(L//2)*22
    return {
        'credit': False, 'scope': 'W initial oracle only; salt adapter missing',
        'coset_rows': L, 'cosets': Q, 'width': width,
        'coset_buffer_bytes': coset, 'frontier_slot_bytes': frontier,
        'named_bytes_with_twiddles_pads_and_upper_stack': named,
        'margin_before_hash_reader_allocator': arena-named,
        'salt_start_and_current_offsets_bytes': 16*L,
        'salt_prescan_minimum_XOF_bytes': 32*L*Q,
        'salt_prescan_W_visits': 0,
        'salt_stream_byte_cap_fail_closed': 1 << 40,
        'commit_W_visits': Q, 'opening_full_replay_W_visits': Q,
        'commit_plus_open_W_payload_bytes': 2*Q*61_394_690_560,
        'generic_scaling_Fp_mul_per_pass': scaling,
        'FFT_Fp_butterflies_per_pass': butterflies,
        'row_leaf_hashes_per_pass': L*Q,
        'binary_internal_hashes_per_pass': L*Q-1,
        'unfused_global_FFT_HBM_lower_bytes_per_pass_conditional':
            Q*22*2*(coset-(256 << 20)),
        'unfused_global_FFT_lower_seconds_per_pass_conditional':
            Q*22*2*(coset-(256 << 20))/3.35e12,
        'unfused_rejected_only_if': 'each radix-2 stage uses global buffers, no compression, <=256MiB cache credit',
        'five_pass_FFT_logical_global_bytes_per_encoding': 10*coset*Q,
        'five_pass_FFT_Fp_twiddle_products_per_encoding': width*L*Q,
        'fused_FFT_seconds_upper': None,
        'all_PCS_visits_or_seconds_upper': None,
    }


def pcs_data_oracle_geometry(d):
    """Data oracles only: masks, padding generation and WHIR state stay separate."""
    remaining, first, rows = d, True, []
    while remaining > 6:
        fold = 7 if first else 2
        width, pad, limbs = 1 << fold, 1536 if first else 512, 1 if first else 3
        message_rows = 1 << (remaining-fold)
        domain = 1 << (8*(message_rows+pad)-1).bit_length()
        rows.append({'input_dimension': remaining, 'fold': fold,
                     'domain_rows': domain, 'base_columns': width*limbs,
                     'encoded_bytes': domain*width*limbs*8,
                     'folded_Fp3_state_bytes': message_rows*24})
        remaining -= fold
        first = False
    return rows


def dominant_cost_screen(assessment):
    """Conditional rejection of literal scalar A replay, not all streaming A.

    SASS constants describe only the named straight-line compiled kernels.
    All other positive time terms remain excluded from this lower.
    """
    w, issue_rate, int_rate = 61_394_690_560, 132*4*32*2e9, 132*64*2e9
    cohorts = base.gemma_weight_cohorts(base.pinned_private_tensors())
    matrix_macs = sum(c['rows']*c['columns']*c['inner']
                      for c in cohorts if c['kind'] == 'matrix')

    def range_merges(d, cut, packed, retained, live):
        g = gram_window_budget(d, cut, packed, retained)
        # Rebuild only nodes with a live leaf. Fully public zero subtrees
        # return cached (P,Q); they are NOT removed from GKR's weighted sum.
        heights = [(d, 1)]+[(d-x['child_bits']-1, x['W_visits']) for x in g['layers']]
        active = sum(visits*sum((live+(1 << h)-1) >> h for h in range(1, height+1))
                     for height, visits in heights)
        leaf = sum(visits*((live+1)//2) for height, visits in heights if height)
        return {'generic_merges_without_zero_or_leaf_specialization': g['fraction_merges_initial_and_replay'],
                'active_merges': active, 'leaf_pairs': leaf, 'internal_mul6_merges': active-leaf,
                'issue_instructions_lower_named_kernels': leaf*231+(active-leaf)*1183,
                'zero_subtree_precompute_not_in_lower': True,
                'other_range_arithmetic_not_in_lower': True}

    wg = range_merges(35, 11, w, 24, w//2)
    batch, trees, height, weight = 4096, 675, 19, 11
    trie = lambda rows: sum(min(trees << j, weight*rows) for j in range(height))
    cases = []
    fft_bytes = 512*10*((4 << 30)-(256 << 20))
    w_open = remainder.split_padding_budget(w//2, 35)
    a_opens = []
    for i, c in enumerate(assessment['ordinary_KV_output_and_EXP30_composition']['cases']):
        a = c['auxiliary_live_bytes']
        a_opens.append(remainder.split_padding_budget(a, 34))
        ag = range_merges(34, 10, a, 24, a)
        range_seconds = (wg['issue_instructions_lower_named_kernels']+
                         ag['issue_instructions_lower_named_kernels'])/issue_rate
        rows = c['base_rows_upper_before_other_operators']
        full, tail = divmod(rows, batch)
        first_butterflies = w_open['Fp_butterflies']+sum(x['Fp_butterflies'] for x in a_opens)
        open_issue = 77*first_butterflies/issue_rate
        commit_fft_issue = 77*3_023_656_976_384/issue_rate
        scalar_getter = (540+2*i)*matrix_macs/int_rate
        cases.append({'old_tokens': c['old_tokens'], 'range_A': ag,
            'range_W_A_named_merge_issue_lower_seconds': range_seconds,
            'commit_A_FFT_array_HBM_lower_bytes': fft_bytes,
            'commit_A_FFT_array_bandwidth_lower_seconds': fft_bytes/3.35e12,
            'commit_A_nonzero_source_scaling_products': 512*(a+128*1536),
            'known_A_full_generation_visits_current_and_old': 540+2*i,
            'scalar_full_A_getter_INT32_lower_seconds': scalar_getter,
            'joint_scalar_getter_range_commit_lower_seconds':
                scalar_getter+range_seconds+max(fft_bytes/3.35e12, commit_fft_issue)+open_issue,
            'specialized_range_plus_commit_FFT_only_lower_seconds': range_seconds+fft_bytes/3.35e12,
            'split_payload_pad_openings_first_oracles_Fp_butterflies': first_butterflies,
            'first_oracle_opening_issue_lower_seconds': open_issue,
            'commit_A_FFT_issue_lower_seconds': commit_fft_issue,
            'range_merges_commit_FFT_first_openings_joint_lower_seconds':
                range_seconds+max(fft_bytes/3.35e12, commit_fft_issue)+open_issue,
            'PCG_base_rows_fixed_schedule': rows,
            'PCG_independent_query_steps_upper_per_role': 209*rows,
            'PCG_batched_trie_steps_upper_per_role': full*trie(batch)+trie(tail),
            'complete_seconds_upper': None})
    return {'credit': False,
        'ninety_seconds_is_discussion_threshold_not_authorization': True,
        'literal_scalar_getter_decision': 'NO_GO_above_90_seconds',
        'exact_tensor_or_other_fused_getter_decision': 'UNRESOLVED_not_rejected_by_this_lower',
        'ceiling_conditions': ['132 SM', 'clock <=2GHz', '<=64 scalar INT32 MAC results/cycle/SM',
            '<=4 warp instruction issues/cycle/SM', '32 lanes/warp',
            'named standalone merge kernels without additional fusion',
            'five separate FFT array passes, no compression, <=256MiB cache credit',
            'scalar getter replays every matrix once per full A visit; no tensor/SIMD/retained-cut shortcut'],
        'matrix_cohorts': sum(c['kind']=='matrix' for c in cohorts),
        'matrix_MACs_per_full_A_generation': matrix_macs,
        'max_matrix_inner_dimension': max(c['inner'] for c in cohorts if c['kind']=='matrix'),
        'commit_A_scalar_getter_only_lower_seconds': 512*matrix_macs/int_rate,
        'range_W': wg, 'cases': cases,
        'split_payload_pad_W_opening': w_open,
        'split_payload_pad_A_openings': a_opens,
        'WHIR': {'data_oracles_per_chain': 12,
                 'literal_all_oracle_remainder_butterflies_W': 3_152_737_468_416,
                 'literal_all_oracle_remainder_butterflies_per_A': 1_593_688_457_216,
                 'current_initial_sumcheck_40N_guard_W_bytes': 40*(1 << 35),
                 'current_initial_sumcheck_40N_guard_A_bytes': 40*(1 << 34),
                 'post_fold7_eval_plus_weights_W_bytes': 48*(1 << 28),
                 'post_fold7_eval_plus_weights_A_bytes': 48*(1 << 27),
                 'known_W_visits_with_one_post_query_S1_reconstruction': 33,
                 # Literal coset plan, no retained S1: reconstruct its input
                 # for every coset. These additional costs are NOT in joint LB.
                 'first_switch_coset_rows': 1 << 24,
                 'first_switch_commit_extra_W_source_visits': 64,
                 'first_switch_commit_extra_A_source_visits_per_chain': 32,
                 'direct_W_visits_including_first_switch_commit': 97,
                 'current_A_visits_including_first_switch_commit': 572,
                 'each_old_A_visits_including_first_switch_commit': 34,
                 'first_switch_commit_counts_exclude_later_oracles_and_sumchecks': True,
                 'mask_oracle_and_new_commit_getter_costs': None},
        'PCG': {'setup_internal_cGGM_evaluations_lower_per_role_if_two_full_traversals':
                    2*trees*((1 << height)-1),
                'batch_rows': batch, 'public_terms_upper': batch*weight,
                'batched_trie_internal_nodes_upper': trie(batch),
                'trie_requires_role_by_role_Acc_PuncAcc_refinement': True,
                'two_aligned_term_arrays_bytes': 2*batch*weight*16,
                'two_sparse_Fp3_frontiers_bytes': 2*batch*weight*24,
                'prover_output_bytes_per_base_row': 32,
                'prover_output_batch_bytes': batch*32,
                'Fp3_packing_carry_bytes': 2*32,
                'H_to_AES_or_seconds_lower': None,
                'persistent_seeds_OT_corrections_peak': None},
        'streaming_state_plan': {
            'credit': False, 'getter_tile_slot_cap': 64 << 20,
            'PCG_trie_extra_scratch_cap': 3_784_704,
            'pending_W_S1_h8_Merkle_and_salt_cache': 301_989_856,
            'first_switch_W_commit_named_geometry_bytes': 5_234_541_344,
            'first_switch_W_commit_named_with_proof_getter_trie_cache': 6_195_259_192,
            'query_named_with_proof_getter_trie_pending_S1_cache':
                remainder.report()['query_named_peak_bytes']+(64 << 20)+3_784_704+301_989_856,
            'unassigned': ['mask oracles', 'small-space sumcheck/public covector',
                           'PCG seeds/OT/corrections', 'allocator/runtime overhead'],
            'slot_caps_are_not_full_implementation_bounds': True},
        'complete_allocated_reserved_peak': None,
        'complete_time_admission_upper': '+infinity'}


def integrated_resource_ledger(assessment):
    """Complete admission categories; unknown costs are NOT filled by peak rates.

    Numeric lower applies to five separate full-array FFT passes and full
    initial-oracle replays, plus the exact generic merge binary. It excludes
    all positive unpriced work, so is not an upper or a PCS impossibility.
    """
    arena, w, cache, bw = 6_442_450_944, 61_394_690_560, 256 << 20, 3.35e12
    cases = assessment['ordinary_KV_output_and_EXP30_composition']['cases']
    complete = assessment['complete_fixed_run_composition']
    packed_a = [c['auxiliary_live_bytes'] for c in cases]
    # Each kernel boundary forces an array traversal; grant cache anew every
    # traversal. The source must be read separately before transforming it.
    pass_bytes = lambda packed, q: q*(packed-cache+10*((4 << 30)-cache))
    w_lower = pass_bytes(w, 1024)
    a_lower = [pass_bytes(a, 512) for a in packed_a]
    merges = gram_window_budget(35, 10, w, 25)['fraction_merges_initial_and_replay']
    merge_imad = 149*merges
    compute_lower = merge_imad/(132*64*2e9)
    output = []
    for i, c in enumerate(cases):
        known_hbm = w_lower+2*a_lower[i]+sum(a_lower[:i])
        a_visits = [512]*(i+1)
        a_visits[i] *= 2
        output.append({
            'old_tokens': c['old_tokens'], 'packed_A_bytes': packed_a[i],
            'original_KV_accepted_bytes': c['old_tokens']*901_120,
            'original_KV_with_pending_bytes': (c['old_tokens']+150)*901_120,
            'initial_oracle_full_replay_W_visits_plus_range_linear': 1052,
            'initial_oracle_A_visits_by_generation': a_visits,
            'initial_oracle_HBM_lower_bytes_conditional': known_hbm,
            'initial_oracle_bandwidth_lower_seconds_conditional': known_hbm/bw,
            'initial_oracle_plus_generic_merge_lower_seconds_conditional': known_hbm/bw+compute_lower,
            'source_PCS_chains': c['source_PCS_chains_including_W'],
            'query_remainder_known_first_oracle_W_visits_plus_range_linear': 32,
            'query_remainder_known_current_A_visits_with_range_before_linear': 539,
            'range_A_Gram_screen': gram_window_budget(34, 10, packed_a[i], 24),
            'W_A_KV_total_visits': None, 'HBM_total_bytes': None,
            'complete_seconds_upper': None,
        })
    return {
        'credit': False, 'decision_full_replay': 'NO_GO_under_stated_ceilings',
        'query_remainder_range_variant': gram_window_budget(35, 11, w, 24),
        'lower_conditions': ['HBM <=3.35e12 B/s', 'cache credit <=256MiB per traversal',
                             'no transparent compression', 'five separate FFT array passes',
                             'original first roots: W opening, current A commit+opening, old A opening',
                             'exact compiled generic merge for every counted merge',
                             '132 SM, <=64 INT32 multiply results/cycle/SM, clock <=2GHz'],
        'generic_merge_IMAD_WIDE_U32_unpredicated_per_merge': 149,
        'generic_merge_instruction_class_count': merge_imad,
        'generic_merge_compute_lower_seconds_conditional': compute_lower,
        'initial_W_install_HBM_lower_bytes_conditional': w_lower,
        'initial_W_install_seconds_lower_conditional': w_lower/bw,
        'initial_W_external_upload_bytes': w,
        'resident_W_scan_external_bytes': 0,
        'spill_external_bytes_allowed': 0,
        'cases': output,
        'data_oracles': {str(d): pcs_data_oracle_geometry(d) for d in (34, 35)},
        'PCG': {'required_base_rows_lifetime_upper': complete['initial_base_rows_upper'],
                'capacity_base_rows': 70_778_880,
                'cGGM_steps_point_query_component_upper_per_role':
                    2*353_894_400+209*complete['initial_base_rows_upper'],
                'all_output_MAC_bytes_prover': 32*complete['initial_base_rows_upper'],
                'stream_output_batch_proposed_bytes': 4096*32,
                'Fp3_packing_carry_bytes': 2*32,
                'live_state_bytes_upper': None, 'AES_OT_field_HBM_seconds_upper': None},
        'memory': {'arena_reserved_bytes_target': arena,
                   'single_KV_append_buffer_450_tokens_reserved_bytes': 450*901_120,
                   'W_KV_arena_known_reserved_bytes': w+450*901_120+arena,
                   'remaining_global_before_context_and_other_residents': 80_000_000_000-w-450*901_120-arena,
                   'allocated_peak_complete': None, 'reserved_peak_complete': None,
                   'full_current_A_plus_W_arena_bytes': [w+a+arena for a in packed_a]},
        'query_remainder_named_buffer_plan': {
            'persistent_cache_within_arena_bytes': 188_743_552,
            'canopy_cut11_with_cache_scratch_histogram_bytes': 3_376_938_824,
            'resident_range_m24_with_cache_scratch_histogram_bytes': 3_480_760_184,
            'initial_PCS_commit_with_cache_256MiB_slot_histogram_PCG_output_bytes': 6_197_215_896,
            'remaining_initial_PCS_before_other_live_state': arena-6_197_215_896,
            'scratch_slots_are_proposed_caps_not_implemented_bounds': True,
            'query_tree_and_folded_PCS_state_peak_bytes': None,
        },
        'time_upper_contract': {
            'expression': 'T_response <= sum_k T_k_upper; T_k_upper = L_k_upper + sum_j work_kj/R_kj_min + HBM_k/BW_k_min + external_k/BWext_k_min',
            'condition': 'certified workload-specific lower service rates and bounded stalls; serial charges, no assumed overlap',
            'categories': ['inference', 'A/KV reconstruction and producer GKR', 'range W',
                           'range A', 'linear W/A/old A', 'PCS all data and mask oracles',
                           'PCG/OT/MAC/FS', 'serialization and external response transport',
                           'allocation/launch/synchronization/host scheduling'],
            'all_category_work_and_service_contracts_available': False,
            'admission_upper': '+infinity',
        },
        'minimum_missing_checks': {
            'A_KV': 'bounded immutable getter trace across all 3471 source recipes and three contexts; reads/recomputations and live buffers',
            'PCS': 'canonical salt/hash/pad adapter with all switch and mask oracles and original terminal MACs',
            'PCG': 'bounded AES/cGGM producer-consumer trace, seed/state/OT allocations and no bulk output pool',
            'time': 'full work census and applicable service-rate floors; component peak bandwidth cannot supply these',
        },
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
    suffix = suffix_first_weight_budget()
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
        'coset_Merkle_frontier': coset_frontier_budget(),
        'suffix_first_W_linear_reducer': suffix,
        'integrated_schedule': integrated_schedule_screen(suffix),
        'local_preflight': local_preflight(gram_window_budget(35, 10, 61_394_690_560, 25), suffix),
        'integrated_resource_ledger': integrated_resource_ledger(assessment),
        'dominant_cost_screen': dominant_cost_screen(assessment),
        'arena_bytes': arena,
        'native_Dory_implemented': False,
        'physical_schedule_admitted': False,
        'complete_prover_seconds_upper': None,
        'goal_complete': False,
    }


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
