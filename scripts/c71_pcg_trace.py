#!/usr/bin/env python3
"""Bounded accounting trace for the candidate C7.1 streaming PCG.

This is an analytic trace, not the missing Fp3 cGGM/ROM implementation.
"""
import json
import hashlib
from collections import Counter
from fractions import Fraction


ROWS = ((0, 3_814_605), (150, 3_826_014), (300, 3_826_329))
BATCH = 4096
TREES, HEIGHT, WEIGHT = 675, 19, 11
DOMAIN = TREES * (1 << HEIGHT)
P = 0xffff_ffff_0000_0001
CGGM_TAG = b"VOLTA-C71-DORY-CGGM-v1"
H_DOMAIN_BYTES = len(CGGM_TAG)+32+8+4+8+24
EA_TAG = b"VOLTA-C71-DORY-EAGEN-v1"


def reference_cggm_h(nonce, block, level, position, node):
    """Reference-only H_D codec and bounded Fp3 rejection trace.

    Numeric labels are fixed-width little endian. This is a minimal local
    codec decision requiring bit-for-bit native refinement, not implemented
    production SHAKE/cGGM credit.
    """
    if len(nonce) != 32 or len(node) != 3 or not all(0 <= x < P for x in node):
        raise ValueError('canonical nonce/Fp3 node required')
    domain = (CGGM_TAG + nonce + block.to_bytes(8, 'little')
              + level.to_bytes(4, 'little') + position.to_bytes(8, 'little')
              + b''.join(x.to_bytes(8, 'little') for x in node))
    tape = hashlib.shake_256(domain).digest(3*8*8)
    output, candidates = [], 0
    for limb in range(3):
        for trial in range(8):
            candidates += 1
            offset = 8*(8*limb+trial)
            value = int.from_bytes(tape[offset:offset+8], 'little')
            if value < P:
                output.append(value)
                break
        else:
            raise RuntimeError('bounded Fp3 sampler exhausted')
    return tuple(output), {'RO_calls': 1, 'Fp_candidates': candidates,
                           'candidate_cap': 24, 'domain_bytes': len(domain)}


def public_EA_row(seed, row, domain=DOMAIN, weight=WEIGHT, max_trials=8):
    """Candidate public-coin codec for one weight-ell EAGen row."""
    if len(seed) != 32 or not 0 <= row < 1 << 64:
        raise ValueError('seed32 and row64 required')
    if not 0 < weight <= domain < 1 << 64 or not 0 < max_trials <= 8:
        raise ValueError('invalid fixed-cap EAGen sampler parameters')
    limit = (1 << 64)//domain*domain
    indices, terms, index_candidates, coefficient_candidates = set(), [], 0, 0
    for term in range(weight):
        prefix = EA_TAG+seed+row.to_bytes(8, 'little')+term.to_bytes(4, 'little')
        tape = hashlib.shake_256(prefix+b'index').digest(8*max_trials)
        for trial in range(max_trials):
            index_candidates += 1
            value = int.from_bytes(tape[8*trial:8*(trial+1)], 'little')
            if value < limit and value % domain not in indices:
                index = value % domain
                indices.add(index)
                break
        else:
            raise RuntimeError('bounded distinct-index sampler exhausted')
        tape = hashlib.shake_256(prefix+b'coefficient').digest(8*max_trials)
        for trial in range(max_trials):
            coefficient_candidates += 1
            coefficient = int.from_bytes(tape[8*trial:8*(trial+1)], 'little')
            if 0 < coefficient < P:
                break
        else:
            raise RuntimeError('bounded nonzero-Fp sampler exhausted')
        terms.append((index, coefficient))
    return terms, {'RO_calls': 2*weight, 'index_candidates': index_candidates,
                   'coefficient_candidates': coefficient_candidates,
                   'candidate_cap': 2*weight*max_trials,
                   'logical_row_bytes': 16*weight}


def seed6_boundary(rows):
    """Exact arithmetic/named payload of the reduced Rust check, not OT/peak."""
    if rows <= 0:
        raise ValueError('nonempty seed required')
    return {
        'rows': rows, 'masks': 6,
        'prover_K6_products': rows+6, 'prover_K6_base_products': rows+6,
        'prover_K6_adds': 2*(rows+6),
        'verifier_K6_products': rows+6, 'verifier_K6_adds': rows+6,
        'relation_K6_products': 1, 'relation_K6_adds': 1,
        'compression_Fp3_products_both_roles': 4*rows+2,
        'compression_Fp3_adds_both_roles': 2*rows+1,
        'prover_borrowed_input_bytes': 104*rows+336,
        'verifier_borrowed_input_bytes': 96*rows+288,
        'prover_check_payload_bytes': 96, 'verifier_check_payload_bytes': 48,
        'prover_compressed_output_bytes': 24*rows,
        'verifier_compressed_output_bytes': 24*(rows+1),
        'input_scan_bytes_both_roles': 200*rows+624,
        'compression_input_read_bytes_both_roles': 96*rows+48,
        'compression_output_write_bytes_both_roles': 48*rows+24,
        'HBM_traffic_credit': False,
        'physical_peak_credit': False,
        'OT_guard_roleswap_composition_credit': False,
        'source': 'rust/volta-pcg/src/c71_seed6.rs',
    }


def trie_nodes(rows):
    """Distribution-free union-trie upper for public EA point terms."""
    terms = WEIGHT * rows
    return sum(min(TREES * (1 << level), terms) for level in range(HEIGHT))


def response_trace(old_tokens, first_row, rows, fail_after_batches=None):
    """Reserve first, then stream raw base rows with a two-row carry."""
    transitions, carry, consumed, batch_count = Counter(), 0, 0, 0
    offset = 0
    while offset < rows:
        take = min(BATCH, rows-offset)
        before = carry
        complete, carry = divmod(before+take, 3)
        transitions[take, before, complete, carry] += 1
        batch_count += 1
        consumed += complete
        offset += take
        if fail_after_batches is not None and batch_count >= fail_after_batches:
            break
    aborted = offset < rows
    h_calls = sum(count*trie_nodes(take)
                  for (take, _before, _complete, _after), count in transitions.items())
    terms = WEIGHT*offset
    return {
        'old_tokens': old_tokens,
        'reservation_burned_before_generation': [first_row, first_row+rows],
        'reserved_base_rows': rows,
        'processed_base_rows': offset,
        'burned_base_rows_even_on_abort': rows,
        'batch_count': batch_count,
        'batch_transitions': [
            {'count': count, 'raw_rows': take, 'carry_in': before,
             'Fp3_correlations_consumed': complete, 'carry_out': after}
            for (take, before, complete, after), count in sorted(transitions.items())],
        'aborted': aborted,
        'discarded_carry_on_abort': carry if aborted else 0,
        'final_carry': None if aborted else carry,
        'Fp3_correlations_consumed': consumed,
        'public_EA_terms_upper': terms,
        'independent_path_H_evaluations_upper_per_role': terms*HEIGHT,
        'union_trie_H_evaluations_upper_per_role': h_calls,
        'H_Fp_rejection_candidates_upper_per_role': 24*h_calls,
        'cGGM_right_child_Fp_subtractions_upper_per_role': 3*h_calls,
        'sender_Acc_Fp3_additions_upper': (HEIGHT+1)*terms,
        'receiver_PuncAcc_Fp3_additions_upper': 2*HEIGHT*terms,
        'EA_Fp3_by_public_Fp_multiplications_upper_per_role': terms,
        'EA_Fp3_accumulations_upper_per_role': terms,
        'logical_prover_output_bytes': 32*offset,
        'logical_verifier_output_bytes': 24*offset,
        'output_HBM_bytes_lower': None,
    }


def report():
    cursor, responses = 0, []
    for old_tokens, rows in ROWS:
        trace = response_trace(old_tokens, cursor, rows)
        assert trace['final_carry'] == 0
        responses.append(trace)
        cursor += rows
    setup_h = 2*TREES*((1 << HEIGHT)-1)
    path_bytes = (HEIGHT+7)//8
    common = 32+32+8  # cGGM nonce, public EAGen seed, counter
    sender_persistent = 24 + TREES*(24+24) + common
    # PuncSetup returns h siblings and the alternatively defined alpha leaf;
    # M(beta) is retained separately by Fig. 5.
    receiver_serialized = TREES*(path_bytes+8+(HEIGHT+1)*24+24) + common
    receiver_aligned = TREES*(4+8+(HEIGHT+1)*24+24) + common
    rejection = Fraction(DOMAIN, 1 << 64)+Fraction(WEIGHT, DOMAIN)
    coefficient_rejection = Fraction((1 << 64)-P+1, 1 << 64)
    ea_failure = 70_778_880*WEIGHT*(rejection**8+coefficient_rejection**8)
    # Roles swap for the second seed: each physical role compresses all row
    # tags/keys and exactly the one Delta it owns in its verifier role.
    compressed_elements = 15_528+3*TREES+1
    extension_h = sum(r['union_trie_H_evaluations_upper_per_role'] for r in responses)
    h_rejection = Fraction((1 << 64)-P, 1 << 64)
    h_failure_both_roles = 2*3*(setup_h+extension_h)*h_rejection**8
    return {
        'credit': False,
        'profile': {'t': TREES, 'h': HEIGHT, 'ell': WEIGHT,
                    'N': DOMAIN, 'batch_base_rows': BATCH},
        'setup_once_before_all_responses': {
            'internal_cGGM_H_evaluations_lower_per_role_if_two_full_traversals': setup_h,
            'universal_hash_field_inputs_lower_per_role': DOMAIN,
            'conditional_bootstrap_wire_both_directions_bytes': 61_841_290,
            'H_to_AES_calls': None,
            'H_to_domain_separated_SHAKE_RO_calls': setup_h,
            'H_SHAKE_absorbed_bytes': setup_h*H_DOMAIN_BYTES,
            'H_SHAKE_squeezed_bytes_upper': setup_h*192,
            'H_Fp_rejection_candidates_upper_per_role': 24*setup_h,
            'cGGM_right_child_Fp_subtractions_per_role': 3*setup_h,
            'universal_hash_Fp3_multiplications_per_role': DOMAIN,
            'universal_hash_Fp3_accumulations_per_role': DOMAIN,
            'Fp6_to_Fp3_compressed_elements_per_role': compressed_elements,
            'Fp6_to_Fp3_linear_Fp3_multiplications_per_role': 2*compressed_elements,
            'Fp6_to_Fp3_linear_Fp3_additions_per_role': compressed_elements,
            'compression_excludes_sampler_and_limb_reduction_costs': True,
            'field_operations_complete': None,
            'native_seed6_check_and_compression': {
                'main': seed6_boundary(15_528),
                'roleswap': seed6_boundary(3*TREES),
                'separate_seed_Delta_each': True,
            },
            'persistent_selected_cGGM_state': {
                'sender_canonical_bytes': sender_persistent,
                'receiver_canonical_serialized_bytes': receiver_serialized,
                'receiver_u32_path_aligned_bytes': receiver_aligned,
                'both_roles_canonical_bytes_if_colocated': sender_persistent+receiver_serialized,
                'native_roles': 'sender P0 is DV verifier; receiver P1 is GPU prover',
                'DV_verifier_sender_canonical_bytes': sender_persistent,
                'GPU_prover_receiver_u32_path_aligned_bytes': receiver_aligned,
                'sender_per_tree': 'k_i Fp3 + K(beta_i) Fp3',
                'receiver_per_tree': ('19-bit alpha + beta Fp + 19 sibling Fp3 + '
                                      'alternative alpha-leaf Fp3 + M(beta) Fp3'),
                'shared_fields_each_role': 'cGGM nonce 32 B + EAGen seed 32 B + counter u64',
                'public_EAGen_seed_and_counter_bytes': 40,
                'public_EAGen_one_row_terms_bytes_already_within_batch_arrays': WEIGHT*16,
                'OT_Fp6_backend_state_bytes': None,
            },
            'transient_named_setup_arrays_not_complete_peak': {
                'path_c_Fp3_bytes': TREES*HEIGHT*24,
                'path_d_Fp_bytes': TREES*HEIGHT*8,
                'main_seed_rows': 15_528,
                'main_seed_rows_prover_native_bytes': 15_528*32,
                'main_seed_rows_verifier_native_bytes': 15_528*24,
                'main_seed_rows_prover_Fp6_materialized_bytes': 15_528*(8+48),
                'main_seed_rows_verifier_Fp6_materialized_bytes': 15_528*48,
                'roleswap_seed_rows': 3*TREES,
                'roleswap_seed_rows_prover_native_bytes': 3*TREES*32,
                'roleswap_seed_rows_verifier_native_bytes': 3*TREES*24,
                'roleswap_seed_rows_prover_Fp6_materialized_bytes': 3*TREES*(8+48),
                'roleswap_seed_rows_verifier_Fp6_materialized_bytes': 3*TREES*48,
                'Fp6_materialization_may_be_erased_after_Fp3_compression': True,
                'complete_setup_peak_bytes': None,
            },
        },
        'responses': responses,
        'fixed_run': {
            'reserved_base_rows': cursor,
            'union_trie_H_evaluations_upper_per_role': sum(
                r['union_trie_H_evaluations_upper_per_role'] for r in responses),
            'extension_SHAKE_RO_calls_upper_per_role': sum(
                r['union_trie_H_evaluations_upper_per_role'] for r in responses),
            'extension_SHAKE_squeezed_bytes_upper_per_role': 192*sum(
                r['union_trie_H_evaluations_upper_per_role'] for r in responses),
            'EAGen_RO_calls_per_role': 22*cursor,
            'EAGen_logical_term_bytes_per_role': 16*WEIGHT*cursor,
            'EAGen_bounded_sampler_failure_upper': str(ea_failure),
            'H_bounded_sampler_failure_upper_both_roles': str(h_failure_both_roles),
            'H_Fp_rejection_candidates_upper_per_role': sum(
                r['H_Fp_rejection_candidates_upper_per_role'] for r in responses),
            'cGGM_right_child_Fp_subtractions_upper_per_role': sum(
                r['cGGM_right_child_Fp_subtractions_upper_per_role'] for r in responses),
            'sender_Acc_Fp3_additions_upper': sum(
                r['sender_Acc_Fp3_additions_upper'] for r in responses),
            'receiver_PuncAcc_Fp3_additions_upper': sum(
                r['receiver_PuncAcc_Fp3_additions_upper'] for r in responses),
            'EA_Fp3_by_public_Fp_multiplications_upper_per_role': WEIGHT*cursor,
            'EA_Fp3_accumulations_upper_per_role': WEIGHT*cursor,
            'logical_prover_output_bytes': 32*cursor,
            'logical_verifier_output_bytes': 24*cursor,
        },
        'liveness_caps': {
            'prover_raw_batch_bytes': BATCH*32,
            'verifier_raw_batch_bytes': BATCH*24,
            'prover_two_row_carry_bytes': 2*32,
            'verifier_two_row_carry_bytes': 2*24,
            'two_aligned_public_term_arrays_bytes': 2*BATCH*WEIGHT*16,
            'two_sparse_Fp3_frontiers_bytes_per_role': 2*BATCH*WEIGHT*24,
            'public_u32_histogram_bytes': BATCH*WEIGHT*4,
            'consumer_and_backend_live_bytes_upper': None,
        },
        'backend_boundary': {
            'implemented': 'B11/Fp9 seed bootstrap and AES128-MMO binary GGM diagnostics',
            'selected_plan': 'domain-separated Fp3 SHAKE/ROM cGGM with additive children',
            'selected_cGGM_native_implemented': False,
            'bounded_real_MR19_seed6': {
                'OT_count': 384,
                'group_domain': 'C71S6/MR19/group/receiver/v1/',
                'KDF_domain': 'C71S6/MR19/seed/sender/v1/',
                'wire_payload_bytes': 127_488,
                'wire_framing_bytes': 27,
                'fixed_scalar_multiplications_each_role': 768,
                'variable_scalar_multiplications_each_role': 768,
                'group_hash_evaluations_each_role': 768,
                'KDF_evaluations_each_role': 768,
                'receiver_point_additions': 384,
                'sender_point_additions': 768,
                'COPE_guard_roleswap_lifetime_credit': False,
            },
            'bounded_CPU_codec_and_Acc_PuncAcc_refinement': {
                'source': 'rust/volta-pcg/src/c71_ea_lpn.rs',
                'H_and_EAGen_match_python_vectors': True,
                'H_output_bytes_each_evaluation': 192,
                'H_fixed_candidate_slots_bytes_per_limb': 64,
                'H_SHAKE256_permutations_each_evaluation': 2,
                'EA_SHAKE256_permutations_per_term': 2,
                'punctured_prefix_identity_exhaustive_heights': [1,2,3,4,5,6,7],
                'OT_Fp6_bridge_and_composed_MAC_credit': False,
            },
            'AES128_MMO_is_selected_Fp3_cGGM': False,
            'reference_H_codec': ('tag || nonce[32] || block_u64_le || level_u32_le || '
                                  'position_u64_le || three canonical u64_le limbs'),
            'reference_H_sampler': 'one SHAKE256 XOF; eight u64 trials per Fp limb; fail closed',
            'reference_H_RO_calls_per_internal_evaluation': 1,
            'public_EAGen_reference_codec': ('separate SHAKE256 XOFs over tag || seed32 || '
                                             'row_u64_le || term_u32_le || kind'),
            'public_EAGen_reference_is_same_public_coin_not_new_message': True,
            'public_EAGen_native_or_theorem_refinement': False,
            'runtime_upper_seconds': None,
        },
        'safe_fusions': [
            'hash the second setup traversal into the late universal-hash accumulator',
            'share public trie prefixes only within the same tree/block/domain label',
            'combine each three base rows and immediately consume the canonical Fp3 row',
            'regenerate public EA weights from their public seed instead of retaining them',
        ],
        'correlation_reuse': False,
        'minimum_missing_check': ('batched union-trie execution, real OT/Fp6 bridge and composed MAC consumption; '
                                  'complete field/OT counters and physical backend workspace liveness'),
    }


if __name__ == '__main__':
    print(json.dumps(report(), indent=2))
