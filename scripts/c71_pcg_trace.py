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
DORY_SEED_ROWS = TREES*(HEIGHT+4)+3
EQ_SEED_ROWS = 3*TREES
MAIN_SEED_ROWS = DORY_SEED_ROWS+EQ_SEED_ROWS
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


def seed6_real_trace(n):
    """Source operations and named native heap bodies; no HBM/physical credit.

    Host ABI point/scalar sizes and context capacity are observed in reduced
    Rust tests. Crypto stack, allocator and transport still need integration.
    """
    if not 0 < n <= (1 << 24)-9:
        raise ValueError('outside the conservative fixed-run profile')
    rows, height = n+6, (n+5).bit_length()
    parties = {}
    for role, branches in [('prover', 2), ('verifier', 1)]:
        outputs = branches*384*rows
        retained = 32*n+48 if role == 'prover' else 24*n
        arrays = 56*rows if role == 'prover' else 48*rows
        heap = {
            'mr19': (266_496 if role == 'prover' else 245_376)+240,
            'cope': arrays+240+3072+(24_576 if role == 'prover' else 12_288),
            'check': arrays+(48 if role == 'prover' else 96),
            'compression': arrays+24*n,
            'retained_output': retained,
        }
        parties[role] = {
            'PRF_field_outputs': outputs,
            'AES256_key_schedules': outputs*height,
            'AES256_block_encryptions': 4*outputs*height,
            'field_sampler_candidates': 8*(outputs+(rows if role == 'prover' else 6*n+12)),
            'cope_Fp_products': 384*rows,
            'cope_Fp_adds': (1 if role == 'prover' else 2)*384*rows,
            'cope_Fp_subtractions': (2 if role == 'prover' else 0)*384*rows,
            'fixed_scalar_mul': 768, 'variable_scalar_mul': 768,
            'scalar_sampler_candidates': 6144, 'group_hashes': 768,
            'group_candidates_lower': 768, 'group_candidates_upper': 512*768,
            'point_additions': 768 if role == 'prover' else 384, 'KDF_calls': 768,
            'heap_phase_bytes': heap, 'heap_phase_peak_bytes': max(heap.values()),
            'check_named_nonheap_bytes': 240 if role == 'prover' else 192,
            'compression_named_nonheap_bytes': 48 if role == 'prover' else 168,
            'retained_nonheap_secret_bytes': 0 if role == 'prover' else 24,
            'MR19_Delta_nonheap_bytes': 0 if role == 'prover' else 48,
            'logical_COPE_write_bytes': arrays,
            'logical_COPE_PRF_seed_input_bytes': outputs*32,
            'logical_check_read_bytes': arrays+48*n,
            'logical_compression_read_bytes': 48*n+(0 if role == 'prover' else 48),
            'logical_compression_write_bytes': 24*n+(0 if role == 'prover' else 24),
        }
    return {
        'rows': n, 'mask_rows': 6, 'AES_path_height': height,
        'wire_bytes_both_directions_without_seal': 146_451+3120*n,
        'planned_seal_bytes_not_implemented': 40,
        'wire_delta_vs_old_screen_per_seed_bytes': 2,
        'common_context_bytes': 121, 'full_context_bytes': 185,
        'binding_digest_retained_bytes': 32,
        'full_context_observed_capacity_bytes': 240,
        'prover': parties['prover'], 'verifier': parties['verifier'],
        'K6_check_and_compression': seed6_boundary(n),
        'physical_peak_complete': False, 'HBM_traffic_credit': False,
        'outer_lifetime_guard_roleswap_composition_credit': False,
        'missing_physical': ['allocator metadata/reserve', 'crypto stack/spills',
                             'audit vectors', 'transport buffering', 'outer setup lifecycle'],
    }


def seed6_guard_trace(blocks=TREES, height=HEIGHT):
    """Original-row consumer only; outer FS/transport/one-use seal still open."""
    if not 0 < blocks <= 675 or not 0 < height <= 19:
        raise ValueError('outside bounded guard geometry')
    triples, count = blocks*height, blocks*(height+1)
    return {
        'triple_count': triples, 'Dory_rows': blocks*(height+4)+3,
        'global_mask_row_ids': list(range(blocks*(height+4), blocks*(height+4)+3)),
        'split_rows_retained': 3*blocks,
        'correction_payload_bytes': 8*count, 'proof_payload_bytes': 48,
        'correction_Fp_multiplications': triples,
        'correction_Fp_add_sub': blocks+triples,
        'prover_Fp3_multiplications': 6*triples+6,
        'prover_Fp3_add_sub': 8*triples+6,
        'verifier_Fp3_multiplications': 4*triples+4,
        'verifier_Fp3_by_Fp_multiplications': 2*triples,
        'verifier_Fp3_add_sub': 5*triples+5,
        'verifier_Fp3_equality_comparisons': 1,
        'prefix_hash_absorbed_bytes_each_role': 85+16*count,
        'prefix_hash_update_calls_each_role': 5+2*count,
        'prefix_digest_bytes_each_role': 32,
        'Seed6_binding_retained_bytes_each_role': 32,
        'Seed6_binding_hash_input_bytes_each_role': 185,
        'native_Frozen_size_bytes': 72,
        'native_ProverGuard_size_bytes': 528,
        'native_VerifierChallenged_size_bytes': 552,
        'native_BLAKE3_Hasher_size_bytes': 1920,
        'native_sizes_scope': 'observed CPU ABI; not total stack/spill reserve',
        'verifier_challenge_retained_bytes': 24,
        'correction_heap_capacity_bytes_each_role': 8*count,
        'triple_vector_allocation_bytes': 0,
        'prover_logical_original_seed_reads_bytes': 64*triples+96,
        'verifier_logical_original_seed_reads_bytes': 48*triples+96,
        'logical_correction_reads_bytes_each_role': 16*triples,
        'counter_scope': 'source field calls and logical payload; not HBM/instruction counts',
        'challenge_fixed_before_proof_input': True,
        'global_FS_codec_credit': False, 'durable_burn_credit': False,
        'cGGM_producer_before_after_guard_connected': False,
        'complete_physical_peak': False,
    }


def seed6_tail_reservation_trace(rows=MAIN_SEED_ROWS, tail=EQ_SEED_ROWS):
    """Copy only the disjoint tail; erased prefix slack remains allocated."""
    if not 0 < tail < rows:
        raise ValueError('nonempty prefix and tail required')
    roles = {}
    for role, stride, slack in [('prover', 32, 48), ('verifier', 24, 0)]:
        source = stride*rows+slack
        copied = stride*tail
        roles[role] = {
            'copied_payload_bytes':copied,
            'logical_copy_read_bytes':copied,
            'logical_copy_write_bytes':copied,
            'logical_explicit_erasure_write_bytes':copied,
            'source_vec_capacity_bytes':source,
            'new_tail_vec_capacity_bytes':copied,
            'destination_vec_capacity_bytes':source+copied,
            'named_vec_capacity_peak_bytes':source+copied,
            'duplicated_fixed_secret_bytes':24 if role=='verifier' else 0,
        }
    return dict(rows=rows, tail_rows=tail, prefix_rows=rows-tail, **roles,
                consuming_split_implemented=True, original_binding_preserved=True,
                prefix_capacity_retained=True, tail_erased_before_truncate=True,
                capacity_scope='selected native Vec capacities; no allocator/stack/HBM credit',
                complete_physical_peak=False)


def seed6_equality_trace(n=TREES):
    """Two-key consumer after both seed completions; no outer F_Rand/seal credit."""
    if not 1 <= n <= TREES:
        raise ValueError('equality requires 1..675 coordinates')
    domain = len(b'VOLTA-C71-Seed6-equality-v1')
    return {
        'coordinates':n, 'reserved_tail_rows_each_seed':3*n,
        'correction_payload_bytes_each_role':24*n,
        'commit_payload_bytes_each_role':32, 'opening_payload_bytes_each_role':56,
        'wire_both_roles_without_coins_or_seed':48*n+212,
        'framing_assumption':'six existing 6-byte frame headers, not yet transported',
        'Fp3_multiplications_each_role':10*n+1,
        'Fp3_by_Fp_multiplications_each_role':3*n,
        'Fp3_additions_role0':12*n,
        'Fp3_additions_role1':12*n+2,
        'Fp3_subtractions_role0':2*n+2,
        'Fp3_subtractions_role1':2*n,
        'Fp3_negations_role0':1,
        'Fp3_negations_role1':0,
        'acceptance_Fp3_additions_each_role':1,
        'acceptance_Fp3_equality_tests_each_role':1,
        'prefix_hash_absorbed_bytes_each_role':domain+len(b'/corrections/')+32+8+64+2+48*n,
        'prefix_hash_update_calls_each_role':10,
        'share_commit_hash_absorbed_bytes_each_role':domain+len(b'/share/')+32+1+56,
        'share_commit_and_peer_verify_hash_calls_each_role':2,
        'owned_input_payload_bytes_each_role':24*n,
        'extra_owned_heap_phase_bytes_each_role':{
            'prepare':48*n, 'freeze_with_received_frame':96*n,
            'commit_with_coins':96*n, 'open_and_verify':0},
        'seed_output_liveness':'only exact reserved tails owned until share commitment; outer prefix retained separately',
        'diagnostic_Audit_Vecs_released_before_correction_allocation':True,
        'each_consumer_seed_rows_exact':3*n,
        'consuming_disjoint_tail_reservation_implemented':True,
        'guard_prefix_then_equality_tail_reduced_real_check':True,
        'native_Prepared_size_bytes':1000, 'native_Frozen_size_bytes':1056,
        'native_Committed_size_bytes':121, 'native_Openable_size_bytes':153,
        'native_BLAKE3_Hasher_size_bytes':1920,
        'native_value_state_slot_bytes':4096,
        'native_value_state_slot_is_not_compiler_stack_bound':True,
        'logical_original_seed_reads_bytes_each_role':168*n+24,
        'logical_correction_payload_read_bytes_each_role':24*n,
        'counter_scope':'source field calls and owned payload; no hardware instructions/HBM credit',
        'both_corrections_fixed_before_coin_callback':True,
        'peer_commitment_fixed_before_own_opening':True,
        'global_F_Rand_or_seal_credit':False,
        'guard_cGGM_to_equality_connected':False,
        'complete_physical_peak':False,
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
    compressed_elements = MAIN_SEED_ROWS+EQ_SEED_ROWS+1
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
            'conditional_bootstrap_wire_both_directions_bytes': 61_841_294,
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
                'main': seed6_boundary(MAIN_SEED_ROWS),
                'roleswap': seed6_boundary(3*TREES),
                'separate_seed_Delta_each': True,
            },
            'native_seed6_real_adapter': {
                'main': seed6_real_trace(MAIN_SEED_ROWS),
                'roleswap': seed6_real_trace(EQ_SEED_ROWS),
                'Dory_rows': DORY_SEED_ROWS, 'F_EQ_extra_rows_each_seed': EQ_SEED_ROWS,
                'path_guard_consumer': seed6_guard_trace(),
                'two_key_equality_consumer':seed6_equality_trace(),
                'disjoint_tail_reservation':seed6_tail_reservation_trace(),
                'physical_roles_opposite': True, 'composed_execution_credit': False,
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
                'main_seed_rows': MAIN_SEED_ROWS,
                'main_seed_rows_prover_native_bytes': MAIN_SEED_ROWS*32,
                'main_seed_rows_verifier_native_bytes': MAIN_SEED_ROWS*24,
                'main_seed_rows_prover_Fp6_materialized_bytes': MAIN_SEED_ROWS*(8+48),
                'main_seed_rows_verifier_Fp6_materialized_bytes': MAIN_SEED_ROWS*48,
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
                'streamed_AES_COPE_and_K6_component_checked': True,
                'guard_roleswap_lifetime_credit': False,
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
