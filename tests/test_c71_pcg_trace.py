"""Finite PCG scheduling/accounting checks; no cryptographic execution."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_pcg_trace as trace


def test_three_response_trace_burns_disjoint_reservations_and_carries_rows():
    report = trace.report()
    responses = report['responses']
    assert [r['reserved_base_rows'] for r in responses] == [
        3_814_605, 3_826_014, 3_826_329]
    assert [r['reservation_burned_before_generation'] for r in responses] == [
        [0, 3_814_605], [3_814_605, 7_640_619], [7_640_619, 11_466_948]]
    assert all(r['final_carry'] == 0 for r in responses)
    assert any(b['carry_in'] == 2 for b in responses[0]['batch_transitions'])
    assert sum(b['count']*b['raw_rows'] for b in responses[0]['batch_transitions']) == 3_814_605
    assert sum(b['count']*b['Fp3_correlations_consumed']
               for b in responses[0]['batch_transitions']) == 1_271_535
    assert report['fixed_run']['logical_prover_output_bytes'] == 366_942_336
    assert report['fixed_run']['logical_verifier_output_bytes'] == 275_206_752


def test_abort_burns_full_reservation_and_discards_unpaired_rows():
    failed = trace.response_trace(0, 123, 3_814_605, fail_after_batches=1)
    assert failed['reservation_burned_before_generation'] == [123, 3_814_728]
    assert failed['processed_base_rows'] == 4096
    assert failed['burned_base_rows_even_on_abort'] == 3_814_605
    assert failed['discarded_carry_on_abort'] == 1
    assert failed['final_carry'] is None


def test_distribution_free_trie_and_unknown_backend_costs():
    report = trace.report()
    assert trace.trie_nodes(4096) == 626_397
    assert [r['union_trie_H_evaluations_upper_per_role'] for r in report['responses']] == [
        583_385_798, 585_121_123, 585_174_648]
    assert report['fixed_run']['union_trie_H_evaluations_upper_per_role'] == 1_753_681_569
    setup = report['setup_once_before_all_responses']
    assert setup['internal_cGGM_H_evaluations_upper_per_role_two_passes'] == 707_786_100
    assert setup['H_to_AES_calls'] is None and setup['field_operations_complete'] is None
    assert setup['Fp6_to_Fp3_compressed_elements_per_role'] == 19_579
    assert setup['Fp6_to_Fp3_linear_Fp3_multiplications_per_role'] == 39_158
    assert setup['Fp6_to_Fp3_linear_Fp3_additions_per_role'] == 19_579
    assert not report['backend_boundary']['AES128_MMO_is_selected_Fp3_cGGM']


def test_reference_cggm_domain_separation_sampler_and_persistent_state():
    nonce = bytes(range(32))
    left, count = trace.reference_cggm_h(nonce, 7, 3, 11, (1, 2, 3))
    assert left == trace.reference_cggm_h(nonce, 7, 3, 11, (1, 2, 3))[0]
    assert left != trace.reference_cggm_h(nonce, 7, 3, 12, (1, 2, 3))[0]
    assert all(0 <= x < trace.P for x in left)
    assert count['RO_calls'] == 1 and count['Fp_candidates'] <= 24
    assert count['domain_bytes'] == trace.H_DOMAIN_BYTES == 98
    persistent = trace.report()['setup_once_before_all_responses'][
        'persistent_selected_cGGM_state']
    assert persistent['sender_canonical_bytes'] == 32_496
    assert persistent['receiver_canonical_serialized_bytes'] == 347_697
    assert persistent['receiver_u32_path_aligned_bytes'] == 348_372
    assert persistent['both_roles_canonical_bytes_if_colocated'] == 380_193
    assert persistent['public_EAGen_seed_and_counter_bytes'] == 40


def test_public_eagen_rows_are_deterministic_distinct_and_domain_separated():
    seed = bytes(reversed(range(32)))
    first, audit = trace.public_EA_row(seed, 9)
    assert first == trace.public_EA_row(seed, 9)[0]
    assert first != trace.public_EA_row(seed, 10)[0]
    assert len(first) == 11 and len({index for index, _ in first}) == 11
    assert all(0 <= index < trace.DOMAIN and 0 < coefficient < trace.P
               for index, coefficient in first)
    assert audit['RO_calls'] == 22 and audit['logical_row_bytes'] == 176


def test_public_eagen_small_domain_fails_closed_when_trial_cap_exhausts():
    failures = 0
    for byte in range(32):
        try:
            trace.public_EA_row(bytes([byte])*32, 0, domain=2, weight=2, max_trials=1)
        except RuntimeError:
            failures += 1
    assert failures > 0


def test_seed6_boundary_matches_reduced_native_payload_and_work():
    bounded = trace.seed6_boundary(3)
    assert [bounded[k] for k in ('prover_K6_products', 'verifier_K6_products',
        'relation_K6_products', 'compression_Fp3_products_both_roles')] == [9, 9, 1, 14]
    assert [bounded[k] for k in ('prover_borrowed_input_bytes',
        'verifier_borrowed_input_bytes', 'prover_compressed_output_bytes',
        'verifier_compressed_output_bytes')] == [648, 576, 72, 96]
    setup = trace.report()['setup_once_before_all_responses']['native_seed6_check_and_compression']
    assert setup['main']['rows'] == 17_553
    assert setup['roleswap']['rows'] == 2_025
    assert not setup['main']['physical_peak_credit']
    assert not setup['roleswap']['OT_guard_roleswap_composition_credit']


def test_real_seed6_wire_work_and_named_heap_match_native_reduced_runs():
    for n, wire, blocks, fields in [(1,149571,64512,43064),(3,155811,110592,55368)]:
        real = trace.seed6_real_trace(n)
        assert real['wire_bytes_both_directions_without_seal'] == wire
        assert real['wire_bytes_both_directions_with_seal']==wire+40
        assert real['completion_seal_native_bytes']==40
        assert real['completion_seal_before_any_output'] and real['seal_already_in_bootstrap_screen']
        assert real['prover']['AES256_block_encryptions'] == blocks
        assert real['prover']['field_sampler_candidates'] == fields
        assert real['prover']['heap_phase_peak_bytes'] == 266736
        assert real['verifier']['heap_phase_peak_bytes'] == 245616
        for role in ('prover','verifier'):
            assert real[role]['heap_phase_bytes']['seal']==real[role]['heap_phase_bytes']['retained_output']
        assert not real['physical_peak_complete']
    setup = trace.report()['setup_once_before_all_responses']['native_seed6_real_adapter']
    assert setup['Dory_rows'] == 15528
    assert setup['main']['rows'] == 15528+2025
    assert setup['roleswap']['rows'] == 2025
    assert setup['main']['prover']['heap_phase_peak_bytes'] == 80*17553+336
    assert sum(setup[k]['wire_delta_vs_old_screen_per_seed_bytes'] for k in ['main','roleswap']) == 4


def test_original_guard_rows_and_named_arena_state():
    import hashlib
    guard=trace.seed6_guard_trace()
    assert guard['triple_count']==12825
    assert guard['global_mask_row_ids']==[15525,15526,15527]
    assert guard['Dory_rows']==15528
    assert guard['split_rows_retained']==2025
    assert guard['correction_heap_capacity_bytes_each_role']==108000
    assert guard['prefix_hash_absorbed_bytes_each_role']==216085
    assert guard['prefix_hash_update_calls_each_role']==27005
    assert guard['prover_Fp3_multiplications']==76956
    assert guard['verifier_Fp3_multiplications']==51304
    assert guard['verifier_Fp3_by_Fp_multiplications']==25650
    assert guard['verifier_Fp3_add_sub']==64130
    assert guard['challenge_fixed_before_proof_input']
    prefix=b'VOLTA-C71-Seed6-path-guard-v1/challenge/'+bytes([1])*32
    tape=hashlib.shake_256(prefix).digest(192)
    assert [int.from_bytes(tape[index*64:index*64+8],'little') for index in range(3)]==[
        12348370486373678026,8578382865034854480,9726913847348157411]
    assert guard['challenge_SHAKE_absorbed_bytes_each_role']==len(prefix)==72
    assert guard['challenge_SHAKE_squeezed_bytes_each_role']==192
    assert guard['sealed_prefix_native_challenge']
    assert not guard['global_FS_codec_credit']


def test_two_key_equality_work_and_bounded_heap_envelope():
    eq=trace.seed6_equality_trace()
    assert eq['reserved_tail_rows_each_seed']==2025
    assert eq['wire_both_roles_without_coins_or_seed']==32630
    assert eq['wire_both_roles_with_native_coin_without_seed']==32785
    assert eq['native_frame_count_including_coin']==9
    assert eq['native_frame_header_bytes']==9
    assert eq['Fp3_multiplications_each_role']==6751
    assert eq['Fp3_by_Fp_multiplications_each_role']==2025
    assert eq['Fp3_additions_role0']==8100
    assert eq['Fp3_subtractions_role0']==1352
    assert max(eq['extra_owned_heap_phase_bytes_each_role'].values())==64800
    assert eq['logical_original_seed_reads_bytes_each_role']==113424
    assert eq['both_corrections_fixed_before_coin_callback']
    assert eq['peer_commitment_fixed_before_own_opening']
    assert not eq['global_F_Rand_or_seal_credit']


def test_role_separated_cggm_split_work_and_retained_state():
    cggm=trace.seed6_cggm_trace()
    assert cggm['H_calls_both_passes']=={'sender':707_786_100,'receiver':707_761_800}
    assert cggm['c_payload_bytes']==307_800 and cggm['z_payload_bytes']==16_200
    assert cggm['retained_private_heap_bytes']=={'sender':32_400,'receiver':329_400}
    assert cggm['first_pass_temporary_heap_bytes']=={'sender':456,'receiver':912}
    assert cggm['split_Fp3_multiplications']=={'sender':353_897_100,'receiver':353_898_450}
    assert cggm['independent_c0_rng_bytes']==129_600
    assert cggm['seed_and_guard_state_retained_through_F_EQ']
    assert not cggm['global_F_Rand_transport_and_burn_credit']
    assert trace.seed6_guard_trace()['cGGM_producer_before_after_guard_connected']
    assert trace.seed6_equality_trace()['guard_cGGM_to_equality_connected']
    assert trace.seed6_cggm_trace(1,1)['H_calls_both_passes']=={'sender':0,'receiver':0}


def test_native_coin_stream_independent_python_vectors_and_accounting():
    import hashlib
    prefix=(b'VOLTA-C71-DORY-COIN-v1'+b'/coefficients/'+bytes([1])*32+
            bytes([2])*32+bytes([0])+bytes([3])*32+(4).to_bytes(8,'little')+bytes([4])*32)
    tape=hashlib.shake_256(prefix).digest(4*192)
    expected=[
        [7834151124423964235,13031131941374409903,5681944031133750938],
        [10799003285637748551,2284425053434151683,5053289842844629254],
        [521325176319418978,2348289769777282647,13570224334304954887],
        [7349065728333141785,3639344013350648656,7378902005202314930]]
    assert [[int.from_bytes(tape[row*192+limb*64:row*192+limb*64+8],'little')
             for limb in range(3)] for row in range(4)]==expected
    coin=trace.seed6_coin_trace()
    assert coin['SHAKE_absorbed_bytes_each_role']==len(prefix)==173
    assert coin['SHAKE_squeezed_bytes_each_role']==67_947_724_800
    assert coin['wire_with_three_reserved_headers_bytes']==155
    assert coin['wire_already_in_bootstrap_screen']
    assert coin['coefficient_storage_heap_bytes']==0
    assert not coin['full_FS_seal_transport_burn_credit']
    assert trace.seed6_coin_trace(675)['SHAKE_squeezed_bytes_each_role']==129600
    assert trace.seed6_coin_trace(675,9)['wire_with_three_reserved_headers_bytes']==155
    assert trace.seed6_cggm_trace()['receiver_ordered_sibling_bit_tests']==25650


def test_accepted_expansion_capacity_state_and_reference_cost():
    expansion=trace.seed6_expansion_trace()
    assert expansion['capacity_base_rows']==70_778_880
    assert expansion['retained_heap_bytes']=={'sender':32400,'receiver':351000}
    assert expansion['conversion_extra_prefix_heap_bytes_receiver']==21600
    assert expansion['conversion_Fp3_additions_sender']==1350
    assert expansion['conversion_Fp3_additions_receiver']==13500
    assert expansion['global_accumulator_prefix_for_all_preceding_blocks']
    assert expansion['H_calls_per_successful_row_sender']==198
    assert expansion['EAGen_SHAKE_calls_per_successful_row_each_role']==22
    assert expansion['EA_sampler_heap_bytes_upper']==409
    assert expansion['H_codec_heap_with_EA_terms_bytes']==274
    assert not expansion['EA_public_seed_agreement_credit']
    assert not expansion['batch_trie_or_canonical_cost_credit']
    assert expansion['local_EA_seed_from_verified_committed_openings']
    assert not expansion['caller_chosen_EA_seed']
    reduced=trace.seed6_expansion_trace(1,4,2)
    assert reduced['capacity_base_rows']==3
    assert reduced['retained_heap_bytes']=={'sender':48,'receiver':160}
    assert 3*(reduced['H_calls_per_successful_row_sender']+
              reduced['EAGen_SHAKE_calls_per_successful_row_each_role'])==30


def test_accepted_ea_seed_python_vector_and_conditional_accounting():
    import hashlib
    from fractions import Fraction
    message=(b'VOLTA-C71-Seed6-equality-v1'+b'/accepted-EA/'+
             bytes([1])*32+bytes([2])*56+bytes([3])*56)
    assert hashlib.shake_256(message).hexdigest(32)=='eeef3cfe102609c57c32479bb08b83107582bf3e75b4996b465d02c135e7bc64'
    equality=trace.seed6_equality_trace()
    assert equality['accepted_EA_seed_SHAKE_absorbed_bytes_each_role']==len(message)==184
    assert equality['accepted_EA_seed_SHAKE_squeezed_bytes_each_role']==32
    assert equality['accepted_EA_seed_extra_rng_and_wire_bytes']==0
    assert Fraction(equality['accepted_EA_seed_ROM_error_upper_conditional'])<Fraction(1,1<<108)
    assert not equality['accepted_EA_seed_compositional_or_Lean_credit']


def test_one_channel_setup_wire_and_added_payload():
    setup=trace.seed6_setup_trace()
    assert setup['wire_bytes_both_directions']==61_841_366
    assert setup['guard_split_wire_bytes_both_directions']==432_239
    assert setup['added_wire_vs_equality_only_transport']==45
    assert setup['guard_correction_frame_heap_temporary_bytes']==108000
    assert setup['private_path_rng_bytes_receiver']==5400
    assert setup['returned_Audit_heap_bytes_each_role']==896
    assert setup['journal_capacity_BLAKE3_absorbed_bytes_each_role']==201
    assert setup['journal_install_and_setup_disk_bytes_each_role']==161
    assert setup['journal_model_heap_temporary_bytes']==104
    assert setup['journal_setup_record_syncs_each_role']==1
    assert setup['setup_burn_before_rng_and_live_owner_borrow']
    assert setup['per_attempt_burn_bounded_stream_and_terminal_stop']
    assert setup['successful_attempt_disk_bytes_each_role']==114
    assert setup['successful_attempt_syncs_each_role']==2
    assert setup['three_accepted_attempts_install_setup_total_disk_bytes_each_role']==503
    assert setup['attempt_stream_extra_heap_besides_generated_batch_bytes']==0
    assert setup['attempt_stream_generated_batch_heap_upper']=={'sender':98304,'receiver':131072}
    assert setup['returned_Audit_and_owner_slot_retained_across_attempts']
    assert setup['journal_experimental_record_kind']==5
    assert setup['public_role_pools_own_lifetime_and_use_OS_rng']
    assert not setup['public_reference_is_production_or_GPU_fallback']
    assert setup['guard_uses_shared_reexported_Fp3_algebra']
    assert not setup['per_attempt_pool_and_acceptance_connected']
    reduced=trace.seed6_setup_trace(2,4,2)
    assert (reduced['main_seed_rows'],reduced['inverse_seed_rows'])==(25,6)
    assert reduced['capacity_base_rows']==6
    assert reduced['wire_bytes_both_directions']==390742
    assert reduced['post_seed_frames']==16
    assert not setup['durable_burn_or_authenticated_transport_credit']


def test_native_batch_trie_payload_and_source_bounds():
    batch=trace.seed6_batch_trace()
    assert batch['sorted_term_heap_capacity_bytes']==1_081_344
    assert batch['named_heap_peak_bytes']=={'sender':1_179_746,'receiver':1_212_514}
    assert batch['union_trie_H_upper_each_role']==625722
    assert batch['union_trie_H_upper_each_role']<trace.trie_nodes(4096)
    caps=trace.report()['liveness_caps']
    envelope=sum(caps[name] for name in ('prover_raw_batch_bytes','two_aligned_public_term_arrays_bytes','two_sparse_Fp3_frontiers_bytes_per_role','public_u32_histogram_bytes'))
    assert batch['named_heap_peak_bytes']['receiver']+batch['named_recursive_value_slot_bytes']<envelope
    assert batch['generation_never_crosses_burned_interval']
    assert not batch['full_reservation_materialized']
    assert not batch['complete_physical_peak']
    assert trace.seed6_batch_trace(6,2,4,2)['public_EAGen_SHAKE_calls_each_role']==24
    response=trace.response_trace(0,0,12)
    assert response['receiver_PuncAcc_Fp3_additions_upper']==39*11*12
    assert response['sender_global_prefix_Fp3_subtractions_upper']==132


def test_consuming_tail_reservation_preserves_prefix_capacity():
    r=trace.seed6_tail_reservation_trace()
    assert (r['prefix_rows'],r['tail_rows'])==(15528,2025)
    assert r['prover']['named_vec_capacity_peak_bytes']==626544
    assert r['verifier']['named_vec_capacity_peak_bytes']==469872
    for role in ('prover','verifier'):
        x=r[role]
        assert x['destination_vec_capacity_bytes']==x['source_vec_capacity_bytes']+x['copied_payload_bytes']
        assert x['logical_explicit_erasure_write_bytes']==x['copied_payload_bytes']
    assert r['verifier']['duplicated_fixed_secret_bytes']==24
    assert trace.seed6_equality_trace()['each_consumer_seed_rows_exact']==2025
