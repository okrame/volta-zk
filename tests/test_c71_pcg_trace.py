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
    assert setup['internal_cGGM_H_evaluations_lower_per_role_if_two_full_traversals'] == 707_787_450
    assert setup['H_to_AES_calls'] is None and setup['field_operations_complete'] is None
    assert setup['Fp6_to_Fp3_compressed_elements_per_role'] == 17_554
    assert setup['Fp6_to_Fp3_linear_Fp3_multiplications_per_role'] == 35_108
    assert setup['Fp6_to_Fp3_linear_Fp3_additions_per_role'] == 17_554
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
    assert setup['main']['rows'] == 15_528
    assert setup['roleswap']['rows'] == 2_025
    assert not setup['main']['physical_peak_credit']
    assert not setup['roleswap']['OT_guard_roleswap_composition_credit']
