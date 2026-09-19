"""End-to-end time partition must not hide proof replay as inference."""
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_response_trace as trace


def test_timing_partition_charges_replay_to_proof_and_rejects_missing_phase():
    upper=dict.fromkeys(trace.BUDGET_SECONDS,0.0)
    upper.update(inference=3.0,proof_getter_replay=11.0,proof_initial_commit_A=7.0)
    assert trace.partition_times(upper)=={'T_inference':3.,'T_proof_only':18.,'T_response_total':21.}
    upper['proof_PCG_MAC']=None
    assert trace.partition_times(upper)=={'T_inference':3.,'T_proof_only':None,'T_response_total':None}
    del upper['proof_PCG_MAC']
    with pytest.raises(ValueError,match='every'):trace.partition_times(upper)


def test_composed_trace_keeps_current_old_sources_memory_and_unknowns():
    r=trace.report()
    assert r['complete_time_upper'] is None
    for c in r['cases']:
        assert sum(c['budget_seconds'].values())==65
        assert c['times_seconds']==dict(T_inference=None,T_proof_only=None,T_response_total=None)
        assert c['known_source_visits_before_sumcheck']['A_by_generation']==[73]*(c['old_tokens']//150)+[611]
        assert c['proof_getter_replay_work']['native_provider_inference_replays_deducted']==0
        producer=c['producer_GKR_partial_work']
        assert producer['relations']==['RMS',f'EXP30_O{c["old_tokens"]}']
        assert producer['phase_budget_seconds']==.8
        assert not producer['canonical_calibrated_profile'] and not producer['complete_work']
        assert producer['branchless_Boolean_fold_masks']>0
        assert producer['source_level_scalar_getter_work_known_components'][
            'original_frame_callbacks']>0
        field=producer['source_level_field_work_known_components']
        assert field['cell_fold_multiplications']>0
        assert field['factored_coefficient_Fp3_mul']>377_813_615_257_794
        assert c['phase_throughput_conditions_partial']['proof_producer_relations']==producer[
            'partial_admission_throughput_targets']
        assert c['memory']['known_global_reserved_bytes']==68_242_645_504
        assert c['memory']['physical_allocated_peak_complete'] is None
        assert c['memory']['known_peak_event']['chain']==f'A{c["old_tokens"]//150}'
        assert c['memory']['known_peak_with_proposed_slots_bytes']<trace.ARENA
        retained=c['retained_A_alternative']
        assert retained['original_A_passes_by_generation']==[36]*(c['old_tokens']//150)+[574]
        assert retained['original_A_passes_saved']==60*(1+c['old_tokens']//150)
        events=retained['memory']['phases']
        assert sum(e['event']=='a_base_open_s11_and_masks' for e in events)==1+c['old_tokens']//150
        assert not any(e['chain'].startswith('A') and e['event']=='base_case_open_all' for e in events)
        assert retained['memory']['known_peak_with_proposed_slots_bytes']<trace.ARENA
        assert c['fresh_session_setup_charged_to_proof_PCG_MAC']==(c['old_tokens']==0)
    assert not r['cases'][-1]['retained_A_alternative']['deadline_excluded_under_same_conditions']
    assert r['online_verifier_challenge_round_trips']==0
