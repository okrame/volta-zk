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
        assert sum(c['budget_seconds'].values())==50
        assert c['times_seconds']==dict(T_inference=None,T_proof_only=None,T_response_total=None)
        assert c['known_source_visits_before_sumcheck']['A_by_generation']==[73]*(c['old_tokens']//150)+[611]
        assert c['proof_getter_replay_work']['native_provider_inference_replays_deducted']==0
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
    assert r['cases'][-1]['retained_A_alternative']['fifty_second_goal_excluded_under_same_conditions']
    assert r['online_verifier_challenge_round_trips']==0
