#!/usr/bin/env python3
"""Bounded address plan; no GPU allocation or native prover admission."""
import json
import c71_response_trace as response
import c71_whir_trace as whir
import c71_pcg_trace as pcg
import c71_getter_trace as getter

ALIGN = 256
MARGIN = response.OPERATIONAL_MARGIN_BYTES
LIMIT = response.ARENA - MARGIN


def aligned(n):
    return (n+ALIGN-1)//ALIGN*ALIGN


def place_events(events, persistent):
    """First-fit offsets; releases require a stream completion fence.

    The output is a plan for one preallocated slab, not cudaMalloc accounting.
    No moving live allocation or releasing a retained predecessor before query.
    """
    live, output, peak, logical_peak = {}, [], 0, 0
    def allocate(key, size):
        nonlocal peak
        if key in live or size < 0: raise ValueError('duplicate or negative allocation')
        size=aligned(size)
        offset=0
        for start,n in sorted(live.values()):
            if offset+size <= start: break
            offset=max(offset,start+n)
        live[key]=(offset,size)
        peak=max(peak,offset+size)
        return (key,offset,size)
    # A reader slot can be fenced/released before a scatter-only commit. Keep
    # it at the tail so its release never moves a persistent root or seed.
    initial=[allocate(key,size) for key,size in sorted(persistent.items(),
        key=lambda x:(x[0]=='reader_hash_slot',-x[1]))]
    for event in events:
        freed=event.get('free',[])
        allocations=event.get('allocate',{})
        before=dict(live)
        inplace=next((k for k in freed if k.startswith('retained:')),None)
        replacement=next((k for k in allocations if k.startswith('retained:')),None)
        for key in freed:
            if key not in live:raise ValueError('release without live owner: '+key)
            del live[key]
        assigned=[]
        if inplace and replacement and 'fold' in event['event']:
            offset,old_size=before[inplace];size=aligned(allocations[replacement])
            if size>old_size:raise ValueError('in-place fold grows allocation')
            live[replacement]=(offset,size)
            assigned.append((replacement,offset,size))
        for key,size in sorted(allocations.items(),key=lambda x:-x[1]):
            if key!=replacement or not assigned:assigned.append(allocate(key,size))
        spans=sorted(live.values())
        assert all(a+n<=b for (a,n),(b,_) in zip(spans,spans[1:]))
        logical_peak=max(logical_peak,sum(n for _,n in spans))
        output.append({'event':event['event'],'allocate':assigned,'free':list(freed),
            'fence_before_release':bool(freed),'live_aligned_bytes':sum(n for _,n in spans),
            'address_end':max((a+n for a,n in spans),default=0)})
    return {'initial_allocations':initial,'events':output,'address_high_water_bytes':peak,'aligned_live_peak_bytes':logical_peak,
        'arena_reserved_bytes':response.ARENA,'operational_margin_required_bytes':MARGIN,
        'unaddressed_tail_bytes':response.ARENA-peak,'fits_with_operational_margin':peak<=LIMIT,
        'device_allocation_measured':False,'native_allocator_connected':False}


def report(ordered_getter=False, reuse_reader_for_commit=False):
    if reuse_reader_for_commit and not ordered_getter:raise ValueError('ordered getter variant required')
    initial_rows=1 << (22 if reuse_reader_for_commit else 21)
    pcs={35:whir.trace(35),34:whir.trace(34,initial_coset_rows=initial_rows)}
    retained=whir.a_s1_retention_schedule(s2_coset_rows=1<<22,
                successor_coset_rows=1<<23, reserve_s1_capacity=True)
    correlations=pcg.report()
    cases=[]
    for old in (0,150,300):
        memory=response.integrated_memory(old,pcs,correlations,retained_A=retained)
        persistent=dict(memory['slots_bytes'],shared_roots=response.shared_roots(old))
        # Each chain runs serially in the same slab; roots and session slots
        # never disappear between chains. Freeing occurs only after a fence.
        chains={'initial_A_commit':[e for e in pcs[34]['events'] if e['event'] in ('commit_data_0','retain_data_0_root')],
            'W_opening':[e for e in pcs[35]['events'] if e['event'] not in ('commit_data_0','retain_data_0_root')],
            'each_A_opening':retained['events']}
        phase_events=[]
        for e in memory['phases']:
            if e['chain']=='response':
                size=e['known_arena_live_bytes']-sum(persistent.values())
                phase_events.extend([{'event':e['event'],'allocate':{'phase:core':size},'free':[]},
                    {'event':e['event']+'_fence_release','allocate':{},'free':['phase:core']}])
        chains['range_and_linear']=phase_events
        if old == 0:
            # Both seeds before their consumers, opposite physical roles. Outputs
            # remain live at this chain's end: outer cGGM/guard is still pending.
            setup=correlations['setup_once_before_all_responses']['native_seed6_real_adapter']
            for main_role, inverse_role in [('prover','verifier'),('verifier','prover')]:
                events=[]
                for label,role in [('main',main_role),('roleswap',inverse_role)]:
                    party=setup[label][role]
                    for phase in ('mr19','cope','check','compression'):
                        nonheap=party.get(phase+'_named_nonheap_bytes',0)
                        if phase in ('mr19','cope'):
                            nonheap=party['MR19_Delta_nonheap_bytes']
                        events += [{'event':label+'_'+phase,'allocate':{
                            'Seed6:phase':party['heap_phase_bytes'][phase]+nonheap+32}},
                            {'event':label+'_'+phase+'_release','free':['Seed6:phase']}]
                    events.append({'event':label+'_retain_until_outer_setup_consumer',
                        'allocate':{'Seed6:'+label:party['heap_phase_bytes']['retained_output']+
                            party['retained_nonheap_secret_bytes']+32}})
                events.append({'event':'freeze_guard_corrections_outer_FS_pending',
                    'allocate':{'Seed6:guard_corrections':setup['path_guard_consumer']['correction_heap_capacity_bytes_each_role'],
                                'Seed6:guard_native_value_state':552}})
                events += [{'event':'guard_prefix_native_hash_object', 'allocate':{'Seed6:hash_object':1920}},
                           {'event':'guard_prefix_hash_release_before_challenge','free':['Seed6:hash_object']}]
                chains['Seed6_'+main_role+'_then_'+inverse_role+'_outer_pending']=events

        if reuse_reader_for_commit:
            chains['initial_A_commit']=[{'event':'scatter_commit_no_reader_fence','free':['reader_hash_slot']}]+chains['initial_A_commit']+[
                {'event':'restore_reader_after_commit_fence','allocate':{'reader_hash_slot':persistent['reader_hash_slot']}}]
        if ordered_getter:
            memory['interpretation']='reference before ordered windows and reader reuse; address_layouts are the selected named liveness plan'
            # One frozen generation's layer cuts, never all historical A.
            cuts=98_380_800
            opening=[]
            opening.append({'event':'build_original_A_cuts','allocate':{'getter:cuts':cuts}})
            for e in chains['each_A_opening']:
                e=dict(e,allocate=dict(e['allocate']),free=list(e['free']))
                if e['event']=='a_open_initial':e['allocate']['getter:ordered_bytes']=1 << 28
                if e['event']=='a_release_initial_open':e['free'].append('getter:ordered_bytes')
                opening.append(e)
                if e['event']=='a_regenerate_and_retain_s1':
                    opening.append({'event':'last_original_A_consumer_fence','free':['getter:cuts']})
            chains['each_A_opening']=opening
            # A range uses the conservative W core size; no extra arena cap.
            # W range/linear and the W PCS chain never retain A cuts/windows.
            a_range=[{'event':'build_range_A_cuts','allocate':{'getter:cuts':cuts}}]
            for e in phase_events:
                if not e['event'].startswith('range_'):continue
                e=dict(e,allocate=dict(e['allocate']),free=list(e['free']))
                if e['allocate']:
                    e['allocate']['getter:ordered_bytes']=1 << 31
                else:e['free'].append('getter:ordered_bytes')
                a_range.append(e)
            a_range.append({'event':'last_range_A_consumer_fence','free':['getter:cuts']})
            chains['ordered_A_range']=a_range
            checkpoint=getter.rms_checkpoint()
            # Serial reuse after P0 and before RNE/range. Source production and
            # circuit/replay scratch remain in their explicitly unverified slots.
            chains['compact_RMS_original_frames']=[
                {'event':'build_RMS_original_cuts','allocate':{'getter:cuts':cuts}},
                {'event':'build_RMS_compact_PYS','allocate':{
                    'RMS:original_PYS':checkpoint['owned_payload_and_metadata_bytes']}},
                {'event':'RMS_statistics_and_original_inputs','allocate':{}},
                {'event':'RMS_last_numeric_getter_consumer_fence','free':['getter:cuts']},
                {'event':'RMS_original_byte_obligation_fence','free':['RMS:original_PYS']}]

        layouts={}
        for name,events in chains.items():
            stripped=[dict(e,allocate={k:v for k,v in e.get('allocate',{}).items() if not k.startswith('shared:')},
                free=[k for k in e.get('free',[]) if not k.startswith('shared:')]) for e in events]
            layouts[name]=place_events(stripped,persistent)
        original_A_passes=[36]*(old//150)+[1024+26+36]
        macs=sum(n*getter.scatter_generation_trace(o)['work']['integer_MACs']
            for n,o in zip(original_A_passes,range(0,old+1,150)))
        tiles=getter.byte_tiles(getter.sources_at(old))
        largest_tile=max(t['rows']*t['cols']*t['width'] for t in tiles)
        cases.append({'old_tokens':old,'memory_with_slots':memory,'address_layouts':layouts,
            'all_chain_layouts_fit_margin':all(p['fits_with_operational_margin'] for p in layouts.values()),
            'original_A_passes_by_generation':original_A_passes,'getter_integer_MACs':macs,
            'four_INT8_learned_matrix_replay_lower_seconds_conditional':
                sum(original_A_passes)*8*4_463_473_459_200/2.2e15,
            'retained_state_logical_read_bytes_per_A':retained['retained_state_logical_read_bytes_total'],
            'native_snapshot_i64_dense_values_lower_bytes':8*getter.getter_trace(old)['unique_words'],
            'ordered_getter_full_DAG_per_tile_fallback':{
                'tile_count':len(tiles),'tile_payload_buffer_cap_bytes':largest_tile,
                'buffer_inside_reader_hash_slot':largest_tile<=memory['slots_bytes']['reader_hash_slot'],
                'full_A_generations_per_ordered_pass':len(tiles),
                'integer_MACs_per_ordered_pass':len(tiles)*getter.scatter_generation_trace(old)['work']['integer_MACs'],
                'four_INT8_lower_seconds_one_ordered_pass_conditional':len(tiles)*8*4_463_473_459_200/2.2e15,
                'decision':'NO_GO_literal_full_DAG_per_tile_under_same_INT8_ceiling',
                'not_a_lower_for_shared_dependency_getters':True},
            'physical_peak_complete':None,'time_upper_complete':None,'admitted':False})
        if ordered_getter:
            for key in ('original_A_passes_by_generation','getter_integer_MACs',
                        'four_INT8_learned_matrix_replay_lower_seconds_conditional',
                        'ordered_getter_full_DAG_per_tile_fallback'):
                del cases[-1][key]
            cases[-1]['work_ledger']='c71_ordered_getter.response_ledger; legacy sourcewise pass counts do not apply'
    return {'credit':False,'deadline_seconds':response.DEADLINE_SECONDS,
        'ordered_getter_windows_included':ordered_getter,
        'reader_slot_reused_during_initial_commit':reuse_reader_for_commit,
        'reader_reuse_requires':'native scatter producer and salted CUDA leaf hashing in consumed coset cells; CPU codec/strided root refinement checked, GPU adapter pending',
        'initial_A_coset_rows':initial_rows,'A_S2_coset_rows':1 << 22, 'A_successor_coset_rows_cap':1 << 23,
        'full_S1_capacity_reserved_through_last_consumer':True,
        'cases':cases,'missing':['CUDA salted in-place hash scratch and complete PCS adapter (CPU strided root check passes)' if reuse_reader_for_commit
            else 'odd-log FFT parity-scatter adapter with identical roots',
            'native ordered getter and producer workspaces (shared cuts traced separately)',
            'native PCS/PCG and global context allocator census',
            'complete phase work before spend; unknown service rates require isolated measurement'],
        'native_workspace_audit':{
            'FFT_square':'in-place values + n*8 twiddles; native launch_five_pass allocates no extra global scratch',
            'FFT_odd':'two square transforms + one in-place merge, no split buffer; CPU DFT checked and sm90 compiled, producer parity scatter not yet integrated',
            'range':'native src/dst and reduction arrays; Gram microbench materialization is component-only',
            'snapshot':'native Snapshot stores Vec<Vec<i64>>; literal lift exceeds arena before byte packing',
            'RMS':'compact original P/S/Y checkpoint uses the range slot serially; native full GKR, Boolean replay and allocator scratch remain open',
            'WHIR':'bounded sourcewise replay matches native D10 bytes and rejects dense fallbacks; canonical accelerated state/workspace not yet wired',
            'PCG':'Seed6 real OT/AES named heap phases and retained opposite-role outputs included; crypto stack, transport, allocator and outer guard/cGGM lifecycle remain open',
            'arena_checker_metadata_bytes':512*24,
            'global_unallocated_margin_required_bytes':1 << 30,
            'remaining_global_for_unverified_residents_after_margin':80_000_000_000-response.W_BYTES-450*response.KV_PER_TOKEN-response.ARENA-(1 << 30)},
        'minimum_H100_benchmark_ready':False}

if __name__=='__main__':print(json.dumps(report(),indent=2))
