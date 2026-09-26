#!/usr/bin/env python3
"""Bounded address plan; no GPU allocation or native prover admission."""
import json
import c71_response_trace as response
import c71_whir_trace as whir
import c71_pcg_trace as pcg
import c71_getter_trace as getter
import c71_gkr_screen as gkr
import c71_exp30_alternatives as exp30

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
            'address_end':max((a+n for a,n in spans),default=0),
            'unverified_requirements':event.get('unknown',[])})
    return {'initial_allocations':initial,'events':output,'address_high_water_bytes':peak,'aligned_live_peak_bytes':logical_peak,
        'arena_reserved_bytes':response.ARENA,'operational_margin_required_bytes':MARGIN,
        'unaddressed_tail_bytes':response.ARENA-peak,'fits_with_operational_margin':peak<=LIMIT,
        'device_allocation_measured':False,'native_allocator_connected':False}


def lookup_events(name, trace):
    """Named requested payloads; caller cuts remain live across this helper.

    Requested descriptor/row payloads join the chain. Proof buffers are
    reserved persistently across chains until the response consumer; actual
    capacities and the native arena adapter remain unverified.
    """
    retained={name+':rows':trace['correlation_rows_requested_bytes'],
              name+':descriptor':trace['descriptor_requested_bytes']}
    cache={name+':query_cache':trace['query_cache_payload_bytes'],
           name+':histogram_cache':trace['histogram_cache_payload_bytes']}
    tree={name+':upper_tree':trace['upper_tree_node_payload_bytes'],
          name+':upper_tree_descriptors':trace['upper_tree_descriptor_requested_bytes'],
          name+':regeneration_scratch':trace['regeneration_scratch_requested_bytes'],
          name+':subtree_stack':trace['subtree_stack_payload_bytes']}
    proof={name+':triples':trace['triples_requested_bytes']}
    return [dict(event=name+'_reserve_rows_and_descriptor',allocate=retained),
            dict(event=name+'_bind_original_frame',allocate={name+':binding_known_payload':trace['binding_payload_bytes_excluding_profile']+130},
                 unknown=['copied profile bytes and allocator capacity']),
            dict(event=name+'_binding_absorbed_fence',free=[name+':binding_known_payload']),
            dict(event=name+'_freeze_original_query_histogram',allocate=cache),
            dict(event=name+'_build_and_prove_cut_tree',allocate=dict(tree,**proof)),
            dict(event=name+'_tree_last_consumer_fence',free=list(tree)),
            dict(event=name+'_original_MAC_endpoint',allocate={name+':Eq_scratch':24*(2*trace['bits']+1)}),
            dict(event=name+'_endpoint_last_consumer_fence',free=[*cache,*retained,name+':triples',name+':Eq_scratch'])]


def report(ordered_getter=False, reuse_reader_for_commit=False, exp30_bmma=False,
           byte_node_contraction=False):
    if reuse_reader_for_commit and not ordered_getter:raise ValueError('ordered getter variant required')
    if byte_node_contraction and not ordered_getter:raise ValueError('ordered getter variant required')
    initial_rows=1 << (22 if reuse_reader_for_commit else 21)
    pcs={35:whir.trace(35),34:whir.trace(34,initial_coset_rows=initial_rows)}
    retained=whir.a_s1_retention_schedule(s2_coset_rows=1<<22,
                successor_coset_rows=1<<23, reserve_s1_capacity=True)
    correlations=pcg.report()
    cases=[]
    for old in (0,150,300):
        memory=response.integrated_memory(old,pcs,correlations,retained_A=retained)
        persistent=dict(memory['slots_bytes'],shared_roots=response.shared_roots(old))
        if ordered_getter:
            persistent.update({name+'_lookup:proof':x['proof_requested_bytes']
                for name,x in response.producer_lookup_trace(old).items()})
        # Each chain runs serially in the same slab; roots and session slots
        # never disappear between chains. Freeing occurs only after a fence.
        chains={'initial_A_commit':[e for e in pcs[34]['events'] if e['event'] in ('commit_data_0','retain_data_0_root')],
            'W_opening':[e for e in pcs[35]['events'] if e['event'] not in ('commit_data_0','retain_data_0_root')],
            'each_A_opening':retained['events']}
        phase_events=[]
        for e in memory['phases']:
            if e['chain']=='response':
                size=e['known_arena_live_bytes']-sum(memory['slots_bytes'].values())-response.shared_roots(old)
                phase_events.extend([{'event':e['event'],'allocate':{'phase:core':size},'free':[]},
                    {'event':e['event']+'_fence_release','allocate':{},'free':['phase:core']}])
        chains['range_and_linear']=phase_events
        if old == 0:
            setup=correlations['setup_once_before_all_responses']['native_seed6_real_adapter']
            for main_role, inverse_role in [('prover','verifier'),('verifier','prover')]:
                events=[]
                for label,role in [('main',main_role),('roleswap',inverse_role)]:
                    party=setup[label][role]
                    for phase in ('mr19','cope','check','compression','seal'):
                        nonheap=party.get(phase+'_named_nonheap_bytes',0)
                        if phase in ('mr19','cope'):
                            nonheap=party['MR19_Delta_nonheap_bytes']
                        events += [{'event':label+'_'+phase,'allocate':{
                            'Seed6:phase':party['heap_phase_bytes'][phase]+nonheap+32}},
                            {'event':label+'_'+phase+'_release','free':['Seed6:phase']}]
                    events.append({'event':label+'_retain_until_outer_setup_consumer',
                        'allocate':{'Seed6:'+label:party['heap_phase_bytes']['retained_output']+
                            party['retained_nonheap_secret_bytes']+32}})
                # Main prefix keeps its old capacity (erased tail slack). The
                # new exact tail stays live independently through the guard.
                reservation=setup['disjoint_tail_reservation'][main_role]
                events.append({'event':'reserve_disjoint_equality_tail_before_guard',
                    'allocate':{'Seed6:main_equality_tail':reservation['new_tail_vec_capacity_bytes']+
                        reservation['duplicated_fixed_secret_bytes']+32}})
                events.append({'event':'freeze_guard_corrections_outer_FS_pending',
                    'allocate':{'Seed6:guard_corrections':setup['path_guard_consumer']['correction_heap_capacity_bytes_each_role'],
                                'Seed6:guard_native_value_state':552}})
                events += [{'event':'guard_prefix_native_hash_object', 'allocate':{'Seed6:hash_object':1920}},
                           {'event':'guard_prefix_hash_release_before_challenge','free':['Seed6:hash_object']}]
                events += [{'event':'guard_sealed_prefix_challenge_before_proof',
                            'allocate':{'Seed6:guard_challenge':setup['path_guard_consumer']['challenge_native_value_slot_bytes']}},
                           {'event':'guard_challenge_temporary_release','free':['Seed6:guard_challenge']}]
                events.append({'event':'split_coin_commit_before_c_then_reuse_for_equality',
                    'allocate':{'Seed6:coin_native_value_slot':setup['coin_tosses']['split']['native_value_and_hash_slot_bytes']}})
                cggm=setup['guard_to_cggm_and_split_consumer']
                tree_role='receiver' if main_role=='prover' else 'sender'
                events.append({'event':'guard_accepted_then_role_separated_cggm',
                    'allocate':{'Seed6:c_wire':cggm['c_payload_bytes'],
                                'Seed6:cggm_private':cggm['retained_private_heap_bytes'][tree_role],
                                'Seed6:cggm_temporary':cggm['first_pass_temporary_heap_bytes'][tree_role],
                                'Seed6:H_codec':cggm['H_codec_heap_bytes'],
                                'Seed6:cggm_native_value_slot':cggm['native_value_and_hash_slot_bytes']}})
                events.append({'event':'cggm_first_pass_temporaries_released',
                               'free':['Seed6:cggm_temporary']})
                events.append({'event':'split_second_pass_original_masks',
                    'allocate':{'Seed6:z_wire':cggm['z_payload_bytes'],
                                'Seed6:split_values':cggm['pending_split_values_heap_bytes_each_role']}})
                events.append({'event':'split_H_codec_released','free':['Seed6:H_codec']})
                equality=setup['two_key_equality_consumer']
                events.append({'event':'reserve_equality_envelope_with_pending_cggm_states',
                    'allocate':{'Seed6:equality_payload_envelope':max(equality['extra_owned_heap_phase_bytes_each_role'].values()),
                                'Seed6:equality_native_value_slot':equality['native_value_state_slot_bytes']}})
                expansion=setup['accepted_pointwise_expansion']
                events.append({'event':'equality_accepted_convert_to_expansion',
                    'allocate':({'Seed6:accepted_beta':expansion['conversion_extra_beta_heap_bytes_receiver']}
                                if tree_role=='receiver' else {})})
                events.append({'event':'accepted_expansion_releases_consumed_setup',
                    'free':['Seed6:'+name for name in ('main','roleswap','main_equality_tail',
                            'guard_corrections','guard_native_value_state','coin_native_value_slot',
                            'c_wire','z_wire','split_values','equality_payload_envelope',
                            'equality_native_value_slot')]})
                events += [{'event':'accepted_pointwise_row_reference',
                    'allocate':{'Seed6:EA_temporary_heap':max(expansion['EA_sampler_heap_bytes_upper'],
                                                            expansion['H_codec_heap_with_EA_terms_bytes']),
                                'Seed6:EA_named_value_scratch':expansion['receiver_on_path_named_value_scratch_bytes']}},
                           {'event':'accepted_pointwise_row_reference_release',
                            'free':['Seed6:EA_temporary_heap','Seed6:EA_named_value_scratch']}]
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
            byte_endpoint=gkr.byte_source_trace(33,16)
            # Serial reuse after P0 and before RNE/range. Source production and
            # circuit/replay scratch remain in their explicitly unverified slots.
            chains['compact_RMS_original_frames']=[
                {'event':'build_RMS_original_cuts','allocate':{'getter:cuts':cuts}},
                {'event':'build_RMS_compact_PYS','allocate':{
                    'RMS:original_PYS':checkpoint['owned_payload_and_metadata_bytes']}},
                {'event':'RMS_statistics_and_original_inputs','allocate':{}},
                {'event':'RMS_last_numeric_getter_consumer_fence','free':['getter:cuts']},
                {'event':'RMS_sourcewise_original_byte_obligation','allocate':{
                    'RMS:byte_LUT':byte_endpoint['lut_capacity_bytes'],
                    'RMS:byte_coefficients':16*256*24,
                    'RMS:byte_prefix_weights':byte_endpoint['max_prefix_weight_payload_bytes']}},
                {'event':'RMS_original_byte_obligation_fence',
                 'free':['RMS:original_PYS','RMS:byte_LUT','RMS:byte_coefficients',
                         'RMS:byte_prefix_weights']}]

            # Maximum layers descend in public order. Drop each checkpoint
            # before allocating the next; the original D getter stays live.
            maximum=response.maximum_source_trace(old)
            events=[{'event':'build_EXP30_original_cuts','allocate':{'getter:cuts':cuts}},
                {'event':'EXP30_maximum_prefix_weights','allocate':{
                    'EXP30:maximum_weights':maximum['source_tree_work']['max_prefix_weight_payload_bytes']}}]
            for layer in maximum['layers']:
                events.append({'event':f"EXP30_maximum_layer_{layer['layer']}",
                    'allocate':{'EXP30:maximum_checkpoint':layer['checkpoint_capacity_bytes']}})
                events.append({'event':f"EXP30_maximum_layer_{layer['layer']}_last_consumer_fence",
                    'free':['EXP30:maximum_checkpoint']})
            events.append({'event':'EXP30_maximum_before_lookup_and_ratio',
                'free':['EXP30:maximum_weights']})
            lookups=response.producer_lookup_trace(old)
            events.extend(lookup_events('EXP30_lookup',lookups['EXP30']))
            prefix = exp30.late_weights(old)
            events.extend([
                {'event':'EXP30_original_ratio_cache', 'allocate':{
                    'EXP30:ratio_original_cache':prefix['original_ratio_cache_bytes']}},
                {'event':'EXP30_pattern_prefix_all_gates', 'allocate':{
                    'EXP30:per_gate_histograms':prefix['raw_histogram_peak_bytes'],
                    'EXP30:packed_replay':prefix['packed_replay_resident_bytes'],
                    'EXP30:pattern_aggregate':prefix['aggregate_histogram_bytes']},
                 'unknown':['public DAG compiler transient, GPU staging, getter complete workspace and allocator; component payload only']},
                {'event':'EXP30_pattern_raw_last_consumer_fence',
                 'free':['EXP30:per_gate_histograms','EXP30:packed_replay']},
                {'event':'EXP30_four_cubics_last_consumer_fence',
                 'free':['EXP30:pattern_aggregate']},
            ])
            if exp30_bmma:
                import c71_exp30_bmma as bm
                # Replace only the unselected consumer's named prefix schedule.
                events=events[:-3]  # Keep the original ratio cache allocation.
                for state in reversed(bm.geometry()[2]):
                    name=f"EXP30_BMMA_layer_{state['depth']}"
                    buffers={name+':'+k:v for k,v in state.items() if k not in ('depth','moment_output_bytes','late_weights_and_flags_bytes')}
                    buffers[name+':packed_replay']=bm.PARALLEL_PLAN_BYTES
                    events.append(dict(event=name+'_producer_consumer_batches',
                        allocate={**buffers,name+':aggregate':24*(256+16)},
                        unknown=['GPU launch, moment weighting, compiler transient and allocator; candidate only']))
                    events.append(dict(event=name+'_last_BMMA_fence',
                        free=[name+':stage_bytes',name+':Eq_bitplanes_bytes',name+':Eq_factor_tables_and_point_bytes',name+':packed_replay'],
                        allocate={name+':moments':state['moment_output_bytes']}))
                    events.append(dict(event=name+'_last_count_consumer_fence',
                        free=[name+':count_bytes',name+':copy_count_bytes'],
                        allocate={name+':late_weights_and_flags':state['late_weights_and_flags_bytes']}))
                    events.append(dict(event=name+'_four_cubics_fence',
                        free=[name+':moments',name+':gate_map_bytes',name+':late_weights_and_flags',name+':aggregate']))
            for name in ('GELU','softcap'):
                chains[name+'_original_lookup']=[
                    dict(event=name+'_build_original_cuts',allocate={'getter:cuts':cuts}),
                    *lookup_events(name+'_lookup',lookups[name]),
                    dict(event=name+'_last_original_consumer_fence',free=['getter:cuts'])]
            endpoint=gkr.byte_source_trace(maximum['row_bits']+maximum['key_bits']+4,16)
            events.append({'event':'EXP30_ratio_original_byte_obligation',
                'allocate':{'EXP30:byte_LUT':endpoint['lut_capacity_bytes'],
                    'EXP30:byte_coefficients':16*256*24,
                    'EXP30:byte_prefix_weights':endpoint['max_prefix_weight_payload_bytes']},
                'unknown':['lookup descriptor/proof/correlations and allocator capacities',
                           'programs/proof/correlations and complete GKR workspace']})
            if byte_node_contraction:
                import c71_byte_tree_contraction as contraction
                events.extend(contraction.arena_events(next(c for c in gkr.ratio_cases() if c['old_tokens']==old)))
            events.append({'event':'EXP30_last_original_byte_consumer_fence',
                'free':['EXP30:ratio_original_cache','getter:cuts','EXP30:byte_LUT','EXP30:byte_coefficients',
                        'EXP30:byte_prefix_weights']})
            chains['EXP30_maximum_original_bytes']=events

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
        'candidate_byte_node_contraction_included':byte_node_contraction,
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
            'RMS':'original P/S/Y plus byte LUT/coefficients included; bounded cell/index/replay checked on reduced proofs; public circuits, proof/correlation capacities, allocator and full getter workspace remain to join',
            'WHIR':'bounded sourcewise replay matches native D10 bytes and rejects dense fallbacks; canonical accelerated state/workspace not yet wired',
            'PCG':'Seed6 OT/AES, guard, role-separated cGGM, split/F_EQ and two native coin envelopes included conservatively; full FS, crypto stack, transport, allocator and seal/burn lifecycle remain open',
            'arena_checker_metadata_bytes':512*24,
            'global_unallocated_margin_required_bytes':1 << 30,
            'remaining_global_for_unverified_residents_after_margin':80_000_000_000-response.W_BYTES-450*response.KV_PER_TOKEN-response.ARENA-(1 << 30)},
        'minimum_H100_benchmark_ready':False}

if __name__=='__main__':print(json.dumps(report(),indent=2))
