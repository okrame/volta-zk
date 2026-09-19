#!/usr/bin/env python3
"""Shared-DAG windows over original A byte addresses; metadata and tiny executor.

Full-shape fused producers within a window give a finite conservative schedule.
It is not a native Gemma numerical implementation or measured HBM traffic.
"""
from collections import Counter
import hashlib
import json
import c71_getter_trace as getter

WINDOW_BYTES = 64 << 20


def producer_for_source(source, by_op):
    recipe=source['recipe'].split('/')
    kind=recipe[0]
    if kind in ('raw','output','rms_stat','histogram','slack'):
        layer=None if recipe[1]=='global' else int(recipe[1]); op=recipe[2]
    elif kind=='attention':
        layer=int(recipe[1]);op={'R':'qk_matmul','X':'qk_matmul','Pi':'softmax','Y':'pv_matmul'}[recipe[2]]
    elif kind=='softmax':layer=int(recipe[1]);op='softmax'
    else:raise ValueError('unmapped original source recipe '+source['recipe'])
    return by_op[layer,op]


def permuted_index(index, dimension, suffix_bits, bottom_bits=0):
    if bottom_bits:
        return (permuted_index(index >> bottom_bits,dimension-bottom_bits,suffix_bits) << bottom_bits) | (index & ((1 << bottom_bits)-1))
    return ((index & ((1 << suffix_bits)-1)) << (dimension-suffix_bits)) | (index >> suffix_bits)


def intersection_count(begin, end, first, size, dimension, suffix_bits, bottom_bits=0):
    """Exact cardinality of a dyadic interval against one bit-rotated window."""
    if bottom_bits:
        block=1 << bottom_bits
        if size < block:raise ValueError('window smaller than preserved subtree block')
        def count(x):
            q,r=divmod(x,block)
            return block*intersection_count(0,q,first//block,size//block,dimension-bottom_bits,suffix_bits) + r*(first//block <= permuted_index(q,dimension-bottom_bits,suffix_bits) < (first+size)//block)
        return count(end)-count(begin)
    prefix=1 << (dimension-suffix_bits)
    period=1 << suffix_bits
    if size <= prefix:
        suffix=first//prefix; start=(first%prefix)*period+suffix
        lo=max(0,(begin-start+period-1)//period)
        hi=min(size,(end-start+period-1)//period)
        return max(0,hi-lo)
    width=size//prefix; low=first//prefix
    def count(x):return (x//period)*width+min(width,max(0,x%period-low))
    return count(end)-count(begin)


def compile_windows(old, window_bytes=WINDOW_BYTES, suffix_bits=0, bottom_bits=0):
    if window_bytes<=0 or window_bytes&(window_bytes-1) or window_bytes>1 << 34:
        raise ValueError('power-of-two window inside D34 required')
    if not 0<=bottom_bits<=34 or not 0<=suffix_bits<=34-bottom_bits:raise ValueError('invalid suffix gather')
    sources=getter.sources_at(old);tiles=getter.byte_tiles(sources)
    events=getter.scatter_generation_trace(old)['events']
    by_op={(e['layer'],e['operation']):e['node'] for e in events}
    owners=[producer_for_source(s,by_op) for s in sources]
    checkpoints={d for e in events for d in e['dependencies'] if events[d]['layer']!=e['layer']}
    assert all(events[d]['operation'] in ('embedding_scale','layer_scalar_mul') for d in checkpoints)
    windows=[]
    for first in range(0,1 << 34,window_bytes):
        segments=[]
        for tile_index,t in enumerate(tiles):
            begin=t['offset'];end=begin+t['rows']*t['cols']*t['width']
            count=intersection_count(begin,end,first,window_bytes,34,suffix_bits,bottom_bits)
            if count:segments.append({'tile':tile_index,'live_byte_count':count,'producer':owners[t['source']],
                'from_checkpoint':owners[t['source']] in checkpoints and sources[t['source']]['recipe'].startswith('output/')})
        windows.append(segments)
    return events,checkpoints,windows,sources,tiles


def required_nodes(events, targets, checkpoints):
    needed=set()
    def visit(n, force=False):
        if (n in checkpoints and not force) or n in needed:return
        needed.add(n)
        for d in events[n]['dependencies']:visit(d)
    for n in targets:visit(n,True)
    return sorted(needed)


def window_trace(events, targets, checkpoints):
    order=required_nodes(events,targets,checkpoints)
    uses=Counter(d for n in order for d in events[n]['dependencies'] if d not in checkpoints)
    live={};peak=0;work=Counter();steps=[]
    for n in order:
        e=events[n];size=e['output_bytes'];live[n]=size
        # Histogram and raw tiles are flushed into the current byte window.
        allocated=sum(live.values())+e['raw_tile_bytes']+65535*4
        peak=max(peak,allocated)
        work.update(e['work'])
        freed=[]
        for d in e['dependencies']:
            if d in checkpoints:continue
            uses[d]-=1
            if not uses[d]:freed.append(d);del live[d]
        if not uses[n]:freed.append(n);del live[n]
        steps.append({'node':n,'released_after_emit':freed,'live_bytes':allocated})
    assert not live
    return {'nodes':order,'steps':steps,'producer_workspace_named_peak_bytes':peak,'work':dict(work),
        'checkpoint_read_bytes':sum(events[d]['output_bytes'] for n in order for d in events[n]['dependencies'] if d in checkpoints)}


def trace(old, window_bytes=WINDOW_BYTES, suffix_bits=0, bottom_bits=0):
    events,checkpoints,windows,sources,tiles=compile_windows(old,window_bytes,suffix_bits,bottom_bits)
    counts=Counter();work=Counter();rows=[]
    peak=0
    for i,segments in enumerate(windows):
        targets={x['producer'] for x in segments if not x['from_checkpoint']}
        for segment in segments:
            if segment['producer'] in targets:segment['from_checkpoint']=False
        row=window_trace(events,targets,checkpoints)
        counts.update(row['nodes']);work.update(row['work']);peak=max(peak,row['producer_workspace_named_peak_bytes'])
        rows.append({'window':i,'first_byte':i*window_bytes,'segments':segments,**row})
    byte_count=sum(s['rows']*s['cols']*s['width'] for s in sources)
    return {'credit':False,'old_tokens':old,'window_bytes':window_bytes,'suffix_bits':suffix_bits,'bottom_bits':bottom_bits,'windows':rows,
        'source_bytes':byte_count,'sources':len(sources),'tiles':len(tiles),
        'checkpoint_nodes':sorted(checkpoints),
        'checkpoint_bytes':sum(events[n]['output_bytes'] for n in checkpoints),
        'checkpoint_build_work':getter.scatter_generation_trace(old)['work'],
        'checkpoint_build_is_proof_only_and_not_free_inference':True,
        'producer_evaluations':sum(counts.values()),'evaluations_by_node':dict(sorted(counts.items())),
        'window_producer_peak_bytes':peak,'work_per_ordered_pass':dict(work),
        'ordered_window_store_bytes':byte_count,'ordered_window_consumer_read_bytes':1 << 34,
        'public_zero_window_bytes':(1 << 34)-byte_count,
        'checkpoint_read_bytes':sum(r['checkpoint_read_bytes'] for r in rows)
            +2*sum(s['live_byte_count'] for w in windows for s in w if s['from_checkpoint']),
        'checkpoint_direct_emit_policy':'one i16 fetch per requested byte, without sibling reuse credit',
        'window_zero_initialization_bytes':1 << 34,
        'virtual_byte_windows_and_producer_instances_exact_for_this_schedule':True,
        'arithmetic_expansion_complete':False,'HBM_transactions_exact':None,
        'legacy_rectangular_KV_read_counts_are_upper_not_actual_future_reads':True,
        'native_workspace_complete':None,'native_numerical_getter_implemented':False,
        'fusion':'emit raw, rounded output, byte siblings and histogram into original window offsets before last-consumer release',
        'unresolved':['native original-byte equivalence for every producer',
            'all RMS/ratio/LUT arithmetic and kernel scratch',
            'native range gather and consumer binding','physical cache/transaction behavior'],
        'no_snapshot_or_full_A_allocated':True}


def execute_window(nodes, targets, checkpoints, evaluate, emit, snapshot, expected_snapshot):
    """Small executable shared-DAG lifecycle; callbacks are trusted internals.

    `emit` must consume the requested values before they can be released.
    The snapshot/checkpoint provider is fixed by Prepare, never proof input.
    """
    if snapshot != expected_snapshot or len(snapshot)!=3 or snapshot[0] not in (0,150,300):
        raise ValueError('original snapshot/root/Gamma mismatch')
    order=required_nodes(nodes,targets,set(checkpoints))
    uses=Counter(d for n in order for d in nodes[n]['dependencies'] if d not in checkpoints)
    live={}
    for n in order:
        inputs=[checkpoints[d] if d in checkpoints else live[d] for d in nodes[n]['dependencies']]
        live[n]=evaluate(n,inputs)
        if n in targets:emit(n,live[n])
        for d in nodes[n]['dependencies']:
            if d in checkpoints:continue
            uses[d]-=1
            if not uses[d]:del live[d]
        if not uses[n]:del live[n]
    assert not live


def range_orders():
    """Native MSB folds: [tail][old prefix][new Gram window][subtree]."""
    import c71_streaming_screen as screen
    result=[{'phase':'initial_tree','suffix_bits':0,'bottom_bits':0}]
    for layer in screen.gram_window_budget(34,10,1,24)['layers']:
        m=layer['child_bits'];p=0
        for width in layer['window_bits']+[0]:
            result.append({'phase':f'child_{m}_folded_{p}_Gram_{width}',
                'child_bits':m,'folded_bits':p,'Gram_bits':width,
                'suffix_bits':m-p-width,'bottom_bits':34-m})
            p+=width
    assert len(result)==26
    return result


def summarize_trace(t):
    events=getter.scatter_generation_trace(t['old_tokens'])['events']
    # Mathematical causal dot products, separate from rectangular launch work.
    counts=t['evaluations_by_node'];old=t['old_tokens']
    pairs=150*old+150*151//2
    attention=sum(counts.get(e['node'],0)*32*pairs*(512 if e['layer']%6==5 else 256)
        for e in events if e['operation'] in ('qk_matmul','pv_matmul'))
    learned=sum(counts.get(e['node'],0)*e['work'].get('integer_MACs',0)
        for e in events if e['operation'] not in ('qk_matmul','pv_matmul'))
    # Prefix KV is reread per query head; no assumed GQA/cache reuse.
    old_kv=sum(counts.get(e['node'],0)*2*32*150*old*(512 if e['layer']%6==5 else 256)
        for e in events if e['operation'] in ('qk_matmul','pv_matmul'))
    cohorts=getter.base.gemma_weight_cohorts(getter.base.pinned_private_tensors())
    matrix_bytes={(c['layer'],c['operation']):2*c['columns']*c['inner'] for c in cohorts if c['kind']=='matrix'}
    # These learned matrices are disjoint tensor regions. Grant 256 MiB of
    # arbitrary cache carry per window, independent of actual cache contents.
    compulsory=sum(max(0,sum(matrix_bytes.get((events[n]['layer'],events[n]['operation']),0)
        for n in w['nodes'])-(256 << 20)) for w in t['windows'])
    result={k:v for k,v in t.items() if k not in ('windows','checkpoint_build_work','unresolved')}
    result.update(trace_sha256=hashlib.sha256(json.dumps(t,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
        learned_matrix_MACs=learned,causal_attention_MACs=attention,
        learned_matrix_HBM_lower_bytes_conditional_uncompressed_cache_256MiB=compulsory,
        past_KV_operand_requested_bytes_no_GQA_reuse=old_kv,
        current_KV_operand_requested_bytes_no_GQA_reuse=2*attention-old_kv,
        recomputed_producer_instances=sum(max(0,n-1) for n in counts.values()))
    return result


def report_case(old):
    """Canonical metadata only; never retain all window traces simultaneously."""
    cache={};passes=[];work=Counter();evaluations=Counter()
    for order in range_orders():
        key=(order['suffix_bits'],order['bottom_bits'])
        if key not in cache:cache[key]=summarize_trace(trace(old,1 << 31,*key))
        row=cache[key];work.update(row['work_per_ordered_pass']);evaluations.update(row['evaluations_by_node'])
        passes.append(dict(order,trace_sha256=row['trace_sha256']))
    query=summarize_trace(trace(old,1 << 28))
    return {'credit':False,'old_tokens':old,'range_passes':passes,
        'range_distinct_window_traces':list(cache.values()),'range_work':dict(work),
        'range_producer_evaluations':sum(evaluations.values()),
        'range_evaluations_by_node':dict(sorted(evaluations.items())),
        'range_learned_matrix_MACs':sum(cache[(x['suffix_bits'],x['bottom_bits'])]['learned_matrix_MACs'] for x in passes),
        'range_causal_attention_MACs':sum(cache[(x['suffix_bits'],x['bottom_bits'])]['causal_attention_MACs'] for x in passes),
        'range_past_KV_operand_requested_bytes_no_GQA_reuse':sum(cache[(x['suffix_bits'],x['bottom_bits'])]['past_KV_operand_requested_bytes_no_GQA_reuse'] for x in passes),
        'range_current_KV_operand_requested_bytes_no_GQA_reuse':sum(cache[(x['suffix_bits'],x['bottom_bits'])]['current_KV_operand_requested_bytes_no_GQA_reuse'] for x in passes),
        'initial_A_query':query,'checkpoint_build':getter.scatter_generation_trace(old)['work'],
        'checkpoint_bytes':query['checkpoint_bytes'],
        'scope':'ordered original-A range and initial query; not a complete response work trace',
        'linear_fusion_required':'S1 commit/OOD/initial sumcheck/regeneration must scatter linear original-A contributions; native adapter pending',
        'physical_peak_complete':None,'time_upper_complete':None}


def response_ledger(cases, commit_replays=1024):
    """Named getter schedule + existing phase gates, without invented rates."""
    import c71_response_trace as response
    import c71_streaming_screen as screen
    import c71_pcg_trace as pcg
    import c71_whir_trace as whir
    if commit_replays not in (512,1024):raise ValueError('unsupported initial commit geometry')
    dominant=screen.dominant_cost_screen(screen.base.b12_pcs_binding_assessment())
    correlations=pcg.report();baseline=response.report();out=[]
    matrix_macs=dominant['matrix_MACs_per_full_A_generation']
    weight_bytes=sum(2*c['columns']*c['inner'] for c in getter.base.gemma_weight_cohorts(
        getter.base.pinned_private_tensors()) if c['kind']=='matrix')
    for slot,c in enumerate(cases):
        assert c['old_tokens']==150*slot
        # Per original A: 35 non-query S1 scans, two linear scans, one cut
        # build before query. Current A also has the selected commit scans and a
        # second cut build for range. Producer GKR is a separate unknown.
        sourcewise=[38]*slot+[commit_replays+39]
        learned=sum(sourcewise)*matrix_macs+c['range_learned_matrix_MACs']
        learned+=sum(x['initial_A_query']['learned_matrix_MACs'] for x in cases[:slot+1])
        generations=[getter.scatter_generation_trace(o) for o in range(0,c['old_tokens']+1,150)]
        full_causal=[sum(32*(150*o+150*151//2)*(512 if e['layer']%6==5 else 256)
            for e in generation['events'] if e['operation'] in ('qk_matmul','pv_matmul'))
            for o,generation in zip(range(0,c['old_tokens']+1,150),generations)]
        attention=sum(n*v for n,v in zip(sourcewise,full_causal))+c['range_causal_attention_MACs']
        attention+=sum(x['initial_A_query']['causal_attention_MACs'] for x in cases[:slot+1])
        W_request_key='W_operand_read_bytes_tile16x256_upper'
        W_requested=sum(n*g['work'][W_request_key] for n,g in zip(sourcewise,generations))
        W_requested+=c['range_work'][W_request_key]+sum(x['initial_A_query']['work_per_ordered_pass'][W_request_key] for x in cases[:slot+1])
        range_by_hash={x['trace_sha256']:x for x in c['range_distinct_window_traces']}
        hbm_key='learned_matrix_HBM_lower_bytes_conditional_uncompressed_cache_256MiB'
        hbm=sum(sourcewise)*(weight_bytes-(256 << 20))
        hbm+=sum(range_by_hash[x['trace_sha256']][hbm_key] for x in c['range_passes'])
        hbm+=sum(x['initial_A_query'][hbm_key] for x in cases[:slot+1])
        phase=dict(baseline['cases'][slot]['phase_throughput_conditions_partial'])
        budget=dict(response.BUDGET_SECONDS)
        if commit_replays==512:
            # Admission targets only. The previous 14s getter target already
            # fails the compulsory-read lower; no measured floor is implied.
            budget.update(inference=1.5,proof_getter_replay=17.,proof_producer_relations=.8,
                proof_range_W_A=17.9,proof_linear_W_A_history=.8,proof_WHIR_remaining=2.)
            assert abs(sum(budget.values())-65)<1e-9
            for name,demands in phase.items():
                phase[name]={k:(v*response.BUDGET_SECONDS[name]/budget[name] if 'per_second' in k else v)
                    for k,v in demands.items()}
        phase['proof_getter_replay']={'learned_matrix_MACs_per_second':learned/budget['proof_getter_replay'],
            'four_INT8_operations_per_second':8*learned/budget['proof_getter_replay'],
            'conditional_compulsory_W_bytes_per_second':hbm/budget['proof_getter_replay']}
        # Exact mathematical FFT work for the proposed odd-log decomposition;
        # no transfer of the 2^22 binary's instruction lower to a missing kernel.
        fft_log=22 if commit_replays==512 else 21
        fft_butterflies=commit_replays*128*(1 << (fft_log-1))*fft_log
        phase['proof_initial_commit_A']={'FFT_butterflies_per_second':fft_butterflies/7,
            'excludes_scatter_hash_and_native_adapter':True}
        pcg_demand=phase['proof_PCG_MAC']
        setup=correlations['setup_once_before_all_responses']['internal_cGGM_H_evaluations_lower_per_role_if_two_full_traversals'] if slot==0 else 0
        pcg_demand['selected_response_H_upper_plus_setup_lower_per_second']=(
            correlations['responses'][slot]['union_trie_H_evaluations_upper_per_role']+setup)/2
        compute_lower=8*learned/2.2e15;bandwidth_lower=hbm/3.35e12
        d=dominant['cases'][slot]
        joint=max(compute_lower,bandwidth_lower)+d['range_W_A_named_merge_issue_lower_seconds']+d['first_oracle_opening_issue_lower_seconds']
        fft_bandwidth=(commit_replays*(10 if commit_replays==512 else 12)*
            ((128*8 << fft_log)-(256 << 20)))/3.35e12
        fft_compute=d['commit_A_FFT_issue_lower_seconds'] if commit_replays==512 else None
        fft_lower=max(fft_bandwidth,fft_compute or 0)
        hash_work=whir.salted_hash_work(whir.oracle_geometry(34)[0]['height'],128)
        # Separate leaf pass after the complete coset FFT: charge the compulsory
        # read only. Tree/salt compute and digest writes are counted but not yet
        # converted to a lower; no extra GPU scratch credit from the CPU check.
        hash_read_lower=(hash_work['leaf_field_read_bytes']-commit_replays*(256 << 20))/3.35e12
        phase['proof_initial_commit_A'].update(
            salted_leaf_bytes_per_second=hash_work['leaf_field_read_bytes']/budget['proof_initial_commit_A'],
            salted_tree_blake3_compressions_per_second=hash_work['blake3_compressions']/budget['proof_initial_commit_A'])
        out.append({'old_tokens':c['old_tokens'],'sourcewise_passes_by_generation':sourcewise,
            'sourcewise_counts_exclude_ordered_range_and_queries':True,
            'getter_learned_matrix_MACs':learned,'getter_compulsory_W_HBM_lower_bytes_conditional':hbm,
            'getter_causal_attention_MACs':attention,
            'getter_causal_KV_operand_requested_bytes_no_GQA_reuse':2*attention,
            'getter_W_operand_requested_bytes_tile16x256_upper':W_requested,
            'logical_operand_requests_are_not_physical_HBM_transactions':True,
            'checkpoint_build_write_bytes':(slot+2)*c['checkpoint_bytes'],
            'RMS_original_checkpoint_named_work':getter.rms_checkpoint(),
            'getter_four_INT8_compute_lower_seconds_conditional':compute_lower,
            'getter_W_bandwidth_lower_seconds_conditional':bandwidth_lower,
            'getter_14s_budget_excluded_under_conditions':max(compute_lower,bandwidth_lower)>14,
            'joint_partial_lower_seconds_excluding_commit_FFT_and_all_other_phases':joint,
            'commit_FFT_bandwidth_lower_seconds_conditional_whole_batch':fft_bandwidth,
            'commit_FFT_compute_lower_seconds_conditional':fft_compute,
            'joint_partial_lower_seconds_with_named_FFT':joint+fft_lower,
            'initial_commit_salted_hash_work':hash_work,
            'salted_leaf_read_lower_seconds_conditional_separate_pass':hash_read_lower,
            'joint_partial_lower_seconds_with_FFT_and_leaf_read':joint+fft_lower+hash_read_lower,
            'named_serial_variant_NO_GO_65s':joint+fft_lower+hash_read_lower>response.DEADLINE_SECONDS,
            'complete_lower_seconds':None,'complete_HBM_traffic_bytes':None,
            'complete_W_KV_visits':None,'known_direct_proof_W_visits':169,
            'logical_direct_proof_W_payload_bytes':169*response.W_BYTES,
            'retained_A_state_read_bytes':(slot+1)*whir.a_s1_retention_schedule(s2_coset_rows=1<<22,
                successor_coset_rows=1<<23, reserve_s1_capacity=True)['retained_state_logical_read_bytes_total'],
            'budget_seconds':budget,'budgets_are_targets_not_time_uppers':True,
            'phase_throughput_conditions_partial':phase,
            'times_seconds':response.partition_times(dict.fromkeys(response.BUDGET_SECONDS)),
            'minimal_local_controls':dict(response.PHASE_CONTROLS),
            'minimum_H100_benchmark_ready':False,'admitted':False})
    return {'credit':False,'cases':out,'initial_commit_source_replays':commit_replays,
        'reader_slot_reuse_required':commit_replays==512,'ceilings_are_not_service_floors':True,
        'lower_conditions':['uncompressed disjoint learned i16 weight matrices',
            'cache carry at most 256 MiB at every producer window/full generation',
            'HBM at most 3.35 TB/s; dense INT8 at most 2.2 POPS; four exact dot products per i16 MAC',
            'named serial range/opening kernels under the existing issue ceiling; no overlap credit',
            'linear scatter fusion at each existing S1 stage, without crossing FS barriers'],
        'FFT_lower_conditions':['each of five square FFT kernels traverses the whole batch before the next kernel',
            '2^21 uses one batch of 256 parity halves plus a separate merge; 2^22 uses the existing 128-column batch',
            'cache credit at most 256 MiB separately for every read/write traversal',
            'no whole-batch HBM lower transferred to a smaller-batch or fused FFT schedule'],
        'time_upper':'+infinity','finite_work_is_not_a_finite_time_upper':True,
        'finite_H100_time_upper_required_before_measurement':False,
        'pre_spend_gate':'complete bounded construction, work and peak; joint lower <65s; isolated rate tests and authorized spend'}


if __name__=='__main__':
    import argparse
    from pathlib import Path
    parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--old',type=int,choices=(0,150,300))
    mode.add_argument('--combine',nargs=3,metavar=('O0_JSON','O150_JSON','O300_JSON'))
    args=parser.parse_args()
    if args.old is not None:result=report_case(args.old)
    else:
        import c71_arena_plan as arena
        cases=[json.loads(Path(p).read_text()) for p in args.combine]
        result={'credit':False,'canonical_getter_traces':cases,
            'input_trace_file_sha256':[hashlib.sha256(Path(p).read_bytes()).hexdigest() for p in args.combine],
            'commit_1024_status':'closed_NO_GO; frozen comparison in 2026-09-13 evidence; not reevaluated',
            'commit_512_candidate':response_ledger(cases,512),
            'arena':arena.report(ordered_getter=True,reuse_reader_for_commit=True)}
    print(json.dumps(result,indent=2))
