#!/usr/bin/env python3
"""Canonical A address/producer trace; bounded metadata, not a Gemma runtime.

Source append order mirrors native gemma/{caller,rms,...,softmax}.rs. No
private full source is allocated. Integer kernel service costs remain separate.
"""
from collections import Counter
import json
import math

import c7_1_gemma_plan as base


def sources_at(old):
    if old not in (0, 150, 300):
        raise ValueError('original three-attempt context required')
    cohorts = base.gemma_weight_cohorts(base.pinned_private_tensors())
    sources, by_name = [], {}

    def add(name, rows, cols, width, recipe):
        entry = dict(name=name, rows=rows, cols=cols, width=width, recipe=recipe)
        if name in by_name:
            if sources[by_name[name]] != entry:
                raise ValueError('original source changed shape or recipe')
            return by_name[name]
        by_name[name] = len(sources)
        sources.append(entry)
        return len(sources)-1

    def label(layer, op):
        return f'{"global" if layer is None else layer}/{op}'

    for c in cohorts:
        add(f'C/{c["ordinal"]}', c['rows'], c['columns'], c['cut_scalar_bytes'],
            f'raw/{label(c["layer"], c["operation"])}')
    producers = {}
    for r in base.gemma_input_routes(cohorts):
        k = (r['source_producer']['layer'], r['source_producer']['operation'])
        producers[k] = r['source_shape']
    # Rust BTreeMap<Option<u64>, String>: None before Some(layer).
    for (layer, op), (rows, cols) in sorted(producers.items(),
            key=lambda x: (-1 if x[0][0] is None else x[0][0], x[0][1])):
        name = label(layer, op)
        add('X/'+name, rows, cols, 2, 'output/'+name)
    norms = base.rms_statistic_cohorts(cohorts)
    for i, n in enumerate(norms):
        p = n['source_producer']; name = label(p['layer'], p['operation'])
        add('X/'+name, *n['source_shape'], 2, 'output/'+name)
        add(f'S/{i}', n['statistic_rows'], 1, 6, f'rms_stat/{label(n["layer"], n["operation"])}')
        name = label(n['layer'], n['operation'])
        add('X/'+name, n['statistic_rows']//n['heads'], n['columns']*n['heads'], 2, 'output/'+name)
    for op in ('gate_proj', 'gelu_tanh'):
        for layer in range(60):
            name = label(layer, op)
            add('X/'+name, 150, 21504, 2, 'output/'+name)
    for layer in range(60):
        add(f'M/GELU/{layer}', 1, 65535, 4, f'histogram/{layer}/gelu_tanh')
    for layer in range(60):
        add(f'X/{layer}/up_proj', 150, 21504, 2, f'output/{layer}/up_proj')
    for layer in range(60):
        add(f'R/{layer}/gate_up_mul', 150, 21504, 6, f'raw/{layer}/gate_up_mul')
    for prefix, width in (('R', 6), ('X', 2)):
        for n in norms:
            if n['operation'] in ('q_norm', 'k_norm'):
                name = label(n['layer'], n['operation'][0]+'_rope')
                add(prefix+'/'+name, 150, n['columns']*n['heads'], width,
                    ('raw/' if prefix == 'R' else 'output/')+name)
    for layer in range(60):
        lane = 512 if layer % 6 == 5 else 256
        for op, rows, cols, width in [('R',8192,old+150,6), ('X',8192,old+150,2),
                ('Pi',8192,old+150,2), ('Y',150,32*lane,6)]:
            add(f'attention/{layer}/{op}', rows, cols, width, f'attention/{layer}/{op}')
    for layer in range(60):
        add(f'X/{layer}/ffw_residual_add',150,5376,2,f'output/{layer}/ffw_residual_add')
    ops = ['global/embedding_scale']+[f'{l}/{op}' for l in range(60)
            for op in ('attention_residual_add','ffw_residual_add','layer_scalar_mul')]
    for op in ops:
        add('R/'+op,150,5376,6,'raw/'+op)
    for name, rows, cols, width, recipe in [
            ('X/global/lm_head',50,262144,2,'output/global/lm_head'),
            ('X/global/final_tanh_softcap',50,262144,2,'output/global/final_tanh_softcap'),
            ('M/global/final_tanh_softcap',1,65535,4,'histogram/global/final_tanh_softcap'),
            ('U/global/argmax_slack',50,262144,2,'slack/global/argmax')]:
        add(name, rows, cols, width, recipe)
    for layer in range(60):
        for op, rows, cols, width in [('max',8192,1,2),('D',8192,old+150,2),
                ('E',8192,old+150,4),('Z',8192,1,6),('M',1,65535,4)]:
            add(f'softmax/{layer}/{op}',rows,cols,width,f'softmax/{layer}/{op}')
    return sources



def rms_checkpoint():
    """Original P/S/Y bytes, with S48 once per row; no full A or frame table.

    This is a logical layout, not a CUDA allocation census. Construction uses
    the ordered original getter; its work and scratch are separate obligations.
    """
    norms = base.rms_statistic_cohorts(base.gemma_weight_cohorts(base.pinned_private_tensors()))
    weighted = sum(n['statistic_rows']*n['columns'] for n in norms if n['weighted'])
    unweighted = sum(n['statistic_rows']*n['columns'] for n in norms if not n['weighted'])
    rows = sum(n['statistic_rows'] for n in norms)
    payload = 6*weighted+4*unweighted+6*rows
    # Five usize fields per CompactNorm on the selected 64-bit native target.
    metadata = 40*len(norms)
    return dict(credit=False, weighted_cells=weighted, unweighted_cells=unweighted,
        statistic_rows=rows, payload_bytes=payload, metadata_bytes=metadata,
        owned_payload_and_metadata_bytes=payload+metadata,
        construction_original_byte_reads=payload, construction_payload_writes=payload,
        frame_logical_byte_reads_per_live_pass=12*weighted+10*unweighted,
        dense_padded_frame_bytes=12*(1 << (weighted+unweighted-1).bit_length()),
        reuse_range_slot_bytes=2 << 30,
        lifetime='after A root/P0; release after RMS original-byte obligation before RNE/range',
        source_reconstruction_count_closed=False, complete_physical_peak=False)

def byte_tiles(sources):
    """Same size/tensor/row/column/byte sort as native Bytes::new."""
    tiles = []
    for source, s in enumerate(sources):
        for row, rows in base.dyadic_intervals(s['rows']):
            for col, cols in base.dyadic_intervals(s['cols']):
                for first, width in base.dyadic_intervals(s['width']):
                    tiles.append(dict(source=source,row=row,col=col,rows=rows,
                                      cols=cols,first=first,width=width))
    tiles.sort(key=lambda t: (-t['rows']*t['cols']*t['width'],t['source'],t['row'],t['col'],t['first']))
    offset = 0
    for t in tiles:
        t['offset'] = offset
        offset += t['rows']*t['cols']*t['width']
    return tiles


def tile_word_addresses(t, first, count):
    """Small exact address iterator used by the checked getter adapter."""
    if min(first,count) < 0 or first+count > t['rows']*t['cols']:
        raise ValueError('tile interval out of bounds')
    for word in range(first, first+count):
        r, c = divmod(word,t['cols'])
        yield t['row']+r, t['col']+c, t['offset']+word*t['width']


def read_tile(sources, tile, snapshot, expected_snapshot, word_getter, first, count):
    """Reference adapter: caller cannot substitute the original snapshot.

    word_getter is a trusted internal integer evaluator, not proof-supplied
    data. This helper models routing/byte encoding, not its native refinement.
    """
    if snapshot != expected_snapshot or len(snapshot) != 3 or snapshot[0] not in (0,150,300):
        raise ValueError('original snapshot/root/context mismatch')
    s = sources[tile['source']]
    bound = 1 << (8*s['width']-1)
    out = []
    for row,col,index in tile_word_addresses(tile,first,count):
        value = word_getter(snapshot,s['name'],row,col)
        if not -bound <= value < bound:
            raise ValueError('original signed source width exceeded')
        biased = value+bound
        for b in range(tile['width']):
            out.append((index+b,(biased >> (8*(tile['first']+b))) & 255))
    return out


def getter_trace(old):
    sources = sources_at(old); tiles = byte_tiles(sources)
    cohorts = base.gemma_weight_cohorts(base.pinned_private_tensors())
    words = sum(s['rows']*s['cols'] for s in sources)
    live = sum(s['rows']*s['cols']*s['width'] for s in sources)
    demanded = sum(t['rows']*t['cols'] for t in tiles)
    matrix_macs = sum(c['rows']*c['columns']*c['inner'] for c in cohorts if c['kind']=='matrix')
    # Full padded rectangles for the original attention/Pi sources, with
    # causal cells filled publicly. Only actual rows require dot products.
    attention = 2*32*150*(old+150)*(50*256+10*512)
    kv_read = 2*2*(old+150)*(50*16*256+10*4*512)
    # No tiled/per-query KV reuse assumed: every query visits both K and V.
    kv_traffic = 150*kv_read
    return {'credit':False,'old_tokens':old,'sources':sources,'byte_tiles':len(tiles),
        'source_count':len(sources),'live_bytes':live,'unique_words':words,
        'ordered_byte_tile_word_requests':demanded,
        'extra_word_requests_if_byte_siblings_not_fused':demanded-words,
        'ordered_recipe_switches':sum(a['source']!=b['source'] for a,b in zip(tiles,tiles[1:])),
        'sourcewise_scatter_commit_can_emit_each_word_once':True,
        'per_full_generation_work':{'learned_matrix_MACs':matrix_macs,
            'attention_QK_PV_MACs_rectangular_upper':attention,
            'integer_words_to_encode':words,'emitted_byte_cells':live,
            'KV_payload_read_bytes_querywise_upper':kv_traffic},
        'original_KV_context_bytes':(old+150)*901_120,
        'old_snapshot_reads_newer_KV':False,
        'external_spill_bytes':0,
        'traffic_is_logical_not_certified_HBM':True,
        'all_recipe_arithmetic_and_replay_dependency_work_closed':False,
        'native_getter_peak_bytes':None,
        'missing':['dependency cut schedule for ordered tiles/remainder',
                   'full integer recipe evaluator with retained layer state',
                   'native callback/source codec equivalence and all temporary lifetimes']}


def report():
    return {'credit':False,'cases':[getter_trace(o) for o in (0,150,300)],
            'scatter_generations':[scatter_generation_trace(o) for o in (0,150,300)]}


def scatter_generation_trace(old):
    """Tensor-liveness trace for ONE teacher-forced, sourcewise A generation.

    Retain only DAG outputs with future consumers. Raw matrix outputs are
    emitted in 16x256 i64 tiles and immediately rounded into i16 outputs.
    This is feasible only for a scatter-capable consumer, not ordered range
    leaves or the current high-to-low remainder getter.
    """
    import c7_d126_gemma_qspec_dag as dag
    if old not in (0,150,300):
        raise ValueError('original snapshot context required')
    manifest = base.pinned_gemma_manifest()
    # Reuse the validated full DAG and project its first execution's topology;
    # tensor extents below are the aggregate 150-row proof replay extents.
    executions = dag._expand_schedule(manifest['workload_schedule'])
    nodes = [n for n in dag.expand_dag(manifest,executions) if n.execution==0]
    cohorts = {(c['layer'],c['operation']):c for c in
               base.gemma_weight_cohorts(base.pinned_private_tensors())}
    uses = Counter(dep for n in nodes for dep in n.dependencies)
    live, events, totals, peak = {}, [], Counter(), 0
    # Scatter consumer can absorb each complete histogram before reuse.
    # This is NOT valid for a future challenge-dependent opening or a sorted
    # range stream. Retaining all 121 tables would cost 121*65535*4 bytes.
    persistent_hist = 65535*4
    for n in nodes:
        op, layer = n.operation,n.layer
        lanes = 512 if layer is not None and layer % 6 == 5 else 256
        kv_heads = 4 if lanes==512 else 16
        c = cohorts.get((layer,op))
        work = Counter()
        if c:
            cells = c['rows']*c['columns']
            if c['kind']=='matrix':
                work['integer_MACs'] = cells*c['inner']
                # Explicit 16x256 output tiles; no cross-CTA reuse credit.
                work['W_operand_read_bytes_tile16x256_upper'] = 2*((c['rows']+15)//16)*c['columns']*c['inner']
                work['matrix_X_operand_read_bytes_tile16x256_upper'] = 2*c['rows']*c['inner']*((c['columns']+255)//256)
                work['RNE_i48_to_i16'] = cells
            elif c['kind']=='norm':
                work['integer_mul_weighted_norm'] = cells
                work['W_operand_read_bytes_tile16x256_upper'] = 2*cells
                work['integer_square_and_sum'] = cells
                work['RMS_exact_rows'] = c['rows']
            else:
                work['embedding_i16_reads'] = cells
                work['W_operand_read_bytes_tile16x256_upper'] = 2*cells
        elif op in ('q_rope','q_norm'):
            cells = 150*32*lanes
        elif op in ('k_rope','v_source','v_norm'):
            cells = 150*kv_heads*lanes
            if op=='v_norm':
                work['integer_square_and_sum'] = cells
                work['RMS_exact_rows'] = 150*kv_heads
        elif op in ('qk_matmul','attention_mask_add','softmax'):
            cells = 32*150*(old+150)
            if op=='qk_matmul':
                work['integer_MACs'] = cells*lanes
                work['RNE_i48_to_i16'] = cells
                work['KV_i16_reads'] = 150*kv_heads*(old+150)*lanes
            elif op=='softmax':
                work['EXP30_lookup'] = cells
                work['RNE_ratio_i48'] = cells
                work['row_max_and_sum_terms'] = cells
        elif op=='pv_matmul':
            cells = 150*32*lanes
            work['integer_MACs'] = cells*(old+150)
            work['RNE_i48_to_i16'] = cells
            work['KV_i16_reads'] = 150*kv_heads*(old+150)*lanes
        elif op in ('gelu_tanh','gate_up_mul'):
            cells = 150*21504
            work['GELU_lookup' if op=='gelu_tanh' else 'integer_mul_gate'] = cells
            if op=='gate_up_mul': work['RNE_i48_to_i16'] = cells
        elif op=='final_tanh_softcap':
            cells = 50*262144
            work['softcap_lookup'] = cells
        elif op=='argmax':
            cells = 50
            work['argmax_compare_and_slack'] = 50*262144
        elif op=='token_input':
            cells = 150
        elif op=='last_row_select':
            cells = 50*5376
        elif op=='kv_cache_append':
            cells = 0  # A replay reads original immutable KV, no second append.
            work['computed_KV_cells_routed_to_original_A'] = 2*150*kv_heads*lanes
        elif op in ('embedding_scale','attention_residual_add','ffw_residual_add','layer_scalar_mul'):
            cells = 150*5376
            work['integer_affine'] = cells
            work['RNE_i48_to_i16'] = cells
        else:
            raise ValueError('unclassified native DAG operator: '+op)
        if op.endswith('_rope'):
            work['RoPE_Q30_pairs'] = cells//2
            work['RNE_i48_to_i16'] = cells
        bytes_out = cells*(4 if op in ('token_input','argmax') else 2)
        # Source emitter consumes raw and all its byte siblings before tile
        # reuse. Exact tensor implementation and correction buffers are pending.
        raw_tile = 16*256*8 if any(k.startswith(('integer_','RNE_')) for k in work) else 0
        before = sum(live.values())+persistent_hist
        live[n.id] = bytes_out
        allocated = sum(live.values())+persistent_hist+raw_tile
        peak = max(peak,allocated)
        reads = sum(live[d] for d in n.dependencies)
        work['logical_activation_read_bytes'] += reads
        work['logical_activation_write_bytes'] += bytes_out
        released = []
        for dep in n.dependencies:
            uses[dep] -= 1
            if not uses[dep]:
                released.append(dep);del live[dep]
        if not uses[n.id]:
            released.append(n.id);del live[n.id]
        events.append(dict(node=n.id,layer=layer,operation=op,dependencies=list(n.dependencies),
            allocated_before=before,output_bytes=bytes_out,raw_tile_bytes=raw_tile,
            allocated_at_event=allocated,released=released,allocated_after=sum(live.values())+persistent_hist,
            work=dict(work)))
        totals.update(work)
    assert not live
    return dict(credit=False,old_tokens=old,events=events,work=dict(totals),
        named_tensor_peak_bytes=peak,persistent_histogram_bytes=persistent_hist,
        virtual_A_output_bytes= getter_trace(old)['live_bytes'],
        includes_full_raw_tensor=False, includes_second_KV_cache=False,
        consumer_requires_scatter=True,ordered_source_schedule_closed=False,
        native_kernel_workspace_bytes=None,
        uncounted=['producer-to-virtual-A scatter operations',
            'kernel-specific RMS/ratio/table internal workspaces',
            'exact-int8 GEMM correction/packing workspace',
            'physical HBM cache/reload factors', 'native original-KV/source refinement'])


if __name__=='__main__':
    print(json.dumps(report(),indent=2))
