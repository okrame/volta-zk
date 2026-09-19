#!/usr/bin/env python3
"""Local C7.1 response ledger: replay stays in proof time, never inference.

Budgets are an allocation proposal, not measured times or service guarantees.
This file composes bounded traces, retaining explicit unknown-work gates.
"""
import json
import math
from pathlib import Path

import c71_getter_trace as getter
import c71_gkr_screen as gkr
import c71_pcg_trace as pcg
import c71_streaming_screen as screen
import c71_whir_trace as whir

DEADLINE_SECONDS = 65.0
OPERATIONAL_MARGIN_BYTES = 256 << 20
ARENA = 6_442_450_944
W_BYTES = 61_394_690_560
KV_PER_TOKEN = 4*(50*16*256+10*4*512)
# Owner-authorized complete-response contract; budgets remain targets.
BUDGET_SECONDS = {
    'inference':1.5,
    'proof_getter_replay':17.0,
    'proof_producer_relations':0.8,
    'proof_range_W_A':17.9,
    'proof_linear_W_A_history':0.8,
    'proof_initial_commit_A':7.0,
    'proof_first_oracle_openings':15.2,
    'proof_WHIR_remaining':2.0,
    'proof_PCG_MAC':2.0,
    'proof_serialization_transport':0.3,
    'proof_host_waits_verifier_interactions':0.5,
}
assert math.isclose(sum(BUDGET_SECONDS.values()),DEADLINE_SECONDS)

# Each missing item is an admission control, not zero work. Keep the same
# phase keys as the time partition so no unpriced phase disappears in totals.
PHASE_CONTROLS = {
    'inference':'native provider baseline, exact workload and peak workspace',
    'proof_getter_replay':'ordered dependency cuts, exact integer adapter, workspace and service floor',
    'proof_producer_relations':'all producer GKR/MAC work, temporaries and service floor',
    'proof_range_W_A':'equality/H reduction, gather HBM, kernel and synchronization service floors',
    'proof_linear_W_A_history':'A linear/history trace plus W weight generation and service floor',
    'proof_initial_commit_A':'scatter/native codec equivalence, source-uniform encoder, FFT/hash service floors',
    'proof_first_oracle_openings':'native remainder/hash/reader trace and service floors',
    'proof_WHIR_remaining':'covector adapter, masks, terminal OpeningMac, field/hash service floors',
    'proof_PCG_MAC':'OT/Fp6 native retention, reference codec refinement and both-role service floors',
    'proof_serialization_transport':'actual wire upper, external link floor and serializer stalls',
    'proof_host_waits_verifier_interactions':'verifier execution, round trips and bounded host stalls',
}
assert set(PHASE_CONTROLS)==set(BUDGET_SECONDS)

GKR_RECORD = (Path(__file__).resolve().parents[1] / 'benchmarks' / 'results' /
              'c71-bounded-rms-gkr-2026-09-19-3e7f24eb332b.json')


def maximum_source_trace(old):
    """One public layer checkpoint, rebuilt from the fixed original D bytes."""
    native=gkr.native_record(GKR_RECORD, 'EXP30', old)
    n=native['padded_cells'];live=native['live_cells']
    key_bits=(old+150-1).bit_length()
    row_bits=n.bit_length()-1-key_bits
    tree=gkr.source_tree_trace(row_bits,key_bits)
    layers=[]
    for l,work in enumerate(tree['layers']):
        entries=1 << (row_bits+l)
        leaves=l==key_bits-1
        layers.append(dict(entries=entries,
            checkpoint_capacity_bytes=entries*(8 if leaves else 16),
            original_byte_getter_calls=2*live,
            build_Fp_products=0 if leaves else live,
            logical_checkpoint_read_bytes=work['getter_calls']*(8 if leaves else 16),
            **work))
    return dict(credit=False,old_tokens=old,live_cells=live,padded_cells=n,
        row_bits=row_bits,key_bits=key_bits,layers=layers,
        maximum_checkpoint_capacity_bytes=max(x['checkpoint_capacity_bytes'] for x in layers),
        checkpoint_logical_write_bytes=sum(x['checkpoint_capacity_bytes'] for x in layers),
        checkpoint_logical_read_bytes=sum(x['logical_checkpoint_read_bytes'] for x in layers),
        original_byte_getter_calls=2*key_bits*live,
        build_Fp_products=(key_bits-1)*live,
        source_tree_work=tree,
        dense_tree_payload_rejected_bytes=48*sum(n>>l for l in range(key_bits+1)),
        dense_assignment_payload_removed_bytes=16*n,
        complete_work=False,complete_physical_peak=False,
        missing=['terminal MAC/products/FS and proof capacities',
                 'original D getter integer work and physical traffic',
                 'allocator and complete caller liveness'])


def producer_gkr_trace(old):
    """Known source work for RMS and this response's EXP30 relation.

    Counts are mathematical/source-level operations. Dividing by the phase
    budget states an admission throughput target, never a measured bound.
    """
    natives = [gkr.native_record(GKR_RECORD, 'RMS', 0),
               gkr.native_record(GKR_RECORD, 'EXP30', old)]
    traces = [gkr.source_prover_trace(native) for native in natives]
    coefficient_cores = [
        gkr.canonical(natives[0])['factored_arithmetic_after_structural_support_pruning'],
        gkr.ratio_factored_arithmetic(natives[1], old),
    ]
    scalar = {
        'original_frame_callbacks':sum(
            trace['cell_phase']['cell_first_logical_frame_callbacks'] for trace in traces),
        'Boolean_replay_gate_evaluations':sum(
            trace['cell_phase']['cell_first_scalar_boolean_replay_gates'] for trace in traces),
        'field_values_loaded_from_rows':sum(
            trace['cell_phase']['field_value_source_scalars'] for trace in traces),
        'byte_endpoint_getter_calls':sum(
            trace['byte_endpoint']['counted_work']['getter_calls'] for trace in traces),
    }
    masks = sum(trace['cell_phase']['boolean_fold_masks_active'] for trace in traces)
    field = {
        'cell_fold_multiplications':sum(
            trace['cell_phase']['field_fold_multiplications_active_boolean_rows'] for trace in traces),
        'cell_fold_additions':sum(
            trace['cell_phase']['field_fold_additions_active_boolean_rows'] for trace in traces),
        'cell_fold_subtractions':sum(
            trace['cell_phase']['field_fold_subtractions_terminal'] for trace in traces),
        'prefix_weight_multiplications':sum(
            trace['cell_phase']['prefix_weight_multiplications'] for trace in traces),
        'prefix_weight_subtractions':sum(
            trace['cell_phase']['prefix_weight_subtractions'] for trace in traces),
        'selector_equality_multiplications':sum(
            trace['cell_phase']['structural_selector_assigned_terms']
            * (native['padded_cells'].bit_length()-1)
            for trace, native in zip(traces, natives)),
        **{f'factored_coefficient_{name}':sum(core[name] for core in coefficient_cores)
           for name in ('Fp3_mul', 'Fp3_add', 'Fp3_sub', 'Fp3_neg')},
    }
    for name in ('equality_multiplications', 'equality_additions', 'equality_subtractions',
                 'cubic_multiplications', 'cubic_additions', 'cubic_subtractions',
                 'fold_multiplications', 'fold_additions', 'fold_subtractions'):
        field['byte_endpoint_'+name] = sum(
            trace['byte_endpoint']['counted_work'][name] for trace in traces)
    maximum=maximum_source_trace(old)
    scalar['maximum_original_byte_getter_calls']=maximum['original_byte_getter_calls']
    scalar['maximum_checkpoint_getter_bundles']=maximum['source_tree_work']['counted_work']['getter_calls']
    field['maximum_build_Fp_products']=maximum['build_Fp_products']
    for name,value in maximum['source_tree_work']['counted_work'].items():
        if name.startswith(('equality_','cubic_','fold_')):
            field['maximum_'+name]=value
    budget = BUDGET_SECONDS['proof_producer_relations']
    return {'credit':False, 'canonical_calibrated_profile':False,
        'relations':['RMS', f'EXP30_O{old}'], 'record':GKR_RECORD.name,
        'EXP30_maximum':maximum,
        'source_level_scalar_getter_work_known_components':scalar,
        'branchless_Boolean_fold_masks':masks,
        'source_level_field_work_known_components':field,
        'phase_budget_seconds':budget,
        'partial_admission_throughput_targets':{
            **{name+'_per_second':value/budget for name,value in scalar.items()},
            'Boolean_fold_masks_per_second':masks/budget,
            **{name+'_per_second':value/budget for name,value in field.items()}},
        'complete_work':False, 'complete_physical_peak':False,
        'missing':['index-round and terminal authentication arithmetic',
                   'selector equality complement subtractions',
                   'MAC/FS/serialization work',
                   'original frame getter integer work and traffic',
                   'native fused-kernel service rate and complete allocator liveness']}


def partition_times(upper_by_phase):
    """Only COMPLETE applicable phase uppers may be supplied here.

    No inference baseline, guessed overlap or allocated budget is silently
    used as a timing upper. Proof wall includes required peer waits, transport
    and serialization; additional final acceptance checks belong in host/waits.
    """
    if set(upper_by_phase)!=set(BUDGET_SECONDS):
        raise ValueError('every end-to-end phase must be present')
    for value in upper_by_phase.values():
        if value is not None and (not math.isfinite(value) or value < 0):
            raise ValueError('nonnegative finite upper or explicit unknown required')
    def add(values):
        return None if any(x is None for x in values) else sum(values)
    return {'T_inference':upper_by_phase['inference'],
            'T_proof_only':add([v for k,v in upper_by_phase.items() if k!='inference']),
            'T_response_total':add(list(upper_by_phase.values()))}


def shared_roots(old):
    count=2+old//150  # W plus current and old A; keep initial pads until run end.
    cache=whir.top_cache_bytes(whir.oracle_geometry(35)[0]['height'])
    cache+=(count-1)*whir.top_cache_bytes(whir.oracle_geometry(34)[0]['height'])
    return cache+count*(128*1536*8+32)


def integrated_memory(old, whir_traces, pcg_report, retained_A=None):
    caps=pcg_report['liveness_caps']
    # Prover is punctured receiver of the selected cGGM; Delta lives at verifier.
    state=pcg_report['setup_once_before_all_responses']['persistent_selected_cGGM_state']
    pcg_live=(caps['prover_raw_batch_bytes']+caps['prover_two_row_carry_bytes']
        +caps['two_aligned_public_term_arrays_bytes']+caps['two_sparse_Fp3_frontiers_bytes_per_role']
        +caps['public_u32_histogram_bytes']+state['GPU_prover_receiver_u32_path_aligned_bytes'])
    slots={'getter_named_plus_unverified_workspace_slot':64<<20,
           'reader_hash_slot':256<<20,'metadata_slot':128<<20,
           'proof_output_cap':130_000_000,'W_histogram':65535*8,
           'PCG_named_live':pcg_live}
    rows=[]
    # Serial arena reuse: no early W contraction coexists with range. Values
    # include out-of-place fold destinations from the existing preflight.
    suffix=screen.suffix_first_weight_budget()
    phase_arrays={
        'producer_sourcewise':0,  # named tensor state is inside getter slot
        'range_canopy_cut11':1_610_612_688+1_006_632_960+503_316_480,
        'range_Gram_windows':24_576+3_072,
        'range_resident_m24':3_023_056_896,
        'linear_W_suffix15':suffix['contraction_bytes'],
        'linear_W_last20':suffix['terminal_W_and_L_bytes'],
    }
    for phase, arrays in phase_arrays.items():
        named=arrays+shared_roots(old)+sum(slots.values())
        rows.append(dict(chain='response',event=phase,known_arena_live_bytes=named,
            arena_margin=ARENA-named,
            unknown=['native scratch/metadata must fit proposed slots; A linear and producer GKR state unresolved']))
    for chain in ['W']+[f'A{i}' for i in range(old//150+1)]:
        d=35 if chain=='W' else 34
        current=(chain==f'A{old//150}')
        for event in whir_traces[d]['events']:
            if retained_A is not None and d==34 and event['event']!='commit_data_0':
                continue  # Replace opening path for EACH fresh A proof.
            if not current and event['event']=='commit_data_0':
                continue  # Installed W and accepted old A are not recommitted.
            buffers=event['known_live_buffers_after']
            shared=sum(v for k,v in buffers.items() if k.startswith('shared:'))
            named=event['known_live_bytes_after']-shared+shared_roots(old)+sum(slots.values())
            rows.append(dict(chain=chain,event=event['event'],known_arena_live_bytes=named,
                             arena_margin=ARENA-named,unknown=event['unknown']))
        if retained_A is not None and d==34:
            # Only current A is initially committed above. Each historical
            # A also has a fresh WHIR opening chain and can retain its S1.
            for event in retained_A['events']:
                buffers=event['known_live_buffers_after']
                shared=sum(v for k,v in buffers.items() if k.startswith('shared:'))
                named=event['known_live_bytes_after']-shared+shared_roots(old)+sum(slots.values())
                rows.append(dict(chain=chain,event=event['event'],known_arena_live_bytes=named,
                    arena_margin=ARENA-named,unknown=event['unknown']))
    peak=max(rows,key=lambda x:x['known_arena_live_bytes'])
    return {'phases':rows,'slots_bytes':slots,'shared_initial_roots_bytes':shared_roots(old),
        'known_peak_event':peak,'known_peak_with_proposed_slots_bytes':peak['known_arena_live_bytes'],
        'proposed_arena_reserved_bytes':ARENA,
        'known_global_reserved_bytes':W_BYTES+450*KV_PER_TOKEN+ARENA,
        'known_global_remaining_before_other_residents':80_000_000_000-W_BYTES-450*KV_PER_TOKEN-ARENA,
        'physical_allocated_peak_complete':None,'physical_reserved_peak_complete':None,
        'missing':['public tables/compiled Gamma and host/device allocator/context census',
            'native inference workspace and producer GKR/A linear buffers',
            'small-space WHIR sumcheck and terminal OpeningMac state',
            'native producer/kernel scratch inside the 64MiB slot',
            'native EAGen codec refinement and OT/backend retention'],
        'zero_spill_is_a_requirement_not_measured':True}


def report():
    assessment=screen.base.b12_pcs_binding_assessment()
    dominant=screen.dominant_cost_screen(assessment)
    pcs={d:whir.trace(d) for d in (35,34)}
    retained=whir.a_s1_retention_schedule(s2_coset_rows=1<<22,
                successor_coset_rows=1<<23, reserve_s1_capacity=True)
    correlations=pcg.report()
    cases=[]
    for slot,old in enumerate((0,150,300)):
        producer_gkr = producer_gkr_trace(old)
        routes=getter.getter_trace(old)
        generation=getter.scatter_generation_trace(old)
        # Explicit no-folded-state replay model, before unknown sumcheck work.
        switches_W=pcs[35]['commit_source_replays_total']-pcs[35]['commit_source_replays_by_oracle'][0]
        switches_A=pcs[34]['commit_source_replays_total']-pcs[34]['commit_source_replays_by_oracle'][0]
        W_visits=29+2+switches_W+12+11
        A_current=512+26+switches_A+12+11
        A_old=switches_A+12+11
        before_sumcheck=[A_old]*slot+[A_current]
        # Rank-one first batch + eleven two-round rational covector batches.
        # Count their original-source replay in proof time even if the native
        # streaming adapter remains unimplemented.
        sumcheck_passes=1+22
        A_by_generation=[n+sumcheck_passes for n in before_sumcheck]
        generators=[getter.scatter_generation_trace(o) for o in range(0,old+1,150)]
        replay_macs=sum(n*g['work']['integer_MACs'] for n,g in zip(A_by_generation,generators))
        kv_reads=2*sum(n*g['work']['KV_i16_reads'] for n,g in zip(A_by_generation,generators))
        lower=dominant['cases'][slot]
        learned_macs=dominant['matrix_MACs_per_full_A_generation']*sum(A_by_generation)
        # Conditional screen for the literal four-INT8 exact-i16 replay;
        # 2.2 POPS dense is an explicit generous ceiling, NOT a service floor.
        replay_lower=8*learned_macs/2.2e15
        joint_lower=replay_lower+lower['range_merges_commit_FFT_first_openings_joint_lower_seconds']
        retained_passes=[retained['original_A_source_passes_through_S1']]*slot+[
            retained['current_A_passes_with_external_512_commit_and_26_range']]
        retained_macs=sum(n*g['work']['integer_MACs'] for n,g in zip(retained_passes,generators))
        retained_replay_lower=8*dominant['matrix_MACs_per_full_A_generation']*sum(retained_passes)/2.2e15
        retained_joint_lower=retained_replay_lower+lower['range_merges_commit_FFT_first_openings_joint_lower_seconds']
        demands={
            'proof_getter_replay':{'integer_MACs_per_second_for_named_replays':replay_macs/BUDGET_SECONDS['proof_getter_replay']},
            'proof_producer_relations':producer_gkr['partial_admission_throughput_targets'],
            'proof_range_W_A':{'named_merge_issue_instructions_per_second':
                lower['range_W_A_named_merge_issue_lower_seconds']*(132*4*32*2e9)
                /BUDGET_SECONDS['proof_range_W_A']},
            'proof_initial_commit_A':{'FFT_butterflies_per_second':
                3_023_656_976_384/BUDGET_SECONDS['proof_initial_commit_A']},
            'proof_first_oracle_openings':{'FFT_butterflies_per_second':
                lower['split_payload_pad_openings_first_oracles_Fp_butterflies']
                /BUDGET_SECONDS['proof_first_oracle_openings']},
            'proof_PCG_MAC':{'selected_trie_H_work_upper_per_second_for_phase_budget':
                correlations['responses'][slot]['union_trie_H_evaluations_upper_per_role']/BUDGET_SECONDS['proof_PCG_MAC'],
                'EAGen_SHAKE_calls_per_second_for_phase_budget':22*pcg.ROWS[slot][1]/BUDGET_SECONDS['proof_PCG_MAC']},
        }
        setup=correlations['setup_once_before_all_responses']
        demands['proof_PCG_MAC']['fresh_session_setup_H_additional_per_role_if_first_response']=(
            setup['internal_cGGM_H_evaluations_lower_per_role_if_two_full_traversals'] if slot==0 else 0)
        ranges=[screen.gram_window_budget(35,11,W_BYTES,24),
                screen.gram_window_budget(34,10,routes['live_bytes'],24)]
        for key in ('fraction_merges_initial_and_replay',
                    'factored_resident_coefficient_Fp3_mul_expressions',
                    'resident_scalar_interpolations','Gram_build_Fp3_mul_expressions',
                    'lower_child_weighted_accumulations'):
            demands['proof_range_W_A'][key+'_per_second']=sum(r[key] for r in ranges)/BUDGET_SECONDS['proof_range_W_A']
        demands['proof_linear_W_A_history']={
            'W_only_contraction_updates_per_second':screen.suffix_first_weight_budget()['both_scans_update_model']}
        demands['proof_WHIR_remaining']={
            'covector_core_Fp3_butterflies_per_second':sum(
                pcs[d]['later_covector_candidate']['block_convolution_fp3_butterflies_excluding_inverse_precomputation']
                for d in [35]+[34]*(slot+1))/BUDGET_SECONDS['proof_WHIR_remaining']}
        cases.append({'old_tokens':old,'budget_seconds':dict(BUDGET_SECONDS),
            'budget_is_target_not_time_upper':True,
            'fresh_session_setup_charged_to_proof_PCG_MAC':slot==0,
            'T_session_setup_component_seconds':None if slot==0 else 0,
            'times_seconds':partition_times(dict.fromkeys(BUDGET_SECONDS)),
            'phase_throughput_conditions_partial':demands,
            'conditional_four_int8_getter_screen':{
                'dense_INT8_ops_per_second_ceiling_condition':2.2e15,
                'four_INT8_exact_i16_operations_named_replays':8*learned_macs,
                'proof_getter_only_lower_seconds':replay_lower,
                'allocated_getter_budget_already_excluded':replay_lower>BUDGET_SECONDS['proof_getter_replay'],
                'proof_joint_partial_lower_seconds':joint_lower,
                'excludes_native_inference_and_other_positive_work':True,
                'serial_named_schedule_no_additional_fusion_or_retention':True,
                'deadline_excluded_under_these_conditions':joint_lower>DEADLINE_SECONDS},
            'known_source_visits_before_sumcheck':{'direct_W':W_visits,'A_by_generation':before_sumcheck,
                'complete_W_A_KV_visits':None},
            'known_source_visits_with_sumcheck_candidate':{'direct_W':W_visits+sumcheck_passes,
                'A_by_generation':A_by_generation,'ordered_getter_dependency_repeats':None},
            'proof_getter_replay_work':{'integer_MACs_named_generation_model':replay_macs,
                'logical_querywise_KV_read_bytes':kv_reads,
                'logical_direct_W_payload_bytes':(W_visits+sumcheck_passes)*W_BYTES,
                'logical_A_bytes_requested':sum(n*getter.getter_trace(o)['live_bytes']
                    for n,o in zip(A_by_generation,range(0,old+1,150))),
                'logical_W_operand_bytes_upper_tile16x256':sum(n*g['work']['W_operand_read_bytes_tile16x256_upper']
                    for n,g in zip(A_by_generation,generators)),
                'W_HBM_inside_A_reconstruction_measured':None,
                'HBM_total':None,'external_W_reloads_or_spill':0,
                'native_provider_inference_replays_deducted':0},
            'getter_census':{k:v for k,v in routes.items() if k!='sources'},
            'sourcewise_generator':{k:v for k,v in generation.items() if k!='events'},
            'producer_GKR_partial_work':producer_gkr,
            'memory':integrated_memory(old,pcs,correlations),
            'retained_A_alternative':{
                'original_A_passes_by_generation':retained_passes,
                'original_A_passes_saved':sum(A_by_generation)-sum(retained_passes),
                'direct_W_visits_unchanged':W_visits+sumcheck_passes,
                'integer_MACs_named_generation_model':retained_macs,
                'logical_querywise_KV_read_bytes':2*sum(n*g['work']['KV_i16_reads']
                    for n,g in zip(retained_passes,generators)),
                'logical_W_operand_bytes_upper_tile16x256':sum(n*g['work']['W_operand_read_bytes_tile16x256_upper']
                    for n,g in zip(retained_passes,generators)),
                'retained_state_logical_read_bytes':(slot+1)*retained['retained_state_logical_read_bytes_total'],
                'retained_state_write_bytes':(slot+1)*retained['all_retained_state_write_bytes'],
                'retained_Fp3_fold_interpolations':(slot+1)*retained['fp3_interpolations_all_retained_folds_and_virtual_getters'],
                'four_INT8_getter_partial_lower_seconds_under_same_conditions':retained_replay_lower,
                'joint_partial_lower_seconds_under_same_conditions':retained_joint_lower,
                'deadline_excluded_under_same_conditions':retained_joint_lower>DEADLINE_SECONDS,
                'getter_integer_MACs_per_second_for_phase_budget':retained_macs/BUDGET_SECONDS['proof_getter_replay'],
                'extra_retained_work_is_positive_not_in_lower':True,
                'dependency_replays_and_HBM_total_still_unknown':True,
                'memory':integrated_memory(old,pcs,correlations,retained_A=retained),
            },
            'admitted':False})
    return {'credit':False,'constraint':'T_response_total <= 65 seconds',
        'time_identity':'T_response_total = T_inference + T_proof_only; serial accounting, no overlap credit',
        'inference_definition':'one native correct provider generation; no proof replay deducted',
        'proof_definition':'all reconstruction/authentication, proof kernels, transport, verifier completion and serialization; fresh session setup charged once to first proof',
        'installation_and_bootstrap':'global model installation reported separately; session setup is a separate subcomponent charged to first proof_PCG_MAC and every complete prefix, never amortized away',
        'online_verifier_challenge_round_trips':0,
        'phase_budgets_are_not_complete_uppers':True,'cases':cases,
        'phase_controls_required_before_finite_upper':PHASE_CONTROLS,
        'WHIR':pcs,'WHIR_retained_A':retained,'PCG':correlations,
        'complete_time_upper':None,'admission_time_upper':'+infinity',
        'next_structural_controls':['sourcewise scatter adapter bit-for-bit with native A commitment',
            'ordered A range/remainder dependency cuts',
            'source-uniform transposed WHIR covector update',
            'public EAGen reference codec refinement and bounded native PCG workspace',
            'applicable service floors for every phase, including native inference']}


if __name__=='__main__':
    print(json.dumps(report(),indent=2))
