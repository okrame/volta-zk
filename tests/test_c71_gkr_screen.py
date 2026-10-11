from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_gkr_screen as gkr


def test_endpoint_products_keep_historical_census_and_count_current_schedule():
    ops = {'and': 1, 'xor': 1, 'copy': 1}
    assert gkr.factored_arithmetic(ops, 1) == {
        'Fp3_mul': 22, 'Fp3_add': 21, 'Fp3_sub': 8, 'Fp3_neg': 1}
    assert gkr.factored_arithmetic(ops, 1, endpoint_products=True) == {
        'Fp3_mul': 20, 'Fp3_add': 19, 'Fp3_sub': 12, 'Fp3_neg': 1}


def test_selected_endpoint_census_preserves_boolean_first_round(monkeypatch):
    import c71_residual_profile as residual
    body = (residual.ROOT / residual.PCS / 'rms/gkr.rs').read_text()
    monkeypatch.setattr(residual, 'source', lambda _: body)
    current = residual.admitted_rms_work()
    monkeypatch.setattr(residual, 'source', lambda _: body.replace(
        'hi[gate.x] * hi[gate.y] - f[0] - f[2]', 'previous four-product formula'))
    previous = residual.admitted_rms_work()
    assert current['selected_three_endpoint_products']
    assert not previous['selected_three_endpoint_products']
    for new, old in zip(current['contexts'], previous['contexts']):
        assert new['coefficient_core_Fp3'] == old['coefficient_core_Fp3']
        ops = new['gate_iterations_after_public_support_pruning']
        first = old['selected_boolean_first_round_products_saved'] - new['selected_boolean_first_round_products_saved']
        saved = ops['and'] + ops['xor'] - first
        before, after = old['selected_coefficient_core_Fp3'], new['selected_coefficient_core_Fp3']
        assert before['Fp3_mul'] - after['Fp3_mul'] == saved > 0
        assert before['Fp3_add'] - after['Fp3_add'] == saved
        assert after['Fp3_sub'] - before['Fp3_sub'] == 2 * saved
        assert after['Fp3_neg'] == before['Fp3_neg']

RECORD = (Path(__file__).resolve().parents[1] / 'benchmarks' / 'results' /
          'c71-bounded-rms-gkr-2026-09-19-3e7f24eb332b.json')


def test_public_MSB_support_matches_every_small_assignment():
    gkr.tiny_checks()
    for intervals,period in [([(-1,2)],4),([(3,2)],4),([(0,1)],0)]:
        with pytest.raises(ValueError):gkr.modulo_union(intervals,period)


def test_sass_probe_rejects_branch_and_call(tmp_path):
    path=tmp_path/'gate.sass'
    for instruction in ('BRA 0x10;','CALL 0x10;'):
        path.write_text('Function : c71_gkr_and_gate\n/*0000*/ '+instruction+'\n/*0010*/ EXIT;')
        with pytest.raises(ValueError):gkr.sass_gate_census(path)


def test_byte_endpoint_counts_include_terminal_source_scan():
    # A one-cell/one-lane first layer has no rounds but still four terminals.
    tiny=gkr.byte_source_trace(0,1)
    assert tiny['layers'][0]['getter_calls']==1
    assert tiny['layers'][0]['fold_multiplications']==4
    assert tiny['layers'][0]['cubic_multiplications']==0
    canonical=gkr.byte_source_trace(33,16)
    assert canonical['counted_work']['getter_calls']==87_686_052_315_136
    assert canonical['counted_work']['fold_multiplications']==350_744_209_260_544
    assert canonical['lut_capacity_bytes']==100_466_688
    assert canonical['dense_tree_payload_bytes']==210_693_915_672_576
    assert not canonical['complete_work'] and canonical['logical_accesses_are_not_HBM']
    for bits,lanes in [(0,2),(35,16),(4,3)]:
        with pytest.raises(ValueError):gkr.byte_source_trace(bits,lanes)


def test_frozen_native_record_derives_active_boolean_fold_without_calibration_credit():
    for kind, old in [('RMS', 0), ('EXP30', 0), ('EXP30', 150), ('EXP30', 300)]:
        native = gkr.native_record(RECORD, kind, old)
        trace = gkr.source_prover_trace(native)
        assert not trace['credit'] and not trace['canonical_calibrated_profile']
        assert trace['cell_phase']['boolean_fold_masks_active'] == native['field_value_source_scalars']
        assert (trace['cell_phase']['field_fold_additions_active_boolean_rows']
                > trace['cell_phase']['field_fold_multiplications_active_boolean_rows'])
        assert not trace['complete_work']

    rms = gkr.native_record(RECORD, 'RMS', 0)
    coefficient = gkr.canonical(rms)['factored_arithmetic_after_structural_support_pruning']
    assert coefficient['Fp3_mul'] == 377_460_232_230_821
    for old in (0, 150, 300):
        ratio = gkr.native_record(RECORD, 'EXP30', old)
        arithmetic = gkr.ratio_factored_arithmetic(ratio, old)
        assert arithmetic['Fp3_mul'] > 0
        assert gkr.ratio_supported_pair_total(old) > 0


def test_zero_layer_source_tree_census_matches_empty_native_descent():
    import c71_gkr_screen as screen
    x=screen.source_tree_trace(3,0)
    assert x['layers']==[] and x['counted_work']=={}
    assert x['max_prefix_weight_payload_bytes']==72


def test_lookup_cut_replay_counts_every_padded_leaf():
    for queries,tables,width in [(16,17,4),(32,33,6),(1,1,4)]:
        x=gkr.lookup_source_trace(queries,tables,width)
        n=x['padded_rows'];bits=x['bits'];cut=x['cut']
        leaves=merges=reads=0
        for layer in range(bits):
            height=bits-layer-1
            if height<cut:
                # Independent literal small callback traversal, including terminal.
                for _ in range(layer+1):
                    for index in range(1<<layer):
                        for child in (2*index,2*index+1):
                            span=range(child<<height,(child+1)<<height)
                            leaves+=len(span);merges+=len(span)-1
                            reads+=sum(width if i<queries else 4 if i<queries+tables else 0 for i in span)
        assert x['replay_leaf_reads']==leaves
        assert x['replay_fraction_merges']==merges
        assert x['replay_cached_original_read_bytes']==reads
        assert x['endpoint_equality_multiplications_each_role']==2*n-2
        assert x['build_fraction_merges']==n-1
        assert not x['complete_work'] and not x['complete_physical_peak']


def test_maincell_certificate_excludes_predicates_and_immediate_multipliers(tmp_path):
    import c71_main_cell_screen as cell
    instructions = {
        0: 'IMAD.WIDE.U32 R4, R6, R8.reuse, R10',
        16: 'IMAD.WIDE.U32 R4, R6, 0x18, R10',
        32: 'IMAD.WIDE.U32.X R4, P0, R6, R8, R10',
    }
    assert cell.register_only_wide(instructions, 0, 48) == [0, 32]
    instructions[16] = '@P0 IMAD.WIDE.U32 R4, R6, R8, R10'
    with pytest.raises(ValueError, match='predicated'):
        cell.register_only_wide(instructions, 0, 48)
    for op in ['BRA 0x100', 'CALL 0x100', 'EXIT', 'RET']:
        with pytest.raises(ValueError, match='branch'):
            cell.no_branch({0: op}, 0, 16, 'test path')
    path = tmp_path/'changed.sass'
    path.write_text('Function : c71_gkr_main_cell_fused\n/*0000*/ EXIT; /* 0x0 */\n')
    with pytest.raises(ValueError, match='function changed'):
        cell.screen(path)


def test_byte_endpoint_certificate_rejects_a_changed_kernel(tmp_path):
    import c71_byte_endpoint_screen as endpoint
    path = tmp_path/'changed.sass'
    path.write_text('Function : c71_byte_coeff6\n/*0000*/ EXIT; /* 0x0 */\n')
    with pytest.raises(ValueError, match='binary changed'):
        endpoint.screen(path)
