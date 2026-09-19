from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_gkr_screen as gkr

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
