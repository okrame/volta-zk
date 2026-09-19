from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_gkr_screen as gkr


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
    assert tiny['layers'][0]['getter_calls']==4
    assert tiny['layers'][0]['cubic_multiplications']==0
    canonical=gkr.byte_source_trace(33,16)
    assert canonical['counted_work']['getter_calls']==350_744_209_260_544
    assert canonical['lut_capacity_bytes']==100_466_688
    assert canonical['dense_tree_payload_bytes']==210_693_915_672_576
    assert not canonical['complete_work'] and canonical['logical_accesses_are_not_HBM']
    for bits,lanes in [(0,2),(35,16),(4,3)]:
        with pytest.raises(ValueError):gkr.byte_source_trace(bits,lanes)
