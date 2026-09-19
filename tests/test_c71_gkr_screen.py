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
