from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import c7_d126_gemma_shapes as shapes


@pytest.fixture(scope="module")
def compiled():
    manifest = shapes.dag._json_no_duplicates(shapes.dag.MANIFEST.read_bytes())
    rows, report = shapes.compile_shapes(manifest)
    return manifest, rows, report


def test_complete_logical_port_census_and_weight_coverage(compiled):
    _, rows, report = compiled
    assert report["logical_shapes"] == "PASS"
    assert report["nodes"] == 79_963
    assert report["tensor_output_ports"] == 83_023
    assert report["tensor_input_port_edges"] == 104_322
    assert report["private_tensor_coverage"] == 772
    assert report["logical_alias_ports"] == 610
    assert report["kv_arena_view_ports"] == 6_120
    assert report["owned_real_output_elements"] == 1_841_924_224
    assert report["canonical_rows_sha256"] == "35c6716f0b8ca5ffc1e089c592af647dcf3c094ed692d7398bff8fbb5561e7d3"
    assert report["allowed_score_cells"] == 21_744_000
    assert report["masked_score_cells"] == 9_504_000
    assert report["max_dot_width"] == 21_504
    for row in rows:
        assert all(source < row.node_id for source, _ in row.input_ports)
        assert all(port.shape[0] == 1 for port in row.outputs)
        for source, name in row.input_ports:
            assert name in {port.name for port in rows[source].outputs}
    assert report["status"] == "BLOCKED"
    assert report["admission_credit"] is False
    assert report["integer_wire_count"] is None
    assert report["physical_peak_bytes"] is None
    assert report["gkr_domain_padding"] is None
    assert report["max_private_tensor_scratch_bytes"] == 2_818_572_288
    cases = report["representation_screens"]["cases"]
    assert cases["i16"]["owned_output_bytes"] == 3_683_848_448
    assert cases["i16"]["conditional_headroom_bytes"] == 4_532_011_008
    assert cases["i16"]["status"] == "BLOCKED"
    assert cases["Fp"]["owned_output_bytes"] == 14_735_393_792
    assert cases["Fp"]["status"] == "NO-GO_IF_SIMULTANEOUS"
    assert cases["Fp3"]["status"] == "NO-GO_IF_SIMULTANEOUS"


def test_global_raw_k_alias_and_selected_final_row(compiled):
    _, rows, _ = compiled
    by_key = {(r.execution, r.layer, r.operation): r for r in rows}
    for execution in range(51):
        t = 100 if execution == 0 else 1
        for layer in (0, 5):
            hd, kh = (256, 16) if layer == 0 else (512, 4)
            q = by_key[(execution, layer, "q_norm")]
            assert q.outputs[0].shape == (1, t, 32, hd)
            v = by_key[(execution, layer, "v_source")]
            assert v.outputs[0].shape == (1, t, kh * hd)
            if layer == 5:
                assert v.outputs[0].alias_node == by_key[(execution, layer, "k_proj")].node_id
                assert v.outputs[0].alias_node != by_key[(execution, layer, "k_norm")].node_id
                assert not v.weight_keys
            else:
                assert v.outputs[0].storage == "owned"
            qk = by_key[(execution, layer, "qk_matmul")]
            pv = by_key[(execution, layer, "pv_matmul")]
            assert qk.input_ports[1][1] == "k"
            assert pv.input_ports[1][1] == "v"
            assert qk.gqa_repeat == (2 if layer == 0 else 8)
        if execution < 50:
            selected = by_key[(execution, None, "last_row_select")].outputs[0]
            assert selected.shape == (1, 1, 5376)
            assert selected.offset_elements == (99 * 5376 if execution == 0 else 0)
            assert selected.alias_node == by_key[(execution, None, "final_rms")].node_id
            assert by_key[(execution, None, "lm_head")].dot_products == 262_144
    assert (50, None, "final_rms") not in by_key


def test_cache_views_cover_only_current_prefix_and_append_once(compiled):
    _, rows, _ = compiled
    by_key = {(r.execution, r.layer, r.operation): r for r in rows}
    for layer in range(60):
        for execution in range(51):
            row = by_key[(execution, layer, "kv_cache_append")]
            assert [port.name for port in row.outputs] == ["k", "v"]
            assert all(port.shape[1] == 100 + execution for port in row.outputs)
            if execution:
                old = by_key[(execution - 1, layer, "kv_cache_append")].node_id
                assert row.input_ports[-2:] == ((old, "k"), (old, "v"))
            assert all(port.storage == "kv-arena-view" for port in row.outputs)


def test_same_sized_rewired_dag_is_rejected(compiled):
    manifest, _, _ = compiled
    schedule = shapes.dag._expand_schedule(manifest["workload_schedule"])
    nodes = shapes.dag.expand_dag(manifest, schedule)
    index = next(i for i, n in enumerate(nodes) if n.operation == "v_source" and n.layer == 5)
    nodes[index] = replace(nodes[index], dependencies=(nodes[index].dependencies[0] + 1,))
    with pytest.raises(shapes.ShapeError, match="edges or owner"):
        shapes.compile_shapes(manifest, nodes)


def test_indexed_gqa_matches_explicit_repetition_on_small_integer_tensors():
    # Independent materialized reference catches the common h % kv_heads error.
    q = [[h + 1, 2 - h] for h in range(8)]
    k = [[[10 * h + s, s + 2] for s in range(3)] for h in range(2)]
    repeated = [head for head in k for _ in range(4)]
    expected = [[sum(a * b for a, b in zip(q[h], repeated[h][s])) for s in range(3)] for h in range(8)]
    actual = [[sum(a * b for a, b in zip(q[h], k[shapes.kv_head(h, 8, 2)][s])) for s in range(3)] for h in range(8)]
    assert actual == expected
    assert [shapes.kv_head(h, 8, 2) for h in range(8)] == [0, 0, 0, 0, 1, 1, 1, 1]
    for values in ((0, 7, 2), (8, 8, 2), (-1, 8, 2), (0, 8, 0)):
        with pytest.raises(shapes.ShapeError):
            shapes.kv_head(*values)


def test_causal_window_boundaries_against_independent_cell_enumeration():
    for s in (1, 100, 150, 1024, 1025, 4096):
        for q in (0, s // 2, s - 1):
            for window in (None, 1024):
                expected = [k for k in range(s) if k <= q and (window is None or q - k < window)]
                assert list(shapes.allowed_keys(q, s, window)) == expected
    assert list(shapes.allowed_keys(1024, 1025, 1024))[0] == 1
