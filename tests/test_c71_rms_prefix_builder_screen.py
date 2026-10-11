"""Public schedule checks; no synthetic count is hardware or protocol credit."""
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from c71_rms_prefix_builder_screen import builder_screen


def fixture():
    return dict(depth=1, input_width=128, original_gates_by_program=[[1, 0, 1], [0, 1, 0]],
                native_plan=dict(CPU_parallel_vs_original_layer_bitplane_parity=True,
                    programs=[dict(program=p, word_operations=p + 3,
                        parallel_plan_requested_bytes=256, parallel_shared_bytes_per_CTA=128)
                        for p in range(2)]))


def test_bounded_schedule_keeps_full_prefix_wires_and_charges_each_mask_batch():
    result = builder_screen(64, [[(0, 4), (60, 64)], [(4, 9)]], [fixture()])
    row = result['levels'][0]
    # Two public sections, each contains both programs; first has one suffix
    # position, second has three. All thirteen original source frames survive.
    assert row['work']['source_batches'] == 2
    assert row['work']['source_frames'] == 13
    assert row['work']['packed_DAG_word_operations'] == 2 * (3 + 4)
    assert row['work']['late_gate_Fp3_products'] == 2 * (256 + 16 + 256 + 16)
    assert row['work']['count_zero_bytes'] == 2 * (288 + 16 + 288) * 192 * 4
    assert row['payload']['chunk_raw_u32_counts'] == 288 * 192 * 4
    assert row['payload']['packed_original_wire_stage'] == 128 * 16 * 256 // 8
    assert row['payload']['merged_mask_Gram_and_linear'] == 3 * (256 + 16) * 24
    assert row['named_new_payload_bytes'] == sum(row['payload'].values())
    assert not result['credit'] and not result['complete_work'] and not result['joint_admitted']


def test_counts_stay_in_registers_across_the_sixteen_tiles_of_each_batch():
    result = builder_screen(131072, [[(0, 65536)], [(65536, 131072)]], [fixture()])
    work = result['levels'][0]['work']
    assert work['source_batches'] == 2  # 8192 suffixes, two full4096 batches.
    slots = 288 + 16 + 288
    assert work['count_read_write_logical_bytes'] == 3 * 2 * slots * 192 * 4
    assert work['count_zero_bytes'] == 2 * slots * 192 * 4


def test_builder_requires_original_depth_program_geometry_and_cpu_plan_parity():
    for key, value in [('input_width', 127), ('original_gates_by_program', [[1, 0, 1]]), ('depth', 2)]:
        bad = fixture(); bad[key] = value
        with pytest.raises(ValueError):
            builder_screen(64, [[(0, 4)], [(4, 8)]], [bad])
    bad = fixture(); bad['native_plan']['CPU_parallel_vs_original_layer_bitplane_parity'] = False
    with pytest.raises(ValueError):
        builder_screen(64, [[(0, 4)], [(4, 8)]], [bad])
