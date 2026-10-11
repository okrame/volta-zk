from pathlib import Path
import sys

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
from c71_rms_native_schedule import native_schedule


def test_launch_count_matches_preserved_real_gpu_coefficient_oracle():
    # The real GPU oracle uses these original dyadic tiles, three depths,
    # and two challenge series. Its immutable counter is 7,830 launches.
    tiles = []
    for p, count in enumerate([8193, 4877, 3307]):
        col = 0
        while col < count:
            size = 1 << ((count - col).bit_length() - 1)
            tiles.append((size, p, col))
            col += size
    intervals = [[], [], []]
    cursor = 0
    for size, p, col in sorted(tiles, key=lambda t: (-t[0], t[1], t[2])):
        intervals[p].append((cursor, cursor + size))
        cursor += size
    levels = [dict(depth=i, input_width=w, original_gates_by_program=c)
              for i, w, c in [(1, 128, [[1, 1, 1], [1, 1, 1], [0, 0, 1]]),
                             (2, 4, [[0, 1, 1], [0, 1, 1], [0, 0, 1]]),
                             (3, 2, [[0, 1, 0], [0, 1, 0], [0, 0, 1]])]]
    result = native_schedule(16384, intervals, levels)
    assert 2 * result['total_cell_launches'] == 7830
    assert result['total_tail_padded_source_positions'] == 3 * 10 * 16384
    assert not result['credit'] and not result['complete_capacity']


def test_canonical_tail_revisits_every_padded_position_each_round():
    level = [dict(depth=1, input_width=128,
                  original_gates_by_program=[[1, 1, 1], [0, 0, 1]])]
    result = native_schedule(1 << 29, [[(0, 1 << 28)], [(1 << 28, 347937024)]], level)
    assert result['total_tail_padded_source_positions'] == 25 * (1 << 29)
    assert all(r['padded_source_positions'] == 1 << 29 for r in result['levels'][0]['tail_rounds'])
    wider = native_schedule(1 << 29, [[(0, 1 << 28)], [(1 << 28, 347937024)]], level, 4096)
    assert wider['total_cell_index_launches'] < result['total_cell_index_launches']
    assert wider['total_tail_padded_source_positions'] == result['total_tail_padded_source_positions']


@pytest.mark.parametrize('cells,capacity,width,gates', [(16, 256, 128, [1, 0, 0]),
    (512, 128, 128, [1, 0, 0]), (512, 256, 127, [1, 0, 0]),
    (512, 256, 128, [0, 0, 0]), (512, 256, 128, [-1, 1, 1])])
def test_rejects_geometry_outside_current_runtime(cells, capacity, width, gates):
    with pytest.raises(ValueError):
        native_schedule(cells, [[(0, cells - 1)]],
                        [dict(depth=1, input_width=width, original_gates_by_program=[gates])], capacity)
