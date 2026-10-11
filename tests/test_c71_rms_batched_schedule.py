import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from c71_rms_batched_schedule import batched_schedule
from c71_temporary_ledger import records
from test_c71_rms_native_schedule import dense_gpu_oracle_geometry


def prefix_gpu_record():
    result = json.loads((ROOT / 'benchmarks/results/c71-certificates-rms-gate-batch-2026-10-11-f868468e.json').read_text())
    assert result['source_git_sha'] == 'f868468ed05d6822e9d41206023f62afaacc6591'
    assert result['git_dirty'] is False
    return result


def test_batched_prefix_matches_original_dense_gpu_oracle_counter():
    intervals, levels = dense_gpu_oracle_geometry()
    result = batched_schedule(16384, intervals, levels, reduce_tail=False)
    actual = prefix_gpu_record()['components']['gpu-cell-tail-coefficients'][0]
    assert actual['original_dense_coefficients_and_terminal']
    assert 2 * result['total_cell_launches'] == actual['stats']['launches'] == 7326


def test_batched_prefix_matches_all159_original_depths_actual_counter():
    census = ROOT / 'benchmarks/results/c71-certificates-rms-moments-census-2026-10-11-dc0064d7'
    levels = sorted(records(census, 'C71_RMS_NATIVE_REPLAY_PLAN_SCREEN'), key=lambda r: r['depth'])
    assert len(levels) == 99
    intervals = [[] for _ in range(159)]
    for cell in range(511):
        intervals[cell % 159].append((cell, cell + 1))
    result = batched_schedule(512, intervals, levels, reduce_tail=False)
    actual = prefix_gpu_record()['components']['gpu-mixed-all'][0]
    assert actual['same_FS_original_MAC_endpoint'] and actual['all_original_layers_executed']
    assert result['total_cell_index_launches'] == actual['native_stats']['launches'] == 707364


def test_program_reduction_preserves_all_source_visits():
    intervals, levels = dense_gpu_oracle_geometry()
    before = batched_schedule(16384, intervals, levels, reduce_tail=False)
    after = batched_schedule(16384, intervals, levels)
    assert after['total_cell_index_launches'] < before['total_cell_index_launches']
    assert after['total_tail_padded_source_positions'] == before['total_tail_padded_source_positions']
    for old, new in zip(before['levels'], after['levels']):
        assert old['prefix_windows'] == new['prefix_windows']
        assert old['index_launches'] == new['index_launches']
        assert [r['source_windows'] for r in old['tail_rounds']] == [r['source_windows'] for r in new['tail_rounds']]
    assert not after['credit'] and not after['complete_work'] and not after['joint_admitted']


def test_program_reduction_matches_original_dense_gpu_counter():
    result = json.loads((ROOT / 'benchmarks/results/c71-certificates-rms-tail-reduce-2026-10-11-c0e0448d.json').read_text())
    assert result['source_git_sha'] == 'c0e0448d4ddb424736fffcf6731ffacd5b91d3bd'
    assert result['git_dirty'] is False
    intervals, levels = dense_gpu_oracle_geometry()
    schedule = batched_schedule(16384, intervals, levels)
    actual = result['components']['gpu-cell-tail-coefficients'][0]
    assert actual['original_dense_coefficients_and_terminal']
    assert 2 * schedule['total_cell_launches'] == actual['stats']['launches']


def test_program_reduction_matches_all159_original_depths_gpu_counter():
    result = json.loads((ROOT / 'benchmarks/results/c71-certificates-rms-tail-reduce-2026-10-11-c0e0448d.json').read_text())
    census = ROOT / 'benchmarks/results/c71-certificates-rms-moments-census-2026-10-11-dc0064d7'
    levels = sorted(records(census, 'C71_RMS_NATIVE_REPLAY_PLAN_SCREEN'), key=lambda r: r['depth'])
    assert len(levels) == 99
    intervals = [[] for _ in range(159)]
    for cell in range(511):
        intervals[cell % 159].append((cell, cell + 1))
    schedule = batched_schedule(512, intervals, levels)
    actual = result['components']['gpu-mixed-all'][0]
    assert actual['same_FS_original_MAC_endpoint'] and actual['all_original_layers_executed']
    assert schedule['total_cell_index_launches'] == actual['native_stats']['launches'] == 280299
