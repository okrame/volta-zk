"""Analytic launch schedule of the original RMS batching candidates."""
import json
from pathlib import Path
import sys

from c71_rms_native_schedule import native_schedule
from c71_rms_prefix_moments import support_sections
from c71_temporary_ledger import records


def batched_schedule(padded_cells, intervals, levels, capacity=256, reduce_tail=True):
    if type(reduce_tail) is not bool:
        raise ValueError('tail reduction selector differs')
    result = native_schedule(padded_cells, intervals, levels, capacity)
    sections = list(support_sections(padded_cells, intervals, 4))
    pair_capacity = result['tail_pair_capacity']
    for level, row in zip(levels, result['levels']):
        counts = level['original_gates_by_program']
        launches = 0
        for first, end, masks in sections:
            if masks:
                gates = sum(sum(counts[p]) for p, _ in masks)
                launches += ((end - first + capacity - 1) // capacity
                             * (4 + 3 * ((gates + 511) // 512)))
        assert launches <= row['prefix_launches']
        row['prefix_launches'] = launches
        if reduce_tail:
            ctas = 0
            for round_record in row['tail_rounds']:
                r = round_record['round']
                pairs = min(pair_capacity, padded_cells >> (r + 1))
                round_record['launches'] = (2 + round_record['pair_windows']
                    * (3 + 6 * round_record['group_batches'])
                    + int(r + 1 == padded_cells.bit_length() - 1))
                ctas += len(intervals) * pairs * round_record['pair_windows']
            row['tail_program_CTAs'] = ctas
            row['tail_program_values_requested_bytes'] = len(intervals) * pair_capacity * 4 * 24
            row['tail_original_gate_ranges_requested_bytes'] = len(intervals) * 8
        row['cell_launches'] = launches + sum(r['launches'] for r in row['tail_rounds'])
        row['cell_index_launches'] = row['cell_launches'] + row['index_launches']
        row['prefix_host_and_device_window_plan_requested_bytes'] = 2 * len(intervals) * 16
    result['total_cell_launches'] = sum(r['cell_launches'] for r in result['levels'])
    result['total_cell_index_launches'] = sum(r['cell_index_launches'] for r in result['levels'])
    result['tail_program_reduced'] = reduce_tail
    result['scope'] = 'Analytic original RMS batched-prefix/tail candidate launch schedule; requires exact clean-SHA GPU counter comparison, no time/physical admission'
    return result


if __name__ == '__main__':
    if len(sys.argv) not in (3, 4, 5):
        raise ValueError('expected original support, census directory, optional capacity and prefix/cell stage')
    support = json.loads(Path(sys.argv[1]).read_text())
    levels = sorted(records(Path(sys.argv[2]), 'C71_RMS_NATIVE_REPLAY_PLAN_SCREEN'),
                    key=lambda r: r['depth'])
    if len(levels) != 99 or len({r['recipes_blake3'] for r in levels}) != 1:
        raise ValueError('full pinned RMS original census missing')
    capacity = int(sys.argv[3]) if len(sys.argv) >= 4 else 256
    stage = sys.argv[4] if len(sys.argv) == 5 else 'cell'
    if stage not in ('prefix', 'cell'):
        raise ValueError('expected prefix or cell stage')
    print(json.dumps(batched_schedule(support['padded_cells'], support['intervals'],
                                     levels, capacity, stage == 'cell'), indent=2))
