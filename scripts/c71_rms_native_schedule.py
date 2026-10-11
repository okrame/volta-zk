"""Count the implemented RMS GPU launch schedule; no capacity/time admission."""
import json
from pathlib import Path
import sys

from c71_rms_prefix_moments import geometry, support_sections
from c71_temporary_ledger import records


def native_schedule(padded_cells, intervals, levels, capacity=256):
    if (type(padded_cells) is not int or padded_cells < 32
            or padded_cells > 1 << 29 or padded_cells & (padded_cells - 1)
            or type(capacity) is not int or not 256 <= capacity <= 4096
            or capacity & (capacity - 1)):
        raise ValueError('native RMS domain or window capacity differs')
    shape = geometry(padded_cells, intervals, 4)
    sections = list(support_sections(padded_cells, intervals, 4))
    bits = padded_cells.bit_length() - 1
    pair_capacity = min(capacity // 16, 1 << (bits - 5))
    output = []
    for level in levels:
        counts = level['original_gates_by_program']
        width = level['input_width']
        if (type(width) is not int or not 1 <= width <= 16384
                or width & (width - 1) or len(counts) != len(intervals)
                or any(len(c) != 3 or any(type(v) is not int or v < 0 for v in c)
                       or not 1 <= sum(c) <= 16384 for c in counts)):
            raise ValueError('native RMS original gate census differs')
        chunks = [(sum(c) + 511) // 512 for c in counts]
        windows = prefix_launches = 0
        for first, end, masks in sections:
            if masks:
                batches = (end - first + capacity - 1) // capacity
                windows += batches
                # Gather, replay, transpose, Eq; three kernels per gate chunk.
                prefix_launches += batches * (4 + 3 * sum(chunks[p] for p, _ in masks))
        rounds = []
        for round_index in range(4, bits):
            half = padded_cells >> (round_index + 1)
            pairs = min(pair_capacity, half)
            pair_windows = half // pairs
            groups = 1 << (round_index - 4)
            group_batches = (groups + capacity // pairs - 1) // (capacity // pairs)
            source_windows = 2 * pair_windows * group_batches
            # Factors/LUT; suffix per pair window; gather/replay/fold per side;
            # gate evaluation/sum per chunk, selector per program; last terminal.
            launches = (2 + pair_windows * (1 + 6 * group_batches
                        + 2 * sum(chunks) + len(intervals))
                        + int(round_index + 1 == bits))
            rounds.append(dict(round=round_index, pair_windows=pair_windows,
                               group_batches=group_batches,
                               source_windows=source_windows, launches=launches,
                               padded_source_positions=2 * half * groups * 16))
        assert all(r['padded_source_positions'] == padded_cells for r in rounds)
        index_bits = width.bit_length() - 1
        index_launches = 6 * index_bits + 4
        cell_launches = prefix_launches + sum(r['launches'] for r in rounds)
        output.append(dict(depth=level['depth'], input_width=width,
                           prefix_windows=windows, prefix_launches=prefix_launches,
                           tail_rounds=rounds, cell_launches=cell_launches,
                           index_launches=index_launches,
                           cell_index_launches=cell_launches + index_launches,
                           tail_padded_source_positions=padded_cells * len(rounds),
                           index_private_requested_bytes=(40 * sum(map(sum, counts))
                               + 32 * len(intervals) + 48 * width
                               + 24 * (6 + 3 * ((sum(map(sum, counts)) + 255) // 256))),
                           tail_fold_requested_bytes=48 * pair_capacity * (width + len(intervals))))
    if not output or [r['depth'] for r in output] != list(range(1, len(output) + 1)):
        raise ValueError('native RMS depths incomplete or out of order')
    return dict(credit=False, gpu_execution=False, canonical_selected=False,
                complete_capacity=False, complete_work=False, joint_admitted=False,
                scope='Exact successful cell/index CUDA launch schedule for current bounded runtime; analytic counts, no time or physical admission',
                capacity=capacity, tail_pair_capacity=pair_capacity,
                public_geometry=shape, levels=output,
                total_cell_launches=sum(r['cell_launches'] for r in output),
                total_cell_index_launches=sum(r['cell_index_launches'] for r in output),
                total_tail_padded_source_positions=sum(r['tail_padded_source_positions'] for r in output),
                excludes=['byte/statistic kernels and original caller/PCS/AES/FS/MAC work',
                          'complete host/device simultaneous capacity and driver allowance',
                          'actual mapped/PCIe/HBM traffic, instruction counts and service rates',
                          'failure/cleanup paths and any runtime timing extrapolation'],
                logical_source_positions_are_not_measured_traffic=True)


if __name__ == '__main__':
    if len(sys.argv) not in (3, 4):
        raise ValueError('expected original support, census directory and optional capacity')
    support = json.loads(Path(sys.argv[1]).read_text())
    levels = sorted(records(Path(sys.argv[2]), 'C71_RMS_NATIVE_REPLAY_PLAN_SCREEN'),
                    key=lambda r: r['depth'])
    if len(levels) != 99 or len({r['recipes_blake3'] for r in levels}) != 1:
        raise ValueError('full pinned RMS original census missing')
    capacity = int(sys.argv[3]) if len(sys.argv) == 4 else 256
    print(json.dumps(native_schedule(support['padded_cells'], support['intervals'],
                                    levels, capacity), indent=2))
