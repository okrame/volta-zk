"""Conditional bounded four-round RMS builder schedule; no native admission."""
import json
from pathlib import Path
import sys

from c71_rms_prefix_moments import geometry, support_sections
from c71_temporary_ledger import records


def builder_screen(padded_cells, intervals, levels):
    bits, block, batch, gate_chunk = 4, 16, 4096, 32
    shape = geometry(padded_cells, intervals, bits)
    sections = list(support_sections(padded_cells, intervals, bits))
    capacity = min(batch, padded_cells // block)
    padded_capacity = (capacity + 255) // 256 * 256
    output = []
    for level in levels:
        counts = level['original_gates_by_program']
        plans = level['native_plan']['programs']
        if (len(counts) != len(intervals) or len(plans) != len(intervals)
                or [p['program'] for p in plans] != list(range(len(intervals)))
                or level['native_plan']['CPU_parallel_vs_original_layer_bitplane_parity'] is not True
                or not 1 <= level['input_width'] <= 16384
                or level['input_width'] & (level['input_width'] - 1)
                or any(len(c) != 3 or any(type(x) is not int or x < 0 for x in c) for c in counts)
                or any(p['word_operations'] < 0 or p['parallel_plan_requested_bytes'] < 0
                       or p['parallel_shared_bytes_per_CTA'] < 0 for p in plans)):
            raise ValueError('native RMS public census differs')
        binary = max(a + x for a, x, _ in counts)
        copies = max(c for _, _, c in counts)
        raw_slots = max(min(gate_chunk, binary) * (block * block + 2 * block),
                        min(gate_chunk, copies) * block)
        terms = dict(source_frames=0, packed_DAG_word_operations=0,
                     source_batches=0, original_suffix_Eq_products=0,
                     binary_BMMA_warp_instructions=0, late_gate_Fp3_products=0,
                     raw_count_shift_add_terms=0, count_zero_bytes=0,
                     count_read_write_logical_bytes=0)
        for start, end, masks in sections:
            if not masks:
                continue
            size = end - start
            full, remainder = divmod(size, batch)
            batches = full + bool(remainder)
            tiles = full * (batch // 256) + (remainder + 255) // 256
            terms['source_batches'] += batches
            terms['source_frames'] += size * sum(mask.bit_count() for _, mask in masks)
            terms['original_suffix_Eq_products'] += size
            # One replay/stage per source batch, reused across gate chunks.
            # Public program masks restrict consumers, never source wire positions.
            replay_groups = full * (batch // 4) + (remainder + 3) // 4
            for program, _ in masks:
                a, x, c = counts[program]
                slots = (a + x) * (block * block + 2 * block) + c * block
                terms['packed_DAG_word_operations'] += replay_groups * plans[program]['word_operations']
                terms['binary_BMMA_warp_instructions'] += (a + x) * 384 * tiles
                terms['late_gate_Fp3_products'] += batches * (a * block * block
                    + x * (block * block + block) + c * block)
                terms['raw_count_shift_add_terms'] += batches * slots * 192
                terms['count_zero_bytes'] += batches * slots * 192 * 4
                terms['count_read_write_logical_bytes'] += 2 * tiles * slots * 192 * 4
        assert terms['source_frames'] == shape['live_cells']
        suffix_bits = (padded_cells // block).bit_length() - 1
        high, low = suffix_bits // 2, suffix_bits - suffix_bits // 2
        tables = (1 << high) + (1 << low)
        terms['suffix_Eq_factor_table_products'] = 2 * tables - 4
        payload = dict(packed_original_wire_stage=level['input_width'] * block * padded_capacity // 8,
                       host_and_device_original_frame_windows=2 * 12 * block * capacity,
                       original_cell_and_assignment_window=16 * block * capacity,
                       native_public_plan_requested=sum(p['parallel_plan_requested_bytes'] for p in plans),
                       native_program_headers=32 * len(plans),
                       original_gate_maps_weights_flags=40 * sum(sum(c) for c in counts),
                       original_suffix_Eq_planes=192 * padded_capacity // 8,
                       original_Eq_factor_tables_and_point=(tables + suffix_bits) * 24,
                       chunk_raw_u32_counts=raw_slots * 192 * 4,
                       chunk_reduced_Fp3_moments=raw_slots * 24,
                       merged_mask_Gram_and_linear=shape['after_gate_weights_equal_masks_merged_payload_bytes'])
        output.append(dict(depth=level['depth'], input_width=level['input_width'],
                           named_new_payload_bytes=sum(payload.values()), payload=payload, work=terms,
                           shared_per_CTA_max_bytes=max(p['parallel_shared_bytes_per_CTA'] for p in plans)))
    if not output or [x['depth'] for x in output] != list(range(1, len(output) + 1)):
        raise ValueError('native RMS depths incomplete or out of order')
    return dict(credit=False, gpu_execution=False, canonical_selected=False,
                prefix_bits=bits, suffix_batch_capacity=batch, gate_chunk_capacity=gate_chunk,
                public_geometry=shape, levels=output,
                scope='Conditional four-round schedule: replay once per suffix batch, reuse stage across gate chunks, reduce/weight counts every chunk and batch; caller unchanged and no GPU caller implemented',
                complete_capacity=False, complete_work=False, joint_admitted=False,
                excludes=['native parallel-plan construction/transients and allocator metadata',
                          'common caller/model/CompactFrames/proof/correlations/Writer/PCS owners',
                          'prefix coefficient evaluation and unchanged tail fold/core/index/byte work',
                          'Copy/Xor-linear consumer instruction schedule, sorting, source gather and kernel time',
                          'whole-device runtime/physical peak and actual traffic/service rates'],
                lifetime='One depth; all source/chunk/aggregate buffers fence and retire before index/byte phases. Gate chunks share immutable original Boolean staging; no additional producer replay per gate chunk.',
                logical_bytes_are_not_measured_HBM=True)


if __name__ == '__main__':
    support = json.loads(Path(sys.argv[1]).read_text())
    levels = sorted(records(Path(sys.argv[2]), 'C71_RMS_NATIVE_REPLAY_PLAN_SCREEN'), key=lambda x: x['depth'])
    if len(levels) != 99 or len({x['recipes_blake3'] for x in levels}) != 1:
        raise ValueError('full pinned RMS plan census missing')
    print(json.dumps(builder_screen(support['padded_cells'], support['intervals'], levels), indent=2))
