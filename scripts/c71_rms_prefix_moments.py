"""Mixed-program RMS prefix identity and public geometry; no native credit."""
import json
from pathlib import Path
import sys

from c71_exp30_alternatives import equality


def support_sections(padded_cells, intervals, bits):
    """Project original disjoint program spans onto the MSB-prefix suffix."""
    if (not 1 <= padded_cells <= 1 << 29 or padded_cells & (padded_cells - 1)
            or not 1 <= bits <= 8 or 1 << bits > padded_cells
            or not 1 <= len(intervals) <= 421 or sum(map(len, intervals)) > 16384):
        raise ValueError("RMS prefix geometry differs")
    spans = sorted((a, z, p) for p, ranges in enumerate(intervals) for a, z in ranges)
    if any(not 0 <= a < z <= padded_cells for a, z, _ in spans):
        raise ValueError("RMS support span outside original domain")
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        raise ValueError("RMS program support overlaps")
    suffix = padded_cells >> bits
    events = {0: [], suffix: []}
    for a, z, p in spans:
        for j in range(a // suffix, (z - 1) // suffix + 1):
            lo, hi = max(a, j * suffix) - j * suffix, min(z, (j + 1) * suffix) - j * suffix
            events.setdefault(lo, []).append((p, j, True))
            events.setdefault(hi, []).append((p, j, False))
    masks = [0] * len(intervals)
    boundaries = sorted(events)
    for at, end in zip(boundaries, boundaries[1:]):
        for p, j, on in events[at]:
            if on:
                masks[p] |= 1 << j
            else:
                masks[p] &= ~(1 << j)
        yield at, end, tuple((p, mask) for p, mask in enumerate(masks) if mask)


def geometry(padded_cells, intervals, bits):
    pairs, vectors, selector_masks = set(), set(), set()
    sections = live_sections = live_cells = max_programs = 0
    for start, end, masks in support_sections(padded_cells, intervals, bits):
        sections += 1
        live_sections += bool(masks)
        pairs.update(masks)
        selector_masks.update(mask for _, mask in masks)
        vectors.add(masks)
        max_programs = max(max_programs, len(masks))
        live_cells += (end - start) * sum(mask.bit_count() for _, mask in masks)
    assert live_cells == sum(z - a for ranges in intervals for a, z in ranges)
    block = 1 << bits
    return dict(prefix_bits=bits, suffix_cells=padded_cells >> bits,
                event_sections=sections, live_sections=live_sections,
                distinct_program_masks=len(pairs), distinct_assignment_vectors=len(vectors),
                distinct_selector_masks=len(selector_masks),
                max_programs_per_section=max_programs, live_cells=live_cells,
                aggregate_gram_and_linear_Fp3_payload_bytes=len(pairs) * (block * block + block) * 24,
                after_gate_weights_equal_masks_merged_payload_bytes=len(selector_masks) * (block * block + block) * 24,
                complete_capacity=False, complete_work=False, credit=False)


def mixed_moments(rows, assignments, programs, weights, point, bits):
    """Small algebra oracle, before current cell coins; not a production builder.

    Gate weights are applied on each source here. A native builder must account
    for those products, or for the retained gate axis if applying weights late.
    Rows at *other* programs' positions contribute to the original folded wires.
    The program mask restricts only the selector, never those wire values.
    """
    n, block = len(rows), 1 << bits
    if (n != 1 << len(point) or not 0 < bits <= len(point)
            or len(assignments) != n or not programs or not rows[0]
            or any(len(row) != len(rows[0]) or any(v not in (0, 1) for v in row) for row in rows)
            or any(p is not None and not 0 <= p < len(programs) for p in assignments)
            or any(p is None and any(row) for p, row in zip(assignments, rows))
            or any(len(gates) > len(weights) for gates in programs)
            or any(op not in ('And', 'Xor', 'Copy') or not 0 <= x < len(rows[0])
                   or not 0 <= y < len(rows[0]) or (op == 'Copy' and x != y)
                   for gates in programs for op, x, y in gates)):
        raise ValueError("RMS moment oracle geometry differs")
    suffix = n // block
    moments = {}
    for k, position_weight in enumerate(equality(point[bits:])):
        for p, gates in enumerate(programs):
            mask = tuple(assignments[j * suffix + k] == p for j in range(block))
            if not any(mask):
                continue
            if mask not in moments:
                moments[mask] = ([[0] * block for _ in range(block)], [0] * block)
            gram, linear = moments[mask]
            for (op, x, y), gate_weight in zip(gates, weights):
                weight = position_weight * gate_weight
                xs = [rows[j * suffix + k][x] for j in range(block)]
                ys = [rows[j * suffix + k][y] for j in range(block)]
                for i in range(block):
                    if op in ('Copy', 'Xor'):
                        linear[i] += weight * (xs[i] + (ys[i] if op == 'Xor' else 0))
                    if op != 'Copy':
                        for j in range(block):
                            gram[i][j] += weight * xs[i] * ys[j] * (-2 if op == 'Xor' else 1)
    return moments


if __name__ == '__main__':
    path = Path(sys.argv[1])
    source = json.loads(path.read_text())
    print(json.dumps(dict(scope='Public mixed-program selector projection only; excludes raw counts, replay, native builder, complete accounting and hardware',
                          credit=False, gpu_execution=False,
                          cases=[geometry(source['padded_cells'], source['intervals'], bits)
                                 for bits in range(2, 9)]), indent=2))
