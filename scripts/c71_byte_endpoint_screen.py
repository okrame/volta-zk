"""Fixed compiled coefficient path for the uncompressed original-byte tree.

This excludes one literal backend, not the relation or a factored replacement.
"""
import hashlib
import json
from pathlib import Path
import re
import sys

import c71_main_cell_screen as cfg
import c71_streaming_screen as streaming

EXPECTED_NINE = '38a9d8468072d750fe039cf29782e92b0e19ce5987dc6a2ab47d36e0e372ce67'

EXPECTED_SIX = 'c371abc7f454abbafc9200f45825d3f89ef880c617983d1599c84b8a31b2640b'

def screen(path, six=True):
    raw = Path(path).read_text()
    blocks = [b for b in raw.split('Function : ')
              if b.splitlines() and (b.splitlines()[0] == 'c71_byte_coeff6' if six
                                    else '12coeff_kernelE' in b.splitlines()[0])]
    cfg.require(len(blocks) == 1, 'expected exactly one original coefficient kernel')
    instructions = {int(m[1], 16): m[2].strip() for m in
                    re.finditer(r'/\*([0-9a-f]+)\*/\s+(.*?)\s*;\s*/\*', blocks[0])}
    digest = hashlib.sha256(json.dumps(sorted(instructions.items())).encode()).hexdigest()
    cfg.require(digest == (EXPECTED_SIX if six else EXPECTED_NINE), 'coefficient binary changed; review its path')
    if six:
        cfg.expect(instructions, 0x90, 'ISETP.GE.U32.AND P0, PT, R60, R3, PT')
        cfg.expect(instructions, 0xa0, 'ISETP.GE.U32.AND.EX P0, PT, R61, R5, PT, P0')
        cfg.expect(instructions, 0xb0, '@P0 EXIT')
        cfg.expect(instructions, 0x1b7e0, 'EXIT')
        begin, end, expected_wide = 0xc0, 0x1b7e0, 525
    else:
        cfg.expect(instructions, 0x170, 'ISETP.GE.U32.AND P0, PT, R2, R5, PT')
        cfg.expect(instructions, 0x190, 'ISETP.GE.U32.AND.EX P0, PT, R3, R7, PT, P0')
        cfg.expect(instructions, 0x1b0, '@P0 BRA 0x21110')
        cfg.expect(instructions, 0x21110, 'BSYNC B0')
        begin, end, expected_wide = 0x1c0, 0x21110, 774
    cfg.no_branch(instructions, begin, end, 'one active byte-tree coefficient pair')
    wide = len(cfg.register_only_wide(instructions, begin, end))
    cfg.require(wide == expected_wide, 'active coefficient path changed')
    other = streaming.dominant_cost_screen(streaming.base.b12_pcs_binding_assessment())
    cases = []
    for old, rest in zip((0, 150, 300), other['cases']):
        native = cfg.gkr.native_record(cfg.NATIVE_RECORD, 'EXP30', old)
        view = native['padded_cells'].bit_length()-1+4  # Original 16 byte lanes.
        # Eight fraction-tree layers, all MSB rounds: sum_h (2^(view+h)-1).
        # The LUT saves storage; the current sourcewise algorithm still visits
        # every coefficient pair. Do not charge its enormous replay here.
        pairs = 255*(1 << view)-8
        trace = cfg.gkr.byte_source_trace(view, 16)
        assert trace['counted_work']['cubic_multiplications'] == 27*pairs
        endpoint = wide*pairs/cfg.SCALAR_RESULT_CEILING
        disjoint = rest['range_merges_commit_FFT_first_openings_joint_lower_seconds']
        cases.append(dict(old_tokens=old, byte_view_bits=view, coefficient_pairs=pairs,
            register_only_IMAD_WIDE_U32=wide*pairs,
            byte_coefficient_lower_seconds_conditional=endpoint,
            disjoint_range_commit_open_lower_seconds_conditional=disjoint,
            T_proof_only_partial_lower_seconds_conditional=endpoint+disjoint,
            T_inference_measured=False,
            T_response_total_partial_lower_seconds_conditional=endpoint+disjoint,
            NO_GO_literal_serial_backend=endpoint+disjoint>65,
            full_response_work_counted=False))
    return dict(credit=False, gpu_execution=False, base_products_per_Fp3=6 if six else 9, instruction_sha256=digest,
        sass_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        register_only_IMAD_WIDE_U32_per_active_pair=wide, cases=cases,
        conditions=['same compiled factored scalar coefficient kernel and one visit per pair',
                    '132 SM, clock <=2 GHz, <=64 scalar INT multiply results/cycle/SM',
                    'same serial range/commit/first-opening schedule; no overlap credit'],
        omitted_positive_costs=['all inference', 'all getter replay/authentication',
            'all EXP30/RMS main-cell work including BMMA', 'byte-tree regeneration/folds',
            'PCG, remaining WHIR, MAC/FS, transfers and serialization'],
        not_a_universal_lower=True,
        next_control='factor the original-byte tree before another scalar port or H100 run')


if __name__ == '__main__':
    print(json.dumps(screen(sys.argv[1]), indent=2))
