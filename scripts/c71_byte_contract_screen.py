"""Fixed-width paired byte contraction: compiled conditional lower, no GPU run."""
import hashlib
import json
from pathlib import Path
import re
import sys

import c71_exp30_alternatives as alternatives
import c71_exp30_bmma as bmma
import c71_main_cell_screen as cfg

EXPECTED = '9a736c092dbb9dec9036b28880ab8c79bdef3da44173ccbf21798467a8c6b59f'
BASE = Path(__file__).resolve().parents[1]/'benchmarks/results/c71-native-streaming-2026-09-18-8ad3270ec1c9.json'


def screen(path):
    raw = Path(path).read_text()
    chunks = [b for b in raw.split('Function : ')
              if b.splitlines() and b.splitlines()[0] == 'c71_byte_contract_coeff']
    cfg.require(len(chunks) == 1, 'expected one contracted coefficient kernel')
    ops = {int(m[1],16):m[2].strip() for m in
           re.finditer(r'/\*([0-9a-f]+)\*/\s+(.*?)\s*;\s*/\*',chunks[0])}
    digest = hashlib.sha256(json.dumps(sorted(ops.items())).encode()).hexdigest()
    cfg.require(digest == EXPECTED, 'compiled contraction changed; review the paths again')
    cfg.expect(ops,0x180,'@P0 BRA 0x9e60')  # inactive pair bypass
    cfg.expect(ops,0x460,'@!P0 BRA 0x5860') # rank zero bypass
    cfg.expect(ops,0x5850,'@!P4 BRA 0x620') # one feature per iteration
    paths = []
    for begin,end,expected in ((0x620,0x5850,1315),(0x5860,0x9e60,1120)):
        cfg.no_branch(ops,begin,end,'contracted pair')
        instructions = [op for at,op in ops.items() if begin <= at < end]
        cfg.require(len(instructions)==expected and all(not op.startswith('@') for op in instructions),
                    'unconditional issue path changed')
        paths.append(dict(begin=begin,end=end,unconditional_instructions=expected,
                          register_only_wide=len(cfg.register_only_wide(ops,begin,end))))
    ranks = [4,8,16,17,9,5,3,2] # Selected constant-work slots, including zero padding.
    base = json.loads(BASE.read_text())['report']['response']['cases']
    cases = []
    for public,rest,moments in zip(alternatives.report()['cases'],base,bmma.report()['cases']):
        old = public['old_tokens']
        support = next(c for c in cfg.gkr.ratio_cases() if c['old_tokens']==old)
        pairs = sum(r['supported_pairs'] for r in support['rounds'])
        instructions = 12*pairs*(sum(ranks)*paths[0]['unconditional_instructions']
                                  +len(ranks)*paths[1]['unconditional_instructions'])
        wide = 12*pairs*(sum(ranks)*paths[0]['register_only_wide']+len(ranks)*paths[1]['register_only_wide'])
        coefficient = max(instructions/(132*4*32*2e9),wide/cfg.SCALAR_RESULT_CEILING)
        tail = next(v for v in public['variants'] if v['prefix_bits']==4)['unchanged_scalar_tail_lower_seconds']
        disjoint = rest['joint_partial_lower_seconds_with_FFT_and_leaf_read']
        prefix = moments['kernel_partial_lower_seconds_conditional']
        total = disjoint+tail+coefficient+prefix
        cases.append(dict(old_tokens=old,coefficient_issue_instructions=instructions,
            coefficient_register_only_wide=wide,coefficient_partial_compute_lower_seconds=coefficient,
            disjoint_getter_range_commit_first_opening_lower_seconds=disjoint,
            disjoint_scalar_main_tail_lower_seconds=tail,disjoint_BMMA_lower_seconds=prefix,
            T_proof_only_partial_lower_seconds=total,T_response_total_partial_lower_seconds=total,
            T_inference_measured=False,NO_GO_fixed_width_backend=total>65))
    return dict(credit=False,gpu_execution=False,instruction_sha256=digest,paths=paths,cases=cases,
        fixed_feature_slots=ranks,base_record_sha256=hashlib.sha256(BASE.read_bytes()).hexdigest(),
        conditions=['same fixed-width padded slots, twelve private lanes and compiled kernel',
                    '132 SM, clock <=2GHz, <=4 warp instruction issues/cycle/SM, <=64 INT multiply results/cycle/SM',
                    'unchanged serial range/FFT/getter/scalar-tail and BMMA screens; no overlap credit'],
        omitted=['inference','all Boolean producer replay','byte regeneration/folds/Eq/endpoint recovery',
                 'remaining PCS, PCG, hash, MAC/FS and serialization'],
        complete_work=False,complete_peak=False,complete_time=False,not_a_universal_lower=True)


if __name__ == '__main__':
    print(json.dumps(screen(sys.argv[1]),indent=2))
