"""Fixed-width paired byte contraction: compiled conditional lower, no GPU run."""
import hashlib
import json
from pathlib import Path
import re
import sys

import c71_exp30_alternatives as alternatives
import c71_exp30_bmma as bmma
import c71_main_cell_screen as cfg
import c71_streaming_screen as streaming

EXPECTED = '9a736c092dbb9dec9036b28880ab8c79bdef3da44173ccbf21798467a8c6b59f'
CARRY_EXPECTED = 'f5d85fa90322198478978a5d755f1b80f8dec65c0aab2b388e9a1966799c75f9'
BASE = Path(__file__).resolve().parents[1]/'benchmarks/results/c71-native-streaming-2026-09-18-8ad3270ec1c9.json'


def screen(path):
    raw = Path(path).read_text()
    chunks = [b for b in raw.split('Function : ')
              if b.splitlines() and b.splitlines()[0] == 'c71_byte_contract_coeff']
    cfg.require(len(chunks) == 1, 'expected one contracted coefficient kernel')
    ops = {int(m[1],16):m[2].strip() for m in
           re.finditer(r'/\*([0-9a-f]+)\*/\s+(.*?)\s*;\s*/\*',chunks[0])}
    digest = hashlib.sha256(json.dumps(sorted(ops.items())).encode()).hexdigest()
    cfg.require(digest in (EXPECTED,CARRY_EXPECTED), 'compiled contraction changed; review the paths again')
    carry = digest == CARRY_EXPECTED
    if carry:
        cfg.expect(ops,0x170,'@P0 BRA 0x74c0')
        cfg.expect(ops,0x470,'@!P0 BRA 0x4150')
        cfg.expect(ops,0x4140,'@!P3 BRA 0x620')
        intervals = ((0x620,0x4140,946),(0x4150,0x74c0,823))
    else:
        cfg.expect(ops,0x180,'@P0 BRA 0x9e60')
        cfg.expect(ops,0x460,'@!P0 BRA 0x5860')
        cfg.expect(ops,0x5850,'@!P4 BRA 0x620')
        intervals = ((0x620,0x5850,1315),(0x5860,0x9e60,1120))
    paths = []
    for begin,end,expected in intervals:
        cfg.no_branch(ops,begin,end,'contracted pair')
        instructions = [op for at,op in ops.items() if begin <= at < end]
        cfg.require(len(instructions)==expected and all(not op.startswith('@') for op in instructions),
                    'unconditional issue path changed')
        paths.append(dict(begin=begin,end=end,unconditional_instructions=expected,
                          register_only_wide=len(cfg.register_only_wide(ops,begin,end))))
    primitives = {}
    if carry:
        # These changed too: replacing the old range cost is mandatory.
        for name,digest_expected,begin,end,expected in (
            ('cost_leaf_pair_kernel','a06dc4df0d6d1e98ed9a0b4cef9e43ca94e8d3527576672253f2d9cf2c986785',0xc0,0xc60,197),
            ('cost_merge6_kernel','22619f6c8523fba18f7e04bb2c0444d112651fc0d438508a41e5c2e75c221f7f',0xc0,0x37a0,889),
            ('c71_gkr_main_cell_fused','1bb6e5a5a9e68bee7875f6c8bacba5a844de7ed56fca7c2d79b36d11569efbbf',0,0,0)):
            blocks=[b for b in raw.split('Function : ') if b.splitlines() and name in b.splitlines()[0]]
            cfg.require(len(blocks)==1,'missing carry primitive '+name)
            code={int(m[1],16):m[2].strip() for m in re.finditer(r'/\*([0-9a-f]+)\*/\s+(.*?)\s*;\s*/\*',blocks[0])}
            cfg.require(hashlib.sha256(json.dumps(sorted(code.items())).encode()).hexdigest()==digest_expected,
                        'carry primitive changed: '+name)
            if expected:
                cfg.no_branch(code,begin,end,name)
                count=sum(not op.startswith('@') and 'NOP' not in op for at,op in code.items() if at<end)
                cfg.require(count==expected,'range primitive count changed')
                primitives[name]=dict(instruction_sha256=digest_expected,unconditional_instructions=count)
            else:
                counts=[]
                for lo,hi in ((0x5c0,0x4cb0),(0x4cc0,0x8010),(0x8020,0xbf10),(0xbf20,0xe300),(0xe8b0,0x155b0)):
                    cfg.no_branch(code,lo,hi,'carry scalar tail')
                    counts.append(len(cfg.register_only_wide(code,lo,hi)))
                cfg.require(counts==[118,90,90,57,180],'scalar tail changed')
                cfg.require(min((counts[0]+counts[1])//7,(counts[0]+counts[2])//7,counts[3]//2,counts[4]//6)>=24,
                            'old scalar-tail lower does not transfer')
                primitives[name]=dict(instruction_sha256=digest_expected,wide_paths=counts,certified_wide_per_Fp3=24)
        range_work=streaming.dominant_cost_screen(streaming.base.b12_pcs_binding_assessment())
    ranks = [4,8,16,17,9,5,3,2] # Selected constant-work slots, including zero padding.
    base = json.loads(BASE.read_text())['report']['response']['cases']
    cases = []
    supports={c['old_tokens']:c for c in cfg.gkr.ratio_cases()}
    for slot,(public,rest,moments) in enumerate(zip(alternatives.report()['cases'],base,bmma.report()['cases'])):
        old = public['old_tokens']
        support = supports[old]
        pairs = sum(r['supported_pairs'] for r in support['rounds'])
        instructions = 12*pairs*(sum(ranks)*paths[0]['unconditional_instructions']
                                  +len(ranks)*paths[1]['unconditional_instructions'])
        wide = 12*pairs*(sum(ranks)*paths[0]['register_only_wide']+len(ranks)*paths[1]['register_only_wide'])
        coefficient = max(instructions/(132*4*32*2e9),wide/cfg.SCALAR_RESULT_CEILING)
        tail = next(v for v in public['variants'] if v['prefix_bits']==4)['unchanged_scalar_tail_lower_seconds']
        disjoint = rest['joint_partial_lower_seconds_with_FFT_and_leaf_read']
        range_saved = 0
        if carry:
            parts=(range_work['range_W'],range_work['cases'][slot]['range_A'])
            range_saved=sum(x['leaf_pairs']*(231-197)+x['internal_mul6_merges']*(1183-889) for x in parts)/(132*4*32*2e9)
            disjoint -= range_saved
        prefix = moments['kernel_partial_lower_seconds_conditional']
        total = disjoint+tail+coefficient+prefix
        cases.append(dict(old_tokens=old,coefficient_issue_instructions=instructions,
            replaced_range_issue_lower_seconds=range_saved,
            coefficient_register_only_wide=wide,coefficient_partial_compute_lower_seconds=coefficient,
            disjoint_getter_range_commit_first_opening_lower_seconds=disjoint,
            disjoint_scalar_main_tail_lower_seconds=tail,disjoint_BMMA_lower_seconds=prefix,
            T_proof_only_partial_lower_seconds=total,T_response_total_partial_lower_seconds=total,
            T_inference_measured=False,NO_GO_fixed_width_backend=total>65))
    return dict(credit=False,gpu_execution=False,instruction_sha256=digest,paths=paths,cases=cases,carry_primitives=primitives,
        fixed_feature_slots=ranks,base_record_sha256=hashlib.sha256(BASE.read_bytes()).hexdigest(),
        conditions=['same fixed-width padded slots, twelve private lanes and compiled kernel',
                    '132 SM, clock <=2GHz, <=4 warp instruction issues/cycle/SM, <=64 INT multiply results/cycle/SM',
                    'named serial range/FFT/getter/scalar-tail and BMMA screens; carry replaces range and recertifies scalar tail; no overlap credit'],
        omitted=['inference','all Boolean producer replay','byte regeneration/folds/Eq/endpoint recovery',
                 'remaining PCS, PCG, hash, MAC/FS and serialization'],
        complete_work=False,complete_peak=False,complete_time=False,not_a_universal_lower=True)


if __name__ == '__main__':
    print(json.dumps(screen(sys.argv[1]),indent=2))
