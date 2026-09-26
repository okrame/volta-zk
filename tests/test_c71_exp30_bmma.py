from random import Random
import subprocess
from test_c71_whir_trace import Fp3
import c71_exp30_alternatives as alt
import c71_exp30_bmma as bm


def test_moments_match_original_pattern_cubics_with_public_masks():
    rng=Random(710256)
    for bits in (2,3,4):
        block=1<<bits
        live=[j<block-1-k%2 and k!=3 for j in range(block) for k in range(4)]
        rows=[[rng.randrange(2) if live[i] else 0 for _ in range(4)] for i in range(block*4)]
        gates=[('And',0,1),('Xor',1,2),('Copy',3,3),('And',2,2)]
        weights=[Fp3(2+i,7,9) for i in range(4)]
        point=[Fp3(3+i,2,5) for i in range(bits+2)]
        gram=bm.moments(rows,live,gates,weights,point,bits)
        bins=alt.pattern_histogram(rows,live,gates,weights,point,bits,4)
        for challenges in ([Fp3(0)]*bits,[Fp3(1)]*bits,[Fp3(4+i,3,9) for i in range(bits)]):
            for r in range(bits):
                for trial in [Fp3(i) for i in range(4)]+[Fp3(9,2,4)]:
                    assert bm.moment_round_value(gram,point[:bits],challenges[:r],trial)==alt.pattern_round_value(bins,point[:bits],challenges[:r],trial,4)


def test_exact_bitplane_reconstruction_and_ptx_fragment_map(tmp_path):
    binary=tmp_path/'bmma-host'
    subprocess.run(['c++','-x','c++','-std=c++17','-O2','-Wall','-Wextra','-Werror',
                    'cuda/c71_exp30_bmma.cu','-o',str(binary)],check=True,timeout=60)
    result=subprocess.run([str(binary)],text=True,capture_output=True,check=True,timeout=10)
    assert '"host_exact_gram_and_fragments":true' in result.stdout
    assert '"gpu_execution":false' in result.stdout


def test_candidate_arena_preserves_margin_and_releases_count_planes(tmp_path):
    import c71_arena_plan as arena
    report=arena.report(ordered_getter=True,reuse_reader_for_commit=True,exp30_bmma=True)
    binary=tmp_path/'arena'
    subprocess.run(['c++','-std=c++17','-O2','-Wall','-Wextra','-Werror',
                    'cuda/c71_arena_preflight.cpp','-o',str(binary)],check=True,timeout=60)
    for case in report['cases']:
        assert case['all_chain_layouts_fit_margin']
        p=case['address_layouts']['EXP30_maximum_original_bytes']
        assert p['fits_with_operational_margin'] and not p['device_allocation_measured']
        stages=[e for e in p['events'] if 'producer_consumer_batches' in e['event']]
        assert len(stages)==94
        assert all(any(':count_bytes' in name for name,_,_ in e['allocate']) for e in stages)
        ids={};lines=[]
        def index(k):
            # Native handles are reused after each layer's release fence.
            if k.startswith('EXP30_BMMA_layer_'):k='BMMA:'+k.split(':',1)[1]
            if k not in ids:ids[k]=len(ids)
            return ids[k]
        for k,offset,size in p['initial_allocations']:lines.append(f'A {index(k)} {offset} {size}')
        for event in p['events']:
            for k in event['free']:lines.append(f'F {index(k)} 1 0')
            for k,offset,size in event['allocate']:lines.append(f'A {index(k)} {offset} {size}')
        result=subprocess.run([str(binary)],input='\n'.join(lines)+'\n',text=True,
                              capture_output=True,check=True,timeout=10)
        assert int(result.stdout.split()[0])==p['address_high_water_bytes']
