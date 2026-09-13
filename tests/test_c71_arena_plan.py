import subprocess
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_arena_plan as arena


def test_native_offsets_margin_and_fenced_release(tmp_path):
    binary=tmp_path/'arena'
    subprocess.run(['c++','-std=c++17','-O2','-Wall','-Wextra','-Werror',
                    'cuda/c71_arena_preflight.cpp','-o',str(binary)],check=True,timeout=60)
    report=arena.report()
    for case in report['cases']:
        assert case['all_chain_layouts_fit_margin']
        for plan in case['address_layouts'].values():
            ids={};lines=[]
            def index(key):
                if key not in ids:ids[key]=len(ids)
                return ids[key]
            for key,offset,size in plan['initial_allocations']:
                lines.append(f'A {index(key)} {offset} {size}')
            for event in plan['events']:
                for key in event['free']:lines.append(f'F {index(key)} 1 0')
                for key,offset,size in event['allocate']:lines.append(f'A {index(key)} {offset} {size}')
            result=subprocess.run([str(binary)],input='\n'.join(lines)+'\n',text=True,capture_output=True,timeout=10)
            assert result.returncode==0,result.stderr
            high,live,metadata=map(int,result.stdout.split())
            assert high==plan['address_high_water_bytes']
            assert metadata<128<<20
            assert high+arena.MARGIN<=arena.response.ARENA
    for bad in ('A 0 0 256\nA 1 0 256\n','A 0 0 256\nF 0 0 0\n','A 0 0',
                f'A 0 0 {arena.response.ARENA}\n'):
        assert subprocess.run([str(binary)],input=bad,text=True,capture_output=True).returncode!=0


def test_lifetime_and_inplace_tail_release():
    with pytest.raises(ValueError):arena.whir.trace(34,initial_coset_rows=3)
    events=[{'event':'retain','allocate':{'retained:S1':1024}},
        {'event':'fold_and_fence','free':['retained:S1'],'allocate':{'retained:S2':256}}]
    plan=arena.place_events(events,{'root':256})
    assert plan['events'][0]['allocate'][0][1]==plan['events'][1]['allocate'][0][1]
    assert plan['events'][-1]['live_aligned_bytes']==512
    with pytest.raises(ValueError):arena.place_events([{'event':'bad','free':['absent']}],{})


def test_odd_log_fft_parity_scatter_preserves_natural_order():
    # N=32=2*4^2: two existing square transforms, then an in-place merge.
    # This checks the memory-saving layout identity, not a CUDA adapter.
    p=97;n=32;root=pow(5,3,p)
    values=[(i*i+7*i+3)%p for i in range(n)]
    def dft(v,w):return [sum(x*pow(w,i*k,p) for i,x in enumerate(v))%p for k in range(len(v))]
    even=dft(values[::2],root*root%p);odd=dft(values[1::2],root*root%p)
    merged=[(even[k]+pow(root,k,p)*odd[k])%p for k in range(n//2)]
    merged +=[(even[k]-pow(root,k,p)*odd[k])%p for k in range(n//2)]
    assert merged==dft(values,root)
