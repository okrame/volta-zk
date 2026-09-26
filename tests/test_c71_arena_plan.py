import subprocess
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_arena_plan as arena


@pytest.mark.parametrize('ordered,reuse',[(False,False),(True,False),(True,True)])
def test_native_offsets_margin_and_fenced_release(tmp_path,ordered,reuse):
    binary=tmp_path/'arena'
    subprocess.run(['c++','-std=c++17','-O2','-Wall','-Wextra','-Werror',
                    'cuda/c71_arena_preflight.cpp','-o',str(binary)],check=True,timeout=60)
    report=arena.report(ordered_getter=ordered,reuse_reader_for_commit=reuse)
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


def test_seed6_guard_cggm_and_split_remain_live_through_equality():
    case=arena.report(ordered_getter=True,reuse_reader_for_commit=True)['cases'][0]
    for role,inverse,private in [('prover','verifier',329400),('verifier','prover',32400)]:
        plan=case['address_layouts'][f'Seed6_{role}_then_{inverse}_outer_pending']
        names=[event['event'] for event in plan['events']]
        assert names.index('main_seal')<names.index('roleswap_seal')<names.index('freeze_guard_corrections_outer_FS_pending')
        live={key:size for key,_,size in plan['initial_allocations']}
        for event in plan['events']:
            for key in event['free']:live.pop(key)
            live.update({key:size for key,_,size in event['allocate']})
        assert live['Seed6:cggm_private']>=private
        assert live['Seed6:c_wire']>=307800 and live['Seed6:z_wire']>=16200
        assert live['Seed6:split_values']>=16200
        assert live['Seed6:equality_payload_envelope']>=64800
        assert live['Seed6:coin_native_value_slot']>=4096
        assert live['Seed6:main'] and live['Seed6:roleswap'] and live['Seed6:main_equality_tail']
        assert 'Seed6:cggm_temporary' not in live and 'Seed6:H_codec' not in live
        assert plan['fits_with_operational_margin']


def test_reader_release_never_moves_roots_and_row_digest_overwrite_is_disjoint():
    # Address identity only; the hash callback is not a B12 codec refinement.
    import hashlib
    import struct
    plan=arena.place_events([
        {'event':'release_reader_fence','free':['reader_hash_slot']},
        {'event':'commit','allocate':{'coset':2048}},
        {'event':'commit_fence','free':['coset']},
        {'event':'restore_reader','allocate':{'reader_hash_slot':1024}},
    ],{'root':512,'reader_hash_slot':1024})
    assert plan['initial_allocations'][0]==('root',0,512)
    assert plan['events'][1]['allocate']==[('coset',512,2048)]
    rows,columns=16,8
    values=[col*1000+row for col in range(columns) for row in range(rows)]
    def digest(row):return hashlib.sha256(b''.join(struct.pack('<Q',values[col*rows+row]) for col in range(columns))).digest()
    expected=[digest(row) for row in range(rows)]
    # Any public row order; every writer touches only its own consumed row.
    for row in reversed(range(rows)):
        words=struct.unpack('<4Q',digest(row))
        for col,word in enumerate(words):values[col*rows+row]=word
    assert [struct.pack('<4Q',*(values[col*rows+row] for col in range(4))) for row in range(rows)]==expected


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


def test_compact_rms_original_bytes_are_released_before_range():
    checkpoint=arena.getter.rms_checkpoint()
    assert checkpoint['weighted_cells']==314_145_024
    assert checkpoint['unweighted_cells']==33_792_000
    assert checkpoint['statistic_rows']==576_149
    assert checkpoint['payload_bytes']==2_023_495_038
    assert checkpoint['owned_payload_and_metadata_bytes']==2_023_511_878
    assert checkpoint['dense_padded_frame_bytes']==arena.response.ARENA
    assert checkpoint['owned_payload_and_metadata_bytes']<2 << 30
    report=arena.report(ordered_getter=True,reuse_reader_for_commit=True)
    for case in report['cases']:
        plan=case['address_layouts']['compact_RMS_original_frames']
        assert plan['fits_with_operational_margin']
        assert plan['events'][-1]['free']==['RMS:original_PYS','RMS:byte_LUT','RMS:byte_coefficients','RMS:byte_prefix_weights']
        assert dict((key,size) for key,_,size in plan['events'][-2]['allocate'])=={
            'RMS:byte_LUT':100_466_688,'RMS:byte_coefficients':98_304,'RMS:byte_prefix_weights':1024}
        assert plan['events'][-1]['fence_before_release']
        assert plan['events'][-1]['live_aligned_bytes']==sum(n for _,_,n in plan['initial_allocations'])


def test_retained_capacity_is_never_freed_by_truncate_and_s3_cap_is_necessary():
    report=arena.report(ordered_getter=True,reuse_reader_for_commit=True)
    for case in report['cases']:
        plan=case['address_layouts']['each_A_opening']
        spans=[(offset,size) for event in plan['events'] for key,offset,size in event['allocate']
               if key.startswith('retained:S')]
        assert len(spans)==11 and len(set(spans))==1
        assert spans[0][1]==3_221_225_472
        assert plan['unaddressed_tail_bytes']>=arena.MARGIN
        old=arena.whir.commit_workspace(arena.whir.oracle_geometry(34)[3],1<<24)
        fields={'coset':'coset_buffer_bytes','frontier':'frontier_bytes',
                'twiddles':'twiddle_bytes','salt_offsets':'salt_offsets_bytes'}
        events=[]
        for e in plan['events']:
            allocate={key:size for key,_,size in e['allocate']}
            if e['event']=='a_commit_s3_with_s2_immutable':
                for key,field in fields.items():allocate['s3_commit:'+key]=old[field]
            events.append(dict(event=e['event'],free=e['free'],allocate=allocate))
        bad=arena.place_events(events,{key:size for key,_,size in plan['initial_allocations']})
        assert bad['aligned_live_peak_bytes']>arena.response.ARENA
        assert not bad['fits_with_operational_margin']


def test_maximum_checkpoint_fences_before_replacement_and_lookup():
    for c in arena.report(ordered_getter=True,reuse_reader_for_commit=True)['cases']:
        p=c['address_layouts']['EXP30_maximum_original_bytes']
        alive=False
        for e in p['events']:
            if 'EXP30:maximum_checkpoint' in e['free']:
                assert alive and e['fence_before_release']
                alive=False
            for name,_,size in e['allocate']:
                if name=='EXP30:maximum_checkpoint':
                    assert not alive
                    assert size<=1073741824
                    alive=True
        assert not alive and p['fits_with_operational_margin']
        cut_releases=[e['event'] for e in p['events'] if 'getter:cuts' in e['free']]
        assert cut_releases==['EXP30_last_original_byte_consumer_fence']
        assert p['events'][-1]['live_aligned_bytes']==sum(v for _,_,v in p['initial_allocations'])


def test_lookup_cache_survives_tree_release_and_cuts_survive_endpoint():
    for c in arena.report(True,True)['cases']:
        for key in ('GELU_original_lookup','softcap_original_lookup','EXP30_maximum_original_bytes'):
            p=c['address_layouts'][key];live={x[0] for x in p['initial_allocations']}
            for event in p['events']:
                live.difference_update(event['free']);live.update(x[0] for x in event['allocate'])
                if event['event'].endswith('_original_MAC_endpoint'):
                    assert 'getter:cuts' in live
                    assert any(k.endswith(':query_cache') for k in live)
                    assert not any(k.endswith(':upper_tree') for k in live)
            assert live=={x[0] for x in p['initial_allocations']}
            assert p['fits_with_operational_margin']


def test_lookup_response_proof_buffers_persist_across_all_chains():
    for c in arena.report(True,True)['cases']:
        shapes=arena.response.producer_lookup_trace(c['old_tokens'])
        for p in c['address_layouts'].values():
            initial={k:n for k,_,n in p['initial_allocations']}
            for name,x in shapes.items():
                key=name+'_lookup:proof'
                assert initial[key]==arena.aligned(x['proof_requested_bytes'])
                assert not any(key in e['free'] for e in p['events'])
        p=c['address_layouts']['EXP30_maximum_original_bytes']
        assert any(e['unverified_requirements'] for e in p['events'] if 'bind_original' in e['event'])
