"""Routing/partition and liveness checks; no Gemma/PCS runtime credit."""
import sys
from pathlib import Path
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_getter_trace as getter


def test_canonical_source_census_and_original_KV_are_distinct():
    for old,expected in zip((0,150,300),(13_154_672_538,14_334_320_538,15_513_968_538)):
        r=getter.getter_trace(old)
        assert r['source_count']==3471 and r['live_bytes']==expected
        assert r['original_KV_context_bytes']==(old+150)*901120
        assert r['ordered_byte_tile_word_requests']>r['unique_words']
        # Original IDs preceding context-sized attention sources are stable.
        if old:
            assert r['sources'][:2400]==getter.sources_at(0)[:2400]


def test_small_getter_tiles_partition_original_biased_bytes_and_bind_snapshot():
    sources=[dict(name='raw',rows=3,cols=5,width=6),dict(name='output',rows=2,cols=3,width=2)]
    tiles=getter.byte_tiles(sources)
    snapshot=(150,b'root-A1',b'Gamma')
    words={s['name']:[[(-1 if (r+c)%2 else 1)*(3*r+c) for c in range(s['cols'])]
           for r in range(s['rows'])] for s in sources}
    def read(context,name,row,col):
        assert context==snapshot
        return words[name][row][col]
    actual={}
    for tile in tiles:
        rows=getter.read_tile(sources,tile,snapshot,snapshot,read,0,tile['rows']*tile['cols'])
        for index,value in rows:
            assert index not in actual
            actual[index]=value
        s=sources[tile['source']]
        # Independent explicit dyadic tile flattening, with signed top-byte bias.
        expected=[]
        for r in range(tile['row'],tile['row']+tile['rows']):
            for c in range(tile['col'],tile['col']+tile['cols']):
                encoded=bytearray(words[s['name']][r][c].to_bytes(s['width'],'little',signed=True))
                encoded[-1]^=128
                expected.extend(encoded[tile['first']:tile['first']+tile['width']])
        assert [v for _,v in rows]==expected
    assert set(actual)==set(range(sum(s['rows']*s['cols']*s['width'] for s in sources)))
    with pytest.raises(ValueError,match='snapshot'):
        getter.read_tile(sources,tiles[0],(300,b'root-A2',b'Gamma'),snapshot,read,0,1)


def test_sourcewise_trace_releases_after_last_consumer_and_keeps_replay_work():
    for old in (0,150,300):
        r=getter.scatter_generation_trace(old)
        assert r['named_tensor_peak_bytes']==52_690_940 < 64<<20
        live={}
        for event in r['events']:
            assert all(dep in live for dep in event['dependencies'])
            live[event['node']]=event['output_bytes']
            for dep in event['released']:del live[dep]
            assert sum(live.values())+r['persistent_histogram_bytes']==event['allocated_after']
        assert not live
        assert r['work']['integer_MACs']>4_463_473_459_200
        assert r['native_kernel_workspace_bytes'] is None
        assert not r['ordered_source_schedule_closed']
