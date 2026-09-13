from collections import Counter
from pathlib import Path
import sys
import pytest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import c71_ordered_getter as g


def test_window_intersections_match_every_original_index():
    n=32
    for suffix in range(6):
        permutation=[g.permuted_index(i,5,suffix) for i in range(n)]
        assert sorted(permutation)==list(range(n))
        for width in (1,2,4,8,16,32):
            for first in range(0,n,width):
                for a,b in ((0,32),(1,7),(7,19),(19,32),(11,12)):
                    count=sum(first<=permutation[i]<first+width for i in range(a,b))
                    assert g.intersection_count(a,b,first,width,5,suffix)==count


def test_shared_executor_preserves_raw_checkpoint_and_rejects_new_snapshot():
    nodes=[{'dependencies':[]},{'dependencies':[0]},{'dependencies':[1]},
           {'dependencies':[1,2]},{'dependencies':[3]}]
    checkpoints={1:6,3:19};calls=Counter();out={}
    def evaluate(n,inputs):
        calls[n]+=1
        return {2:lambda:inputs[0]*2,3:lambda:sum(inputs)+1,4:lambda:inputs[0]*3}[n]()
    snap=(0,'original-root','Gamma')
    # Target 3 denotes a raw emission: cached rounded output alone cannot serve it.
    g.execute_window(nodes,{2,3,4},checkpoints,evaluate,out.__setitem__,snap,snap)
    assert calls=={2:1,3:1,4:1} and out=={2:12,3:19,4:57}
    assert checkpoints=={1:6,3:19}
    with pytest.raises(ValueError):
        g.execute_window(nodes,{2},checkpoints,evaluate,out.__setitem__,(150,'new','Gamma'),snap)


def test_canonical_dag_windows_cover_sources_once_and_release_temporaries():
    for old in (0,150,300):
        r=g.trace(old,1 << 31,9)
        assert r['checkpoint_bytes']==98_380_800 and r['sources']==3471
        assert r['window_producer_peak_bytes']<64 << 20
        assert sum(s['live_byte_count'] for w in r['windows'] for s in w['segments'])==r['source_bytes']
        assert all(len(w['nodes'])==len(set(w['nodes'])) for w in r['windows'])
        assert r['HBM_transactions_exact'] is None and not r['native_numerical_getter_implemented']


def test_gkr_gather_preserves_bottom_subtree_contiguity():
    for bottom in range(4):
        for suffix in range(6-bottom):
            perm=[g.permuted_index(i,5,suffix,bottom) for i in range(32)]
            assert sorted(perm)==list(range(32))
            for width in (8,16,32):
                for first in range(0,32,width):
                    for a,b in ((0,32),(1,7),(7,19),(19,32)):
                        assert g.intersection_count(a,b,first,width,5,suffix,bottom)==sum(first<=perm[i]<first+width for i in range(a,b))


def test_range_gather_matches_native_half_folds_and_gram_groups():
    # Native c71_matrix::fold pairs halves, not adjacent MLE coordinates.
    prime=97;d=7;m=5;bottom=d-m
    rows=[[(i*i+3*j*i+7*j+1)%prime for i in range(1<<m)] for j in range(4)]
    for previous in range(3):
        for width in range(1,4-previous):
            point=[3,5][:previous];dense=[v[:] for v in rows]
            for challenge in point:
                dense=[[(a+challenge*(b-a))%prime for a,b in zip(v[:len(v)//2],v[len(v)//2:])] for v in dense]
            tail=1 << (m-previous-width);length=1 << width
            actual=[[[0]*4 for _ in range(length)] for _ in range(tail)]
            for original in range(1 << m):
                high=original >> (m-previous)
                weight=1
                for k,r in enumerate(point):weight=weight*(r if high>>(previous-1-k)&1 else 1-r)%prime
                address=g.permuted_index(original << bottom,d,m-previous-width,bottom) >> bottom
                t,rest=divmod(address,1 << (previous+width));u=rest & (length-1)
                for j in range(4):actual[t][u][j]=(actual[t][u][j]+weight*rows[j][original])%prime
            assert actual==[[[row[u*tail+t] for row in dense] for u in range(length)] for t in range(tail)]
    orders=g.range_orders()
    assert len(orders)==26
    assert all(x['suffix_bits']+x['folded_bits']+x['Gram_bits']==x['child_bits'] for x in orders[1:])


def test_sourcewise_fold_coset_fusion_preserves_linear_map():
    # Each scan runs at its own FS stage; pad is added once after accumulation.
    p=97;values=[(i*i+13*i+9)%p for i in range(32)];weights=[2,5,11,17]
    folded=[sum(weights[a]*values[a*8+t] for a in range(4))%p for t in range(8)]
    coset_rows=2;z=7
    expected=[[sum(folded[col*4+j]*pow(z,j,p) for j in range(4) if j%2==k)%p for k in range(2)] for col in range(2)]
    actual=[[0]*coset_rows for _ in range(2)]
    # Public source-emission order may differ from the polynomial byte order.
    for index in sorted(range(32),key=lambda i:(i%7,i)):
        a,t=divmod(index,8);col,j=divmod(t,4)
        actual[col][j%coset_rows]=(actual[col][j%coset_rows]+values[index]*weights[a]*pow(z,j,p))%p
    assert actual==expected
