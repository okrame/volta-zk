"""Public shape census for a bounded candidate; not a runtime or protocol result."""
import hashlib
import json
from pathlib import Path

ROOT = Path('/home/okrame/projects/volta-zk')
INPUT = ROOT / 'benchmarks/results/c71-certificates-rms-shared-support-local-2026-10-11-fe5f9d65'
LIMIT = 16 << 20
N, LIVE, PROGRAMS = 1 << 29, 347937024, 159
# Conservative 64-bit metadata bound; thresholds must agree for every size 0..256.
HEADER = 256

def capture(width, programs, cells, limit, header):
    for r in range(cells.bit_length()-1):
        active = cells >> r
        capacity = header + active*((width+programs)*24+programs)
        if capacity <= limit:
            return r, active, capacity
    return None

# Threshold boundary and no-fit; independent literal callback/fold counts.
assert capture(8,3,32,256+8*267,256) == (2,8,2392)
assert capture(8,3,32,2391,256)[0] == 3
assert capture(8,3,32,1,256) is None
for n in [2,4,8,16,32]:
    for r in range(n.bit_length()-1):
        active=n>>r
        total=0
        while active>2:
            total+=active//2
            active//=2
        assert total==(n>>r)-2

rows=[]; sources=[]
for name in ['depths-1-33.log','depths-34-66.log','depths-67-99.log']:
    p=INPUT/name; data=p.read_bytes()
    sources.append({'path':str(p.relative_to(ROOT)),'sha256':hashlib.sha256(data).hexdigest()})
    for line in data.decode().splitlines():
        marker='C71_RMS_SHARED_GATE_SCREEN '
        if marker not in line: continue
        shape=json.loads(line.split(marker,1)[1])
        assert shape['programs']==PROGRAMS and shape['credit'] is False
        width=shape['input_width']; r,active,capacity=capture(width,PROGRAMS,N,LIMIT,HEADER)
        assert 0<width<=16384 and width&(width-1)==0
        assert all(capture(width,PROGRAMS,N,LIMIT,h)[:2]==(r,active) for h in range(257))
        rows.append({'depth':shape['depth'],'width':width,'capture_round_zero_based':r,
            'active_at_capture':active,'cache_capacity_upper_bytes':capacity,
            'original_row_callbacks':LIVE*(r+1),'original_selector_callbacks':N*(r+1),
            'extra_fold_products_additions_subtractions_each':(active-2)*(width+PROGRAMS)})
assert [r['depth'] for r in rows]==list(range(1,100))
old=LIVE*29*99; new=sum(r['original_row_callbacks'] for r in rows)
assert old==998927195904
out={'schema':'volta-c71-rms-folded-cache-screen-v1','credit':False,'canonical_selected':False,
    'scope':'cell folds only; excludes byte endpoint, caller statistics, PCS, AES, allocator and complete physical peak',
    'inputs':sources,'limit_bytes':LIMIT,'metadata_upper_bytes':HEADER,
    'thresholds_same_for_all_metadata_bytes_0_through_256':True,
    'programs':PROGRAMS,'live_cells':LIVE,'padded_cells':N,'depths':rows,
    'old_original_row_callbacks':old,'candidate_original_row_callbacks':new,
    'saved_original_row_callbacks':old-new,'callback_ratio':new/old,
    'old_original_selector_callbacks':N*29*99,
    'candidate_original_selector_callbacks':sum(r['original_selector_callbacks'] for r in rows),
    'extra_fold_products_additions_subtractions_each':sum(r['extra_fold_products_additions_subtractions_each'] for r in rows),
    'cache_capacity_upper_peak_bytes':max(r['cache_capacity_upper_bytes'] for r in rows),
    'unchanged_coefficient_core_Fp3_products':751359028655932,
    'runtime_seconds':None,'complete_certificate':False}
print(json.dumps(out,indent=2))
