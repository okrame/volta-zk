"""Download pinned C7.1 shards into a new private directory, hashing complete bodies."""
import hashlib,json,os,time,urllib.parse,urllib.request
from pathlib import Path
from c7_d126_gemma_weight_ingest import MODEL,REVISION,SHARDS
root=Path(os.environ['SHARDS'])
root.mkdir(mode=0o700,exist_ok=False)
for name,spec in SHARDS.items():
    target=root/name; partial=target.with_suffix(target.suffix+'.partial')
    assert not target.exists() and not partial.exists()
    request=urllib.request.Request(f'https://huggingface.co/{MODEL}/resolve/{REVISION}/{name}')
    digest=hashlib.sha256(); count=0; last=0; started=time.monotonic()
    with urllib.request.urlopen(request,timeout=60) as source,partial.open('xb') as sink:
        while chunk:=source.read(4*1024**2):
            count+=len(chunk); assert count<=spec['bytes']
            digest.update(chunk); sink.write(chunk)
            if count-last>=1024**3:
                print(json.dumps({'shard':name,'downloaded_bytes':count,'elapsed_seconds':time.monotonic()-started}),flush=True);last=count
        sink.flush(); os.fsync(sink.fileno())
    assert count==spec['bytes'] and digest.hexdigest()==spec['lfs_sha256']
    os.link(partial,target); partial.unlink()
    print(json.dumps({'shard':name,'bytes':count,'sha256':digest.hexdigest(),'verified':True}),flush=True)
