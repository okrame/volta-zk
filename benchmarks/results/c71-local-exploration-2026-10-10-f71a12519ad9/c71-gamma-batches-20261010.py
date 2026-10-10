import hashlib,json,os,pathlib,resource,subprocess,sys,time
binary=pathlib.Path(sys.argv[1]).resolve()
directory=pathlib.Path(sys.argv[2]).resolve()
manifest=json.loads((directory/'manifest.json').read_text())
records=[]
def restrict():
    resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
env=dict(os.environ,RAYON_NUM_THREADS='1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1')
for ordinal,batch in enumerate(manifest['batches']):
    source=directory/batch['input']
    assert hashlib.sha256(source.read_bytes()).hexdigest()==batch['sha256']
    output=directory/batch['output']
    stem=output.with_suffix('')
    stderr=stem.with_suffix('.stderr')
    timings=stem.with_suffix('.time.txt')
    command=['/usr/bin/time','-v','-o',str(timings),'timeout','-k','5s','60s',str(binary),'rms-programs',str(source)]
    started=time.monotonic()
    with output.open('xb') as out,stderr.open('xb') as err:
        result=subprocess.run(command,stdout=out,stderr=err,env=env,preexec_fn=restrict)
    record={'input':batch['input'],'output':batch['output'],'command':command,'exit_code':result.returncode,'wall_s':time.monotonic()-started,'as_limit_bytes':2*1024**3,'deadline_s':60,'worker_threads':1,'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest()}
    with stem.with_suffix('.execution.json').open('x') as f:json.dump(record,f,indent=2)
    records.append(record)
    print(json.dumps({'batch':ordinal+1,'of':len(manifest['batches']),'exit_code':result.returncode,'wall_s':record['wall_s']}),flush=True)
    if result.returncode:break
with (directory/'batch-execution.json').open('x') as f:json.dump({'binary':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'records':records,'all_batches_completed':len(records)==len(manifest['batches']) and all(r['exit_code']==0 for r in records),'credit':False},f,indent=2)
if len(records)!=len(manifest['batches']) or any(r['exit_code'] for r in records):sys.exit(1)
