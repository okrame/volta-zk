import datetime,hashlib,json,os,pathlib,resource,subprocess,sys,time
root=pathlib.Path('/home/okrame/projects/volta-zk')
binary=pathlib.Path(sys.argv[1]).resolve()
directory=pathlib.Path(sys.argv[2]).resolve()
manifest=json.loads((directory/'manifest.json').read_text())
source_sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
dirty=bool(subprocess.check_output(['git','status','--porcelain'],cwd=root))
assert not dirty
binary_sha=hashlib.sha256(binary.read_bytes()).hexdigest()
records=[]
def restrict():resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',RAYON_NUM_THREADS='1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1')
for ordinal,batch in enumerate(manifest['batches']):
    source=directory/batch['input']
    assert hashlib.sha256(source.read_bytes()).hexdigest()==batch['sha256']
    assert hashlib.sha256(binary.read_bytes()).hexdigest()==binary_sha
    output=directory/batch['output'];stem=output.with_suffix('');stderr=stem.with_suffix('.stderr')
    command=['timeout','-k','5s','60s',str(binary),'rms-programs',str(source)]
    started=time.monotonic()
    with output.open('xb') as out,stderr.open('xb') as err:
        p=subprocess.Popen(command,stdout=out,stderr=err,env=env,preexec_fn=restrict)
        _,status,usage=os.wait4(p.pid,0)
    exit_code=os.waitstatus_to_exitcode(status)
    record={'input':batch['input'],'input_sha256':batch['sha256'],'output':batch['output'],'command':command,'source_git_sha':source_sha,'git_dirty':dirty,'binary_sha256':binary_sha,'exit_code':exit_code,'wall_s':time.monotonic()-started,'max_rss_bytes':usage.ru_maxrss*1024,'as_limit_bytes':2*1024**3,'deadline_s':60,'worker_threads':1,'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'recorded_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}
    if exit_code==0:
        parsed=json.loads(output.read_text());assert parsed['credit'] is False and parsed['gamma_admitted'] is False and len(parsed['programs'])==len(json.loads(source.read_text()))
    with stem.with_suffix('.execution.json').open('x') as f:json.dump(record,f,indent=2)
    records.append(record)
    print(json.dumps({'batch':ordinal+1,'of':len(manifest['batches']),'exit_code':exit_code,'wall_s':record['wall_s'],'max_rss_bytes':record['max_rss_bytes']}),flush=True)
    if exit_code:break
with (directory/'batch-execution.json').open('x') as f:json.dump({'binary':str(binary),'binary_sha256':binary_sha,'source_git_sha':source_sha,'git_dirty':dirty,'records':records,'all_batches_completed':len(records)==len(manifest['batches']) and all(r['exit_code']==0 for r in records),'credit':False},f,indent=2)
if len(records)!=len(manifest['batches']) or any(r['exit_code'] for r in records):sys.exit(1)
