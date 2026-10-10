import datetime,hashlib,json,os,pathlib,resource,subprocess,sys,time
root=pathlib.Path('/home/okrame/projects/volta-zk');directory=pathlib.Path(sys.argv[1]);binary=pathlib.Path(sys.argv[2]);manifest=json.loads((directory/'manifest.json').read_text());source_sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip();assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
binary_sha=hashlib.sha256(binary.read_bytes()).hexdigest();records=[];env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',RAYON_NUM_THREADS='1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1')
original=json.load(open(root/'artifact/c7.1-pod/h100-components-20261009T194100Z/gamma-inputs/recipes-original.json'))
(directory/'recipes').mkdir()
def restrict():resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
for name in ['admitted','rms-even-finer','rms-even-coarser','rms-output-finer-one','rms-output-coarser-control']:
    entry=manifest['candidates'][name];source=directory/entry['path'];assert hashlib.sha256(source.read_bytes()).hexdigest()==entry['sha256'];assert hashlib.sha256(binary.read_bytes()).hexdigest()==binary_sha
    output=directory/'recipes'/f'{name}.json';error=directory/'recipes'/f'{name}.stderr';command=['timeout','-k','5s','60s',str(binary),'recipes',str(source)];started=time.monotonic()
    with output.open('xb') as out,error.open('xb') as err:
        p=subprocess.Popen(command,stdout=out,stderr=err,env=env,preexec_fn=restrict);_,status,usage=os.wait4(p.pid,0)
    exit_code=os.waitstatus_to_exitcode(status)
    record={'candidate':name,'input_sha256':entry['sha256'],'output':str(output.relative_to(directory)),'output_sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'command':command,'source_git_sha':source_sha,'git_dirty':False,'binary_sha256':binary_sha,'exit_code':exit_code,'wall_s':time.monotonic()-started,'max_rss_bytes':usage.ru_maxrss*1024,'as_limit_bytes':2*1024**3,'deadline_s':60,'workers':1,'recorded_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'full_compiler_all_three_contexts':exit_code==0}
    if exit_code==0:
        parsed=json.loads(output.read_text());assert not parsed['calibrated'];assert len(parsed['rms'])==421
        for field in ['gelu','exp30','softcap','rope_positions','table_bytes']:assert parsed[field]==original[field]
        if name=='admitted':assert parsed==original
        record['certified_table_recipes_unchanged']=True;record['recipe_digest']=parsed['recipe_digest']
    with (directory/'recipes'/f'{name}.execution.json').open('x') as f:json.dump(record,f,indent=2)
    records.append(record);print(json.dumps(record),flush=True)
with (directory/'recipe-execution.json').open('x') as f:json.dump({'credit':False,'source_git_sha':source_sha,'git_dirty':False,'binary_sha256':binary_sha,'records':records},f,indent=2)
