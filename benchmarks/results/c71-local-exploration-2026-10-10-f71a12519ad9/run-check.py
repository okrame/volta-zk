import datetime, hashlib, json, os, pathlib, resource, subprocess, sys, time
root=pathlib.Path('/home/okrame/projects/volta-zk')
label, *command=sys.argv[1:]
run=pathlib.Path(__file__).parent
log=run/(label+'.log'); report=run/(label+'.json')
assert not log.exists() and not report.exists()
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
dirty=bool(subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=root,text=True))
def limit(): resource.setrlimit(resource.RLIMIT_AS,(2*1024**3,2*1024**3))
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',RAYON_NUM_THREADS='1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',PYTHONPATH=str(root/'scripts'))
start=time.monotonic()
with log.open('xb') as f:
 p=subprocess.Popen(['timeout','-k','5s','60s',*command],cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,preexec_fn=limit)
 _,status,u=os.wait4(p.pid,0)
result=dict(command=command,source_git_sha=sha,git_dirty=dirty,cwd=str(root),exit_code=os.waitstatus_to_exitcode(status),wall_s=time.monotonic()-start,max_rss_bytes=u.ru_maxrss*1024,deadline_s=60,as_limit_bytes=2*1024**3,workers=1,recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),log=str(log),sha256=hashlib.sha256(log.read_bytes()).hexdigest())
report.write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result))
print(log.read_text()[-14000:])
sys.exit(result['exit_code'])
