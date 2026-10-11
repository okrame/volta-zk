import json, os, pathlib, resource, subprocess, sys, time
out=pathlib.Path(sys.argv[1]);out.mkdir()
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',RAYON_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
checks=[]
def limit():resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
for name in ['test_c71_temporary_ledger','test_c71_docs']:
 start=time.monotonic()
 with (out/(name+'.log')).open('xb') as f:
  child=subprocess.Popen(['timeout','-k','5s','60','.venv/bin/python','-m','pytest','-q','-p','no:cacheprovider','tests/'+name+'.py'],env=env,preexec_fn=limit,stdout=f,stderr=subprocess.STDOUT)
  _,status,usage=os.wait4(child.pid,0);child.returncode=os.waitstatus_to_exitcode(status)
 result={'check':name,'exit_code':child.returncode,'wall_s':time.monotonic()-start,'rss_bytes':usage.ru_maxrss*1024,'as_bytes':2<<30,'deadline_s':60,'workers':1,'summary':[s for s in (out/(name+'.log')).read_text().splitlines() if 'passed' in s]}
 checks.append(result);(out/'checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps(result),flush=True)
 if child.returncode:print((out/(name+'.log')).read_text());sys.exit(child.returncode)
