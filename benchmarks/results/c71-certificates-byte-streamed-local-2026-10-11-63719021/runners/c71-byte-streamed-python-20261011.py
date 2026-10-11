import json,os,pathlib,resource,subprocess,time
out=pathlib.Path('/tmp/c71-byte-streamed-clean-python-20261011');out.mkdir()
sha=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();assert not subprocess.check_output(['git','status','--porcelain'])
env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',RAYON_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1');checks=[]
def limit():resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
commands=[(n,['.venv/bin/python','-m','pytest','-q','-p','no:cacheprovider','tests/'+n+'.py']) for n in ['test_c71_gkr_screen','test_c71_byte_tree_contraction','test_c71_docs']]
commands.append(('public-plan',['python3','/tmp/c71-byte-streamed-plan-20261011.py',str(out/'public-plan.json')]))
for name,cmd in commands:
 start=time.monotonic()
 with (out/(name+'.log')).open('xb') as f:
  child=subprocess.Popen(['timeout','-k','5s','60',*cmd],env=env,preexec_fn=limit,stdout=f,stderr=subprocess.STDOUT)
  _,status,usage=os.wait4(child.pid,0);child.returncode=os.waitstatus_to_exitcode(status)
 result={'check':name,'exit_code':child.returncode,'wall_s':time.monotonic()-start,'rss_bytes':usage.ru_maxrss*1024,'as_bytes':2<<30,'deadline_s':60,'workers':1,'summary':[s for s in (out/(name+'.log')).read_text().splitlines() if 'passed' in s]}
 checks.append(result);(out/'checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps(result),flush=True);assert child.returncode==0
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==sha
assert not subprocess.check_output(['git','status','--porcelain'])
(out/'source.json').write_text(json.dumps({'git_sha':sha,'git_dirty':False})+'\n')
