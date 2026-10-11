import hashlib,json,os,pathlib,resource,subprocess,time
out=pathlib.Path('/tmp/c71-rms-shared-clean-20261011');out.mkdir(exist_ok=False)
sha=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();assert not subprocess.check_output(['git','status','--porcelain'])
prov=json.load(open('/tmp/c71-rms-shared-adaptive-provenance-20261011.json'))
for p,h in prov['source_files'].items():assert hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h
assert hashlib.file_digest(open(prov['binary_path'],'rb'),'sha256').hexdigest()==prov['binary_sha256']
prov.update(source_git_sha=sha,git_dirty=False)
(out/'source.json').write_text(json.dumps(prov,indent=2)+'\n')
env=dict(os.environ,RAYON_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1')
checks=[]
def limit():resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
def run(name,cmd):
 start=time.monotonic()
 with (out/(name+'.log')).open('xb') as log:
  p=subprocess.Popen(['timeout','-k','5s','60s',*cmd],env=env,stdout=log,stderr=subprocess.STDOUT,preexec_fn=limit)
  _,status,usage=os.wait4(p.pid,0);p.returncode=os.waitstatus_to_exitcode(status)
 txt=(out/(name+'.log')).read_text();summary=[l for l in txt.splitlines() if l.startswith('test result:') or 'passed in' in l]
 r={'check':name,'exit_code':p.returncode,'wall_s':time.monotonic()-start,'max_rss_bytes':usage.ru_maxrss*1024,'as_bytes':2<<30,'deadline_s':60,'workers':1,'summary':summary};checks.append(r);print(json.dumps(r),flush=True)
 (out/'checks.json').write_text(json.dumps(checks,indent=2)+'\n')
 assert p.returncode==0 and summary and not any('0 passed' in s for s in summary)
filters=['c71_rms_shared_gate_','c71_rms_folded_cache_','c71_b12_packed_mixed_gkr_complete_wire_mac_and_endpoint','sourcewise_cell_coefficients_match_dense_folds_without_cell_wire_matrix','c71_b12_boolean_first_cell_round_exact_all_gate_patterns']
for f in filters:run(f,[prov['binary_path'],f,'--nocapture','--test-threads=1'])
run('documents',['.venv/bin/python','-m','pytest','-q','-p','no:cacheprovider','tests/test_c71_docs.py'])
source=pathlib.Path.cwd()/'benchmarks/results/c71-certificates-rms-shared-support-local-2026-10-11-fe5f9d65'
env.update(C71_RMS_BENCH_RECIPES=str(source/'c71-rms-shared-recipes-20261011.json'),C71_RMS_BENCH_SUPPORT=str(source/'c71-rms-shared-support-20261011.json'),C71_RMS_SCREEN_IMPLEMENTED_SHARED='1')
for first in range(1,100,11):
 last=min(first+10,99);env.update(C71_RMS_SCREEN_FIRST_DEPTH=str(first),C71_RMS_SCREEN_LAST_DEPTH=str(last))
 run(f'census-{first}-{last}',[prov['binary_path'],'c71_rms_pinned_shared_gate_screen','--ignored','--nocapture','--test-threads=1'])
assert not subprocess.check_output(['git','status','--porcelain'])
