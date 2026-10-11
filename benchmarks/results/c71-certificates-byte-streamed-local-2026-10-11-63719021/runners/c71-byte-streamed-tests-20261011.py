import hashlib,json,os,pathlib,resource,subprocess,time,sys
out=pathlib.Path(sys.argv[1]);out.mkdir(exist_ok=False)
binary=pathlib.Path('/home/okrame/projects/volta-zk/rust/target/debug/deps/volta_pcs-b3228fb890c6a4d7')
files=['rust/volta-pcs/src/c71_matrix/byte_function.rs','rust/volta-pcs/src/c71_matrix/byte_function/contraction.rs','rust/volta-pcs/src/c71_matrix/rms/gkr.rs']
source={'git_sha':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'git_dirty':bool(subprocess.check_output(['git','status','--porcelain'])),'binary_path':str(binary),'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'source_files':{p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in files},'scope':'Bounded local parity; no canonical certificate or hardware result'}
(out/'source.json').write_text(json.dumps(source,indent=2)+'\n')
env=dict(os.environ,RAYON_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',OMP_NUM_THREADS='1',PYTHONDONTWRITEBYTECODE='1');checks=[]
def limit():resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
filters=['c71_byte_streamed_contraction_budget_support_and_original_coefficients','c71_byte_streamed_contraction_full_wire_above_reduced_limit','c71_byte_node_contraction_matches_native_lut_cubics_and_terminal_children','c71_b12_byte_functions_close_original_byte_macs_in_one_ranged_pcs','c71_b12_packed_mixed_gkr_complete_wire_mac_and_endpoint']
if len(sys.argv)>2:filters=[f for f in filters if f in sys.argv[2:]]
for f in filters:
 start=time.monotonic()
 with (out/(f+'.log')).open('xb') as sink:
  child=subprocess.Popen(['timeout','-k','5s','60',str(binary),f,'--nocapture','--test-threads=1'],env=env,stdout=sink,stderr=subprocess.STDOUT,preexec_fn=limit)
  _,status,usage=os.wait4(child.pid,0);child.returncode=os.waitstatus_to_exitcode(status)
 lines=(out/(f+'.log')).read_text().splitlines();summaries=[x for x in lines if x.startswith('test result:')]
 result={'check':f,'exit_code':child.returncode,'wall_s':time.monotonic()-start,'rss_bytes':usage.ru_maxrss*1024,'as_bytes':2<<30,'deadline_s':60,'workers':1,'summary':summaries};checks.append(result)
 (out/'checks.json').write_text(json.dumps(checks,indent=2)+'\n');print(json.dumps(result),flush=True)
 assert child.returncode==0 and summaries and '1 passed' in summaries[0]
for p,h in source['source_files'].items():assert hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h
assert hashlib.sha256(binary.read_bytes()).hexdigest()==source['binary_sha256']
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==source['git_sha']
assert bool(subprocess.check_output(['git','status','--porcelain']))==source['git_dirty']
