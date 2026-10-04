import os,subprocess,resource,json,re,sys
from pathlib import Path
out=Path(os.environ.get('C71_MEMORY_LOGS','/tmp/c71-memory-final-tests'));out.mkdir(exist_ok=True)
filters=['c71_original_claim_batch_','c71_temporary_budget_','c71_canonical_device_','c71_b12_canonical_initial_geometry','c71_b12_canonical_extension_geometry','replay_tree_','c71_b12_query_factors_','c71_b12_scattered_','c71_b12_query_byte_windows','c71_b12_retained_lifecycle','c71_b12_sourcewise_geometry','c71_b12_full_sourcewise_chain','c71_b12_windowed_native_','c71_canonical_metrics_','c71_canonical_runner_','c71_b12_native_dispatch_canonical_preflight','c71_b12_native_streaming_lookup_gkr_whir_positive_original_macs','c71_seed6_native_full_o0_proof_promotes_same_receipt_after_role_journals']
filters=sys.argv[1:] or filters
env=dict(os.environ,RAYON_NUM_THREADS='1',OMP_NUM_THREADS='1',OPENBLAS_NUM_THREADS='1',PYTHONDONTWRITEBYTECODE='1')
def limits():resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
for name in filters:
 path=out/(name+'.log')
 with path.open('x') as log:
  p=subprocess.run(['timeout','-k','5s','60s','rust/target/debug/deps/volta_pcs-005c7396bb08fa32',name,'--test-threads=1','--nocapture'],env=env,stdout=log,stderr=subprocess.STDOUT,preexec_fn=limits)
 match=re.search(r'test result: (\w+)\. (\d+) passed; (\d+) failed',path.read_text())
 record={'filter':name,'exit':p.returncode,'summary':match.group(0) if match else None}
 print(json.dumps(record),flush=True)
 if p.returncode or not match or int(match[2])==0:sys.exit(p.returncode or 1)
