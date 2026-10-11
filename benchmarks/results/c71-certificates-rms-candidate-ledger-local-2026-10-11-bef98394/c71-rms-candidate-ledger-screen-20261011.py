import hashlib, importlib.util, json, os, pathlib, re, resource, shutil, subprocess, sys, time
root=pathlib.Path.cwd();out=pathlib.Path(sys.argv[1]);out.mkdir()
resource.setrlimit(resource.RLIMIT_AS,(2<<30,2<<30))
sha=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
dirty=bool(subprocess.check_output(['git','status','--porcelain']))
if len(sys.argv)>2 and sys.argv[2]=='clean':assert not dirty
frozen=root/'benchmarks/results/c71-certificates-vmm-pool-local-2026-10-11-6ccb54a1'
inputs=out/'inputs';inputs.mkdir();sources=[]
for path in sorted(frozen.glob('inputs-*.log')):
 shutil.copyfile(path,inputs/path.name)
 sources.append({'path':str(path.relative_to(root)),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
spec=importlib.util.spec_from_file_location('ledger',root/'scripts/c71_temporary_ledger.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
args=[inputs,'s1-prepared',root/'benchmarks/results/c71-crypto-query-local-2026-10-09-46d295ef4ea6.json',root/'benchmarks/results/c71-crypto-linear-local-2026-10-09-31280382f681.json',root/'benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1.json']
start=time.monotonic();d=m.ledger(*args,rms_candidates=True)
(out/'ledger.json').write_text(json.dumps(d,indent=2)+'\n')
summary={'source_git_sha':sha,'git_dirty':dirty,'credit':False,'gpu_execution':False,'canonical_selected':False,'joint_admitted':False,'input_sources':sources,'payload_cap_bytes':d['enforced_joint_allocation_limit_bytes'],'phase_count':len(d['named_phase_crosschecks']),'contexts':[]}
for i,old in enumerate([0,150,300],1):
 rows=[r for r in d['named_phase_crosschecks'] if re.search(r'_A'+str(i)+r'(?:_|$)',r['phase'])]
 maximum=max(rows,key=lambda r:r['named_allocation_subtotal_bytes'])
 pick=lambda r:{k:r[k] for k in ['phase','named_allocation_subtotal_bytes','remaining_shared_payload_capacity_bytes','named_subtotal_exceeds_payload']}
 summary['contexts'].append({'old_tokens':old,'named_context_maximum':pick(maximum),'RMS':[pick(r) for r in rows if 'RMS_GKR' in r['phase']]})
summary['check']={'wall_s':time.monotonic()-start,'rss_bytes':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*1024,'as_bytes':2<<30,'deadline_s':60,'workers':1}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({k:v for k,v in summary.items() if k!='input_sources'},indent=2),flush=True)
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()==sha
assert bool(subprocess.check_output(['git','status','--porcelain']))==dirty
