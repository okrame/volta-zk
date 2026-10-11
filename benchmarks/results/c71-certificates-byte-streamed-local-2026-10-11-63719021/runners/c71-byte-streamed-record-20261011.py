import hashlib,json,pathlib,subprocess,shutil
base=pathlib.Path.cwd();read=lambda p:json.loads(p.read_text())
clean=pathlib.Path('/tmp/c71-byte-streamed-clean-20261011');py=pathlib.Path('/tmp/c71-byte-streamed-clean-python-20261011');source=read(clean/'source.json')
sha=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();assert sha==source['git_sha'] and not source['git_dirty'];assert not subprocess.check_output(['git','status','--porcelain'])
assert read(py/'source.json')=={'git_sha':sha,'git_dirty':False}
for p,h in source['source_files'].items():assert hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==h
assert hashlib.sha256(pathlib.Path(source['binary_path']).read_bytes()).hexdigest()==source['binary_sha256']
checks=read(clean/'checks.json')+read(py/'checks.json');assert len(checks)==8 and all(c['exit_code']==0 for c in checks)
def tagged(p,marker):
 rows=[json.loads(l.split(marker,1)[1]) for l in p.read_text().splitlines() if marker in l];assert len(rows)==1;return rows[0]
byte=tagged(clean/'c71_byte_streamed_contraction_full_wire_above_reduced_limit.log','C71_BYTE_STREAMED_WIRE ')
rms=tagged(clean/'c71_b12_packed_mixed_gkr_complete_wire_mac_and_endpoint.log','C71_RMS_BYTE_CONTRACTION ')
assert byte['work']['retained_state_capacity_peak_bytes']==24+173*(8+24+2*17*24)==146728
assert rms['byte_work']['retained_state_capacity_peak_bytes']==12*24+6*(8+12*24+2*12*17*24)==60816
stem='c71-certificates-byte-streamed-local-2026-10-11-'+sha[:8];out=base/'benchmarks/results'/stem;out.mkdir()
files=[]
for label,root in [('clean-rust',clean),('clean-python',py),('development',pathlib.Path('/tmp/c71-byte-streamed-development-20261011')),('development-rest',pathlib.Path('/tmp/c71-byte-streamed-development-rest-20261011'))]:
 for p in sorted(root.iterdir()):
  if p.is_file():files.append((p,pathlib.Path(label)/p.name))
for n in range(1,5):
 for ext in ['json','log']:
  p=pathlib.Path(f'/tmp/c71-byte-streamed-build0{n}-20261011.{ext}');files.append((p,pathlib.Path('builds')/p.name))
for n in ['tests','python','plan','record']:
 p=pathlib.Path(f'/tmp/c71-byte-streamed-{n}-20261011.py');files.append((p,pathlib.Path('runners')/p.name))
artifacts=[]
for p,rel in files:
 dest=out/rel;dest.parent.mkdir(parents=True,exist_ok=True)
 with dest.open('xb') as f:f.write(p.read_bytes())
 artifacts.append({'path':str(rel),'bytes':dest.stat().st_size,'sha256':hashlib.sha256(dest.read_bytes()).hexdigest()})
record={'schema':'volta-c71-byte-streamed-local-v1','source_git_sha':sha,'git_dirty':False,'credit':False,'canonical_selected':False,'gpu_execution':False,'certificates_generated':0,'certificates_verified':0,'contexts_completed':[],'checks':checks,'source_provenance':dict(source,build_before_source_commit=True,final_build='builds/c71-byte-streamed-build04-20261011.json',build_source_files_identical_to_clean_commit=True,profile={'dependency_opt_level':2,'volta_pcs_opt_level':0,'volta_pcs_codegen_units':64,'global_codegen_units_override':False,'jobs':1}),'byte_wire_parity':byte,'rms_wire_parity':rms,'public_plan':read(py/'public-plan.json'),'development_failures':[{'kind':'build_timeout','file':'builds/c71-byte-streamed-build01-20261011.json','cause':'Global codegen-units override rebuilt dependencies; corrected to prior package-only profile with unchanged limits.'},{'kind':'compile_error','file':'builds/c71-byte-streamed-build02-20261011.json','cause':'New Work type was not visible to sibling RMS test; visibility corrected.'},{'kind':'compound_PCS_test_timeout','file':'development/c71_b12_byte_functions_close_original_byte_macs_in_one_ranged_pcs.log','result':read(pathlib.Path('/tmp/c71-byte-streamed-development-20261011/checks.json'))[-1],'limitation':'Partial positive output is not a complete PCS test pass. No timeout extension or hardware claim.'}],'development_build_provenance':'Final build 04 is identified by matching source files and binary digest. Intermediate build sources/binaries are not separately frozen; their logs are development evidence, not clean runs of record.','artifact_directory':str(out.relative_to(base)),'artifacts':artifacts,'scope':'Local original-field/dense-wire/FS/MAC parity and public bounded-state plan only. Complete canonical work, simultaneous physical peak, native/H100 timing, AES and canonical certificates remain unproved. The original compound PCS test timed out.'}
p=out.with_suffix('.json')
with p.open('x') as f:json.dump(record,f,indent=2);f.write('\n')
for e in artifacts:
 f=out/e['path'];assert f.stat().st_size==e['bytes'] and hashlib.sha256(f.read_bytes()).hexdigest()==e['sha256']
print(json.dumps({'record':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'files':len(artifacts),'bytes':sum(e['bytes'] for e in artifacts),'checks':len(checks)}))
