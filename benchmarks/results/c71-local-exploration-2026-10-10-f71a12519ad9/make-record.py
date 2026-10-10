import datetime,hashlib,json,pathlib,re,shutil,subprocess
root=pathlib.Path('/home/okrame/projects/volta-zk'); run=pathlib.Path(__file__).parent
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert sha=='f71a12519ad933f0f5e877e2362b490dcdea449a'
assert not subprocess.check_output(['git','status','--porcelain','--untracked-files=all'],cwd=root)
name=f'c71-local-exploration-2026-10-10-{sha[:12]}'
out=root/'benchmarks/results'/name;out.mkdir()
for src in run.iterdir():
 if src.is_file() and src.suffix in ('.py','.cpp','.json','.log'):
  shutil.copyfile(src,out/src.name)
shutil.copytree('/tmp/c71-gamma-screen-20261010-02',out/'gamma')
shutil.copytree('/tmp/c71-gamma-screen-20261010',out/'gamma-driver-first-failure')
for name2 in ('c71-gamma-batches-20261010.py','c71-gamma-batches-20261010-02.py','c71-gamma-batches-driver-01-failure.json','c71-gamma-screen-20261010-102ecf02.json'):
 shutil.copyfile('/tmp/'+name2,out/name2)
for src in pathlib.Path('/tmp').glob('c71-gamma-*20261010*.py'):
 if not (out/src.name).exists():shutil.copyfile(src,out/src.name)
reports=[json.loads(p.read_text()) for p in run.glob('rust-[0-9][0-9].json')]
assert len(reports)==15 and all(not r['git_dirty'] for r in reports)
failed_reports=[r for r in reports if r['exit_code']!=0]
assert len(failed_reports)==1 and 'c71_canonical_device_replay_original_rows_windows_and_failure' in failed_reports[0]['command']
retry=json.loads((run/'rust-09-corrected.json').read_text())
assert retry['exit_code']==0 and not retry['git_dirty']
reports.append(retry)
rust_passed=sum(int(re.search(r'test result: ok\. (\d+) passed',pathlib.Path(r['log']).read_text()).group(1)) for r in reports if r['exit_code']==0)
assert rust_passed==17
checks=[json.loads((run/n).read_text()) for n in ('owner-clean.json','gamma-python-final.json','ledger-python-final.json','inventory-clean.json','executor-census.json','typed-ledger.json','flag-build-baseline.json','flag-build-pooled.json','flag-run-baseline.json','flag-run-pooled.json')]
assert all(c['exit_code']==0 and not c['git_dirty'] for c in checks)
gamma=json.loads((out/'c71-gamma-screen-20261010-102ecf02.json').read_text())
batches=json.loads((out/'gamma/batch-execution.json').read_text()); recipes=json.loads((out/'gamma/recipe-execution.json').read_text())
ledger=json.loads((run/'typed-ledger.log').read_text())
comparison=json.loads((run/'flag-counter-comparison.json').read_text())
files=[]
for p2 in sorted(out.rglob('*')):
 if p2.is_file():files.append(dict(path=str(p2.relative_to(root)),bytes=p2.stat().st_size,sha256=hashlib.sha256(p2.read_bytes()).hexdigest()))
result=dict(schema='volta-c71-local-exploration-v1',source_git_sha=sha,git_dirty=False,initial_source_git_sha='072de372a3d1038b037856950bfffb84657920af',branch='exploration/c71-local-20261010',reused_clean_measurement_source_git_sha='102ecf02ab98f0e6b0aa5d45483ebb874bddcaca',test_fixture_followup_source_git_sha=sha,followup_scope='Only cold-replay fixture expectations and marker changed after primary measurements; production runtime, compiler and Gamma scripts unchanged. Initial replay failure retained, corrected filter recompiled and rerun clean.',recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),credit=False,gpu_execution=False,hardware_execution=False,paid_campaign_authorized=False,gamma_admitted_reference_unchanged=True,alternative_gamma_admitted=False,complete_work=False,complete_physical_peak=False,scope='Clean local implementation checks and public/reduced Gamma screening after closed H100 campaign; preliminary failures retained separately; no packed weights or complete traces present/downloaded.',artifacts=files,passed_tests=dict(rust=rust_passed,python=11,total=rust_passed+11),local_limits=dict(test_deadline_s=60,test_AS_bytes=2*1024**3,workers=1,serial_tests=True,build_deadline_s=120,build_aggregate_RSS_stop_bytes=3*1024**3),flag_counter_comparison=comparison,analytical_executor_census=json.loads((run/'executor-census.log').read_text()),typed_ledger=dict(phases=len(ledger['named_phase_crosschecks']),maximum_named_payload_bytes=max(p['named_allocation_subtotal_bytes'] for p in ledger['named_phase_crosschecks']),joint_admitted=ledger['joint_admitted'],physical_allowance_verified=ledger['allowance_physically_verified'],maximum_phase=max(ledger['named_phase_crosschecks'],key=lambda p:p['named_allocation_subtotal_bytes']),ledger_output_sha256=hashlib.sha256((run/'typed-ledger.log').read_bytes()).hexdigest()),gamma_screen=dict(report='c71-gamma-screen-20261010-102ecf02.json',program_batches=len(batches['records']),unique_program_recipes=398,all_batches_passed=batches['all_batches_completed'],ranking_by_partial_core=gamma['candidate_ranking_by_selected_partial_RMS_multiplications'],operational_priority=['rms-even-coarser','rms-even-finer'],discarded_as_optimizations=['rms-output-coarser-control','rms-output-finer-one'],candidates=gamma['candidates'],full_recipe_execution=recipes),clean_regression_failure=failed_reports,development_failures='dev-owner, dev-owner-assertion, gamma-python and ledger-python logs retained; original esiti not replaced. Initial /usr/bin/time absence and calibration test-harness selection are operational failures/adjustments, documented in operational-notes.json.',remaining=['Real CUDA parity for current owner; counter/wall comparison with original runtime on representative H100 input','Attributed owner and CUDA API/driver activity around A HBM spike; simultaneous W commitment/setup retained state','Optimized inference engine same-workload comparison absent','Gamma real-weight numeric/quality validation, tables, two complete replays, independent exact trace, full admission checks, complete resource/correlation/security envelope','No complete proof/verification time, no 65-second result; CPU/fake-driver timing is not H100 speed prediction'])
(root/'benchmarks/results'/f'{name}.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps(dict(path=str(out.relative_to(root)),artifacts=len(files),rust_passed=rust_passed,ledger_max=result['typed_ledger']['maximum_named_payload_bytes'])))
