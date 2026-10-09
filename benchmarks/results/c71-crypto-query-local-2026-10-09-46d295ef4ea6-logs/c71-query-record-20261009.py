import datetime
import hashlib
import json
import pathlib
import platform
import re
import shutil
import subprocess

root=pathlib.Path('/home/okrame/projects/volta-zk')
suite_path=pathlib.Path('/tmp/c71-query-clean-suite-20261009-01.json')
suite=json.loads(suite_path.read_text())
sha=suite['source_git_sha']
assert sha.startswith('46d295e') and len(suite['checks'])==10
assert all(c['exit_code']==0 and not c['git_dirty'] and c['source_git_sha']==sha for c in suite['checks'])
name='c71-crypto-query-local-2026-10-09-'+sha[:12]
record_path=root/'benchmarks/results'/(name+'.json')
logs=record_path.with_name(name+'-logs')
assert not record_path.exists() and not logs.exists()
logs.mkdir()
manifest=[]
def save(path):
    path=pathlib.Path(path)
    target=logs/path.name
    assert not target.exists()
    shutil.copyfile(path,target); target.chmod(0o600)
    relative=str(target.relative_to(root))
    manifest.append(dict(path=relative,bytes=target.stat().st_size,
        sha256=hashlib.sha256(target.read_bytes()).hexdigest()))
    return relative

checks=[]; metrics={}; rust_tests=python_tests=0
for original in suite['checks']:
    c=dict(original)
    contents=pathlib.Path(c['log']).read_text()
    c['log']=save(c['log']); save(pathlib.Path(original['log']).with_suffix('.json'))
    c['kind']='warm_build' if c['name']=='build' else 'python' if c['name'] in ['cpp','docs'] else 'rust'
    if c['kind']=='rust': rust_tests+=c['passed']
    if c['kind']=='python': python_tests+=c['passed']
    checks.append(c)
    for line in contents.splitlines():
        match=re.search(r'(C71_[A-Z0-9_]+) (\{.*\})$',line)
        if match: metrics.setdefault(match.group(1),[]).append(json.loads(match.group(2)))
preliminary=[]
for path in sorted(pathlib.Path('/tmp').glob('c71-query-native-*-pre*-20261009.json')):
    c=json.loads(path.read_text())
    c.update(log=save(path.with_suffix('.log')),record_run=False,git_dirty=True)
    save(path); preliminary.append(c)
for path in ['/tmp/c71-local-check-20261008.py','/tmp/c71-build-monitor-20261009.py',
             '/tmp/c71-query-pre-suite-20261009.py','/tmp/c71-query-native-pre-suite-20261009.json',
             '/tmp/c71-query-clean-20261009.py','/tmp/c71-query-record-20261009.py',str(suite_path)]:
    save(path)
sources=subprocess.check_output(['git','diff-tree','--no-commit-id','--name-only','-r',sha],cwd=root,text=True).splitlines()
inputs={p:hashlib.sha256(subprocess.check_output(['git','show',sha+':'+p],cwd=root)).hexdigest() for p in sources}
binary=root/'rust/target/debug/deps/volta_pcs-efe6791186972026'
assert hashlib.sha256(binary.read_bytes()).hexdigest()==suite['binary_sha256']
tests=[c for c in checks if c['kind']!='warm_build']
builds=[c for c in preliminary if 'build-' in c['log']]
record=dict(
    schema='c71-crypto-preparation-local-v1',date='2026-10-09',
    recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    status='PASS_LOCAL_RESIDENT_INITIAL_A_QUERY_REMAINDERS_AND_UNCACHED_REDUCED_PCS_CHAIN',
    credit=False,source_git_sha=sha,git_dirty=False,baseline='9033c64',goal_complete=False,goal_status='active',
    canonical_diagnostic='benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json',
    prior_stage='benchmarks/results/c71-crypto-transform-local-2026-10-09-e96bd202d527.json',
    readiness=dict(resident_A_initial_query_caller_integrated=True,resident_A_S1_integrated=False,
        GPU_linear_owner_caller_integrated=False,H100_campaign_authorized=False),
    provenance=dict(platform=platform.platform(),machine=platform.machine(),gpu_execution=False,
        cuda_compilation=False,inputs_sha256=inputs,gamma_identities_unchanged=True,
        native_fixture='deferred fake CUDA driver; exact base FFT and query models; independent Rust P3 and direct Horner; no CUDA kernels executed',
        clean_suite='same clean source SHA and binary digest checked before and after every invocation; all checks completed before subsequent edits',
        binary_build='build-pre09 completed in 57.088880157563835 s; one job, incremental disabled; crate O0, dependencies O2, 256 codegen units; existing toolchain LLD with one linker thread; debug overflow checks retained',
        timeout_rusage='wait4 descendant RSS/CPU is incomplete when a timed-out rustc is killed before its parent reaps it; pre06-09 additionally sample all live sandbox descendants at100ms',
        composed_scope='D10 full PCS wire/FS/RNG/original ideal MAC/verifiers; ordinary CPU initial commitment, real uncached native initial-query route; remaining extension PCS CPU'),
    binary=dict(path=str(binary.relative_to(root)),bytes=binary.stat().st_size,sha256=suite['binary_sha256']),
    checks=checks,metrics=metrics,preliminary_checks=preliminary,
    failures_preserved=[dict(log='c71-query-native-build-pre01-20261009.log',exit_code=101,
        reason='ambiguous closure Result error type, fixed with explicit Result<DenseMatrix<Goldilocks>,String>; no tests ran'),
        dict(logs=['c71-query-native-build-pre'+str(i).zfill(2)+'-20261009.log' for i in range(2,9)],
             exit_code=124,reason='60s compile deadline; incomplete artifacts not executed; build strategy changed, limits not extended')],
    invariants=dict(fields='Goldilocks base; PCS v^3=v+1 and MAC u^3=2 unchanged',
        layout='original biased little-endian bytes, column-major polynomial coefficients; original salts/pads, natural roots and duplicate/reversed opening indices retained',
        owner='same numerical owner/stream and original buffer binding; unavailable/pending/foreign/failed readers terminal, no scalar/host-window fallback',
        NoPeek='numeric reader receives runtime and original public interval only; private query spectra/PCS pads remain in consumer',
        replay='exact original window requests match CPU oracle; no extra initial A commitment reconstructions, still512',
        transfer='no original byte D2H; final returned column words plus existing4B original gather flags; CPU creates only public query factors/shift and private PCS pads',
        authentication='original endpoint MACs, fresh reserved correlations, FS wire/order, roots/pads and both verifier results unchanged; no MAC reauthentication',
        salts='mandatory-symbol/private read negative tests preserve completion guard and deny private buffers'),
    accounting=dict(checks=len(checks),rust_tests=rust_tests,python_tests=python_tests,
        max_test_or_descendant_rss_bytes=max(c['max_rss_bytes'] for c in tests),
        max_test_wall_s=max(c['wall_s'] for c in tests),AS_per_test_bytes=2<<30,deadline_s=60,workers=1,serial=True,
        full_build_rss_bytes=2442866688,full_build_sampled_aggregate_peak_bytes=2493812736,
        full_build_wall_s=57.088880157563835,owner_host_bytes=37288,owner_stats_bytes=152,
        Rust_API_additional_bytes=32,query_block_bytes=72,independent_query_parity_cases=75,
        reader_rejections=4,owner_rejections=25,mandatory_symbol_rejections=4,
        q_max=1<<20,message_rows_max=1<<27,pad_rows_max=1536,returned_columns_max=128,
        byte_window_max=1<<28,column_staging_max=8<<20,
        canonical_query_device_named_bytes=1125647872,
        canonical_query_device_breakdown=dict(public_factor_spectra=704643072,
            aligned_forward_inverse_twiddles_all_levels=67110400,optional_pad_shift=16777216,
            low_pad_remainders_work_scratch=67108864,original_field_pads=1572864,original_byte_window=268435456),
        query_buffer_descriptors=93,additional_original_gather_flag_aligned_bytes=256,
        returned_matrix_host_bytes=1073741824,returned_column_staging_host_bytes=8388608,
        maximum_batch_H2D_bytes=722993152,maximum_batch_return_matrix_D2H_bytes=1073741824,
        original_window_flag_D2H_bytes_each=4,original_data_D2H_bytes=0,
        joint_admitted=False,
        additional_joint_costs='public product construction, conversion staging and CPU DFT cache; retained W/A Tree/replay, already-opened requested rows/salts/paths across batches; numeric producer/workspace, PCG/masks, proof/codec, both roles and runtime/physical margin; all remain globally charged',
        lifetime='native query temporary buffers retire before Tree regenerates/copies the current batch; previously opened rows remain live. S1 retention starts only after original A opening/release, so it does not coexist with initial A native-query scratch'),
    measurements_scope='representative bounded local owner/models and harness census; Rust O0 vs C++ O2 timings do not support a speedup claim; no H100 performance, CUDA scheduling or physical admission',
    primary_sources=[dict(url='https://doc.rust-lang.org/cargo/commands/cargo-rustc.html',
        purpose='--profile test selects unit-test mode and flags target only the selected crate'),
        dict(url='https://lld.llvm.org/',purpose='existing GNU-compatible ELF linker; local one-thread link, no new dependency')],
    remaining=['resident S1 commit/OOD/retention/fold and extension opening consumers preserving512initial+35non-queryApasses',
        'GPU original-linear owner/caller, GKR/range/PCG and sync profile, exact attention and Tensor candidate hardware comparisons',
        'complete joint host/device/physical ledger and separate installation/setup/inference/proof/verification measurements',
        'sm_90 compilation and CUDA parity/performance only on a new owner-authorized H100 campaign'],
    artifact_manifest=manifest,artifacts=len(manifest))
assert rust_tests==9 and python_tests==18
with record_path.open('x') as output:
    json.dump(record,output,indent=2); output.write('\n')
record_path.chmod(0o600)
print(json.dumps(dict(record=str(record_path.relative_to(root)),sha256=hashlib.sha256(record_path.read_bytes()).hexdigest(),
    source_git_sha=sha,rust_tests=rust_tests,python_tests=python_tests,artifacts=len(manifest),
    artifact_bytes=sum(x['bytes'] for x in manifest),max_test_rss=record['accounting']['max_test_or_descendant_rss_bytes'],
    max_test_wall=record['accounting']['max_test_wall_s'])))
