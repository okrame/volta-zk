import datetime
import hashlib
import json
import pathlib
import platform
import re
import shutil
import subprocess

root=pathlib.Path('/home/okrame/projects/volta-zk')
suite_path=pathlib.Path('/tmp/c71-linear-clean-suite-20261009-01.json')
suite=json.loads(suite_path.read_text())
sha=suite['source_git_sha']
assert sha=='31280382f6814a929f7651cd2c31fdd73e668952' and len(suite['checks'])==11
assert all(c['exit_code']==0 and not c['git_dirty'] and c['source_git_sha']==sha for c in suite['checks'])
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==sha
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
name='c71-crypto-linear-local-2026-10-09-'+sha[:12]
record_path=root/'benchmarks/results'/(name+'.json')
logs=record_path.with_name(name+'-logs')
assert not record_path.exists() and not logs.exists()
logs.mkdir()
manifest=[]
def save(path):
    path=pathlib.Path(path); target=logs/path.name
    assert not target.exists()
    shutil.copyfile(path,target); target.chmod(0o600)
    relative=str(target.relative_to(root))
    manifest.append(dict(path=relative,bytes=target.stat().st_size,
        sha256=hashlib.sha256(target.read_bytes()).hexdigest()))
    return relative

checks=[]; metrics={}; rust_tests=python_tests=0
for original in suite['checks']:
    c=dict(original); contents=pathlib.Path(c['log']).read_text()
    c['log']=save(c['log']); save(pathlib.Path(original['log']).with_suffix('.json'))
    c['kind']='warm_build' if c['name']=='build' else 'python' if c['name'] in ['components','docs'] else 'rust'
    if c['kind']=='rust': rust_tests+=c['passed']
    if c['kind']=='python': python_tests+=c['passed']
    checks.append(c)
    for line in contents.splitlines():
        match=re.search(r'(C71_[A-Z0-9_]+) (\{.*\})$',line)
        if match: metrics.setdefault(match.group(1),[]).append(json.loads(match.group(2)))
preliminary=[]
paths=set(pathlib.Path('/tmp').glob('c71-linear-*-pre*-20261009.json'))
paths.add(pathlib.Path('/tmp/c71-pcs-residual-helper-pre01-20261009.json'))
for path in sorted(paths):
    c=json.loads(path.read_text())
    if 'log' not in c: continue
    c.update(log=save(path.with_suffix('.log')),record_run=False,git_dirty=True)
    save(path); preliminary.append(c)
for path in ['/tmp/c71-local-check-20261008.py','/tmp/c71-build-monitor-20261009.py',
             '/tmp/c71-linear-pre-suite-20261009.py','/tmp/c71-linear-pre-suite-20261009-01.json',
             '/tmp/c71-linear-clean-20261009.py','/tmp/c71-linear-record-20261009.py',str(suite_path)]:
    save(path)
sources=subprocess.check_output(['git','diff-tree','--no-commit-id','--name-only','-r',sha],cwd=root,text=True).splitlines()
sources += ['cuda/c71_linear_native.cuh','cuda/c71_linear_native.cu','tests/c71_linear_native_host.cpp',
    'tests/test_c71_linear_native.py','cuda/c71_pcs_residual.cuh','cuda/c71_pcs_residual.cu',
    'tests/c71_pcs_residual_host.cpp','tests/test_c71_pcs_residual.py']
inputs={p:hashlib.sha256(subprocess.check_output(['git','show',sha+':'+p],cwd=root)).hexdigest() for p in sources}
binary=root/'rust/target/debug/deps/volta_pcs-efe6791186972026'
assert hashlib.sha256(binary.read_bytes()).hexdigest()==suite['binary_sha256']
tests=[c for c in checks if c['kind']!='warm_build']
build=json.loads(pathlib.Path('/tmp/c71-linear-rust-build-pre01-20261009.json').read_text())
align=lambda value:(value+255)&~255
def device_bound(intervals,points):
    return sum(map(align,[32,5*16,1280*24,35*16,intervals*64,points*24]))+2*256
record=dict(
    schema='c71-crypto-preparation-local-v1',date='2026-10-09',
    recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    status='PASS_LOCAL_RESIDENT_ORIGINAL_LINEAR_OWNER_CALLER_AND_REDUCED_FULL_WIRE',
    credit=False,source_git_sha=sha,git_dirty=False,baseline='9033c64',goal_complete=False,goal_status='active',
    canonical_diagnostic='benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json',
    prior_stage='benchmarks/results/c71-crypto-query-local-2026-10-09-46d295ef4ea6.json',
    readiness=dict(GPU_linear_owner_caller_integrated=True,resident_A_initial_query_caller_integrated=True,
        resident_A_S1_integrated=False,S1_arithmetic_helper_checked_only=True,H100_campaign_authorized=False),
    provenance=dict(platform=platform.platform(),machine=platform.machine(),gpu_execution=False,
        cuda_compilation=False,inputs_sha256=inputs,gamma_identities_unchanged=True,
        native_fixture='deferred fake CUDA driver, host helper reductions and independent dense Rust oracle; no CUDA kernel or scheduling execution',
        clean_suite='same clean source SHA and binary digest checked before/after every invocation; no later S1 owner/caller edit is covered',
        composed_scope='D10 native signed-W linear sumcheck/terminal on CPU initial commitment and CPU PCS, identical full proof wire/FS/point/original ideal MAC and verifier; A original codec/endpoints and failed-round tests separately',
        build='one job, incremental disabled, crate O0/dependencies O2, 256 codegen units, existing one-thread LLD, overflow checks retained'),
    binary=dict(path=str(binary.relative_to(root)),bytes=binary.stat().st_size,sha256=suite['binary_sha256']),
    checks=checks,metrics=metrics,preliminary_checks=preliminary,
    failures_preserved=[dict(log='c71-linear-docs-pre01-20261009.log',exit_code=1,
        reason='four C API names were mistaken for Rust test filters by documentation check; signatures now include (...) without weakening test or code guards')],
    review=dict(independent_agent=True,finding='fixture INT16_MIN cannot be uploaded or multiplied as signed original; corrected before compilation',
        resolution='produce admitted u16 slack with canonical argmax resident route; use distinct symmetric raw-i48 input; runtime guards unchanged'),
    invariants=dict(fields='linear uses original MAC Fp3 u^3=2; canonical limb marshalling, no PCS basis reinterpretation',
        equality='bounded eight-bit prefix tables, dyadic residuals, duplicate/overlapping cubes and zero/one/extension challenges preserve dense coefficients and endpoints',
        NoPeek='numeric A producer receives emitter only; public covectors/challenges stay in consumer; A scanner owns unique trusted partition',
        owner='same original buffer/Arc owner and sealed W mapping; begin fences packet uploads, finish fences and validates outputs then retires all three private allocations before publication',
        failure='missing symbols, wrong owner/token/type/span/coverage, producer errors, failed copies/fences/frees and malformed field outputs terminal; no scalar or host-reader fallback',
        correlations='three fresh original correlations consumed only after a completed round, 3D+2 reservation and terminal authenticated endpoint unchanged',
        work='one original A scan or sealed W scan per round; no scans per field limb or public block; W mapping uploaded once per proof and retired after D rounds',
        telemetry='durable per-round work/progress, packet capacity and bounded staging, complete shared owner delta including producer/mapping; owner peak is cumulative'),
    accounting=dict(checks=len(checks),rust_tests=rust_tests,python_tests=python_tests,
        max_test_or_descendant_rss_bytes=max(c['max_rss_bytes'] for c in tests),
        max_test_wall_s=max(c['wall_s'] for c in tests),AS_per_test_bytes=2<<30,deadline_s=60,workers=1,serial=True,
        full_build_wall_s=build['wall_s'],full_build_rss_bytes=build['max_rss_bytes'],
        full_build_sampled_aggregate_peak_bytes=build['sampled_aggregate_live_rss_peak_bytes'],
        owner_host_bytes=37408,owner_host_additional_bytes=120,Stats_bytes=152,Rust_API_additional_bytes=32,
        owner_result_bytes=120,owner_flag_bytes=4,linear_consumer_D2H_bytes_each_round=124,
        linear_consumer_fences_each_round=2,producer_and_mapping_operations_additional=True,
        original_A_commitment_reconstructions=512,linear_A_scans=34,linear_W_scans=35,
        linear_A_result_D2H_bytes=34*124,linear_W_result_D2H_bytes=35*124,
        source_parity_cases=16,additional_public_zero_tail_case=True,owner_rejections=30,
        mandatory_symbol_rejections=4,failed_producer_round_cases=5,independent_dense_host_cases=167,
        independent_dense_host_original_visits=218809,host_helper_rejections=16,
        linear_kernel_shared_bytes=30720,kernel_threads=256,kernel_grid_cap=8192,
        owner_packet_cap_bytes=1<<30,owner_interval_cap=1<<20,owner_point_cap=1<<25,
        owner_maximum_named_aligned_packet_output_flag_bytes=device_bound(1<<20,1<<25),
        Rust_MAX_CUBES=1<<19,Rust_max_residual_points=(1<<19)*34,
        Rust_conservative_named_aligned_packet_output_flag_bytes=device_bound(1<<19,(1<<19)*34),
        packet_host_actual_capacity_and_conservative_bound_logged_each_round=True,
        joint_admitted=False,
        additional_joint_costs='public input forms and borrowed residual descriptors, packet marshalling/staging capacities/realloc; producer/cache/workspace, sealed W metadata; retained Tree/replay/opened rows/paths, PCG/masks, proof/codec, both roles, all other owner allocations and physical runtime margin. Shared memory/registers/spills require real CUDA census'),
    S1_component_scope='pure af1a88d arithmetic only: PCS v^3=v+1, singleton/retention/coset/OOD/fold exact against independent oracle, no S1 common-owner integration/selection/CUDA credit',
    measurements_scope='representative bounded D15/D17 host helper and reduced owner models; Rust O0/C++ O2 timings do not imply H100 speedup or physical admission',
    remaining=['resident S1 commit/OOD/retention/fold, private contractions and extension query/opening consumers preserving existing work and lease ordering',
        'quantified remaining GKR/range/PCG and synchronization profile; exact Tensor W and causal QK/PV comparisons on authorized hardware',
        'complete joint host/device/physical resource ledger and separate installation/setup/inference/proof/verification measurements',
        'sm_90 compilation, actual CUDA parity and performance only on separately authorized H100 hardware/duration'],
    artifact_manifest=manifest,artifacts=len(manifest))
assert rust_tests==10 and python_tests==20
with record_path.open('x') as output:
    json.dump(record,output,indent=2); output.write('\n')
record_path.chmod(0o600)
print(json.dumps(dict(record=str(record_path.relative_to(root)),sha256=hashlib.sha256(record_path.read_bytes()).hexdigest(),
    source_git_sha=sha,rust_tests=rust_tests,python_tests=python_tests,artifacts=len(manifest),
    artifact_bytes=sum(x['bytes'] for x in manifest),max_test_rss=record['accounting']['max_test_or_descendant_rss_bytes'],
    max_test_wall=record['accounting']['max_test_wall_s'],binary_bytes=binary.stat().st_size,
    owner_packet_bytes=record['accounting']['owner_maximum_named_aligned_packet_output_flag_bytes'],
    Rust_packet_bytes=record['accounting']['Rust_conservative_named_aligned_packet_output_flag_bytes'])))
