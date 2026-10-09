import datetime
import hashlib
import json
import pathlib
import platform
import re
import shutil
import subprocess

root = pathlib.Path('/home/okrame/projects/volta-zk')
suite = json.loads(pathlib.Path('/tmp/c71-salts-clean-complete-checks-20261009-02.json').read_text())
sha = suite['source_git_sha']
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip() == sha
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
assert len(suite['checks']) == 15
assert all(c['exit_code']==(124 if c['name']=='range-macs' else 0) for c in suite['checks'])
name = 'c71-crypto-salts-owner-local-2026-10-09-' + sha[:12]
record_path = root / 'benchmarks/results' / (name + '.json')
logs = record_path.with_suffix('').with_name(name + '-logs')
assert not record_path.exists() and not logs.exists()
logs.mkdir()
manifest = []

def save(path):
    path = pathlib.Path(path)
    destination = logs / path.name
    assert not destination.exists()
    shutil.copyfile(path,destination)
    relative = str(destination.relative_to(root))
    manifest.append(dict(path=relative,bytes=destination.stat().st_size,
        sha256=hashlib.sha256(destination.read_bytes()).hexdigest()))
    return relative

checks = []
metrics = {}
traces = []
rust_tests = python_tests = 0
for original in suite['checks']:
    c = dict(original)
    text = pathlib.Path(c['log']).read_text()
    c['log'] = save(c['log'])
    save(pathlib.Path(original['log']).with_suffix('.json'))
    if c['exit_code']:
        c.update(kind='rust_obligation',passed=0,
            status='TIMEOUT_LOCAL_CPU_FULL_LOOKUP_GKR_WHIR_CHAIN',credit=False)
    elif c['name']=='build':
        c['kind'] = 'warm_build'
    elif c['name'] in ['cpp','docs']:
        c['kind'] = 'python'
        c['passed'] = int(re.search(r'(\d+) passed',text).group(1))
        python_tests += c['passed']
    else:
        c['kind'] = 'rust'
        result = re.search(r'test result: ok\. (\d+) passed; 0 failed; 0 ignored;',text)
        assert result
        c['passed'] = int(result.group(1)); assert c['passed']
        rust_tests += c['passed']
    checks.append(c)
    for line in text.splitlines():
        match = re.search(r'(C71_[A-Z0-9_]+) (\{.*\})$',line)
        if match:
            metrics.setdefault(match.group(1),[]).append(json.loads(match.group(2)))
        trace = re.search(r'C71_NATIVE_[AW]_CHAIN_PROGRESS (\S+)$',line)
        if trace:
            path = pathlib.Path(trace.group(1))
            traces.append(dict(path=save(path),records=len(path.read_text().splitlines()),
                provenance='clean reduced composed proof; original numeric fixtures; no private inputs'))
preliminary = []
for path in sorted(pathlib.Path('/tmp').glob('c71-salts-*.json')):
    if 'clean-' in path.name or path.name.endswith('suite-20261009-01.json'):
        continue
    log = path.with_suffix('.log')
    if not log.exists():
        continue
    c = json.loads(path.read_text())
    c.update(log=save(log),record_run=False,git_dirty=True)
    save(path)
    preliminary.append(c)
for file in ['/tmp/c71-local-check-20261008.py','/tmp/c71-salts-clean-suite-20261009.py',
    '/tmp/c71-salts-dev-suite-20261009.py','/tmp/c71-salts-record-20261009.py',
    '/tmp/c71-salts-clean-suite-20261009-01.json','/tmp/c71-salts-clean-tail-20261009.py',
    '/tmp/c71-salts-clean-complete-checks-20261009-02.json']:
    save(file)
sources = [
    'cuda/c71_range_runtime.cpp','cuda/c71_range_runtime.h','cuda/c71_pcs_salts.cu','cuda/c71_pcs_salts.cuh',
    'rust/volta-pcs/src/c71_matrix/b12.rs','rust/volta-pcs/src/c71_matrix/b12/replay.rs',
    'rust/volta-pcs/src/c71_matrix/b12/replay_tree.rs','rust/volta-pcs/src/c71_matrix/range/windowed/native.rs',
    'tests/c71_range_runtime_host.cpp','tests/c71_pcs_salts_host.cpp','tests/test_c71_range_native.py',
]
inputs = {file:hashlib.sha256(subprocess.check_output(['git','show',sha+':'+file],cwd=root)).hexdigest()
    for file in sources}
binary = root / 'rust/target/debug/deps/volta_pcs-4cb98f0e88b6e8d1'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == suite['binary_sha256']
test_checks = [c for c in checks if c['kind']!='warm_build']
record = dict(schema='c71-crypto-preparation-local-v1',date='2026-10-09',
    recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    status='PASS_LOCAL_PRIVATE_SALTS_COMMON_OWNER_AND_W_A_TREE; CPU_LOOKUP_GKR_WHIR_CHAIN_TIMEOUT',credit=False,
    source_git_sha=sha,git_dirty=False,baseline='9033c64',goal_complete=False,goal_status='active',
    canonical_diagnostic='benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json',
    prior_stage='benchmarks/results/c71-crypto-components-local-2026-10-09-44acc7d49bf2.json',
    readiness=dict(GPU_XOF_owner_and_Tree_integrated=True,resident_A_initial_Tree_selected=True,
        resident_A_query_and_S1_integrated=False,Tensor_Core_default_selected=False,
        QK_PV_MMA_selected=False,H100_campaign_authorized=False),
    provenance=dict(platform=platform.platform(),machine=platform.machine(),gpu_execution=False,
        cuda_compilation=False,inputs_sha256=inputs,gamma_identities_unchanged=True,
        native_fixture='deferred fake driver; owner g++ O2 Werror UBSan, Rust root O0/dependencies O2',
        CUDA_prescan_hierarchy_execution=False,
        prescan_oracle='sequential independent stream in fake driver; original BLAKE3 Rust stream and leaf digests',
        clean_suite='each invocation asserted clean tree and same SHA/binary digest before and after',
        warm_cargo='clean build reused exact binary of tree-build-pre02; full build 55.4205 s / 2483286016 B separately',
        full_build_tree_input_identity='final dirty build source tree committed unchanged at source_git_sha; Cargo fingerprints and binary digest unchanged'),
    binary=dict(path=str(binary.relative_to(root)),bytes=binary.stat().st_size,sha256=suite['binary_sha256']),
    checks=checks,metrics=metrics,durable_traces=traces,preliminary_checks=preliminary,
    failures_preserved=[
        dict(log='c71-salts-owner-build-pre01-20261009.log',exit_code=101,
            reason='E0282 Result inference; fixed explicit private capability result type; no test ran'),
        dict(log='c71-salts-w-tree-pre01-20261009.log',exit_code=101,
            reason='old D2H accounting assertion 4328 expected vs 8996 actual; fixed complete control-transfer ledger; root/opening checks in later passing runs'),
        dict(log='c71-salts-clean-range-macs-20261009-01.log',exit_code=124,
            reason='unchanged full CPU lookup/GKR/WHIR positive test exceeded 60 s; last output initial_commit_A. Not a pass or a localized proof-stage timing; no extended timeout or retry'),
    ],
    invariants=dict(private_capability='opaque nonclone token tied to common Rust owner; kind17 never publicly allocatable/readable/releasable',
        stream='same domain/NUL/seed, logical cursor, LE rejection and finite cap 2^40; advance host sampler exactly once after prescan, discard prefetch',
        replay='one owner stream; same sticky hash flag; cursor/consumption verified after fence; no salt H2D',
        publication='digest read denied until all groups/replay/current cursors complete and private buffers retire',
        A_reconstructions=512,W_equivalent_scans=128,canonical_counts='analytical pinned schedule; not measured canonical workload',
        MACs='original VOLE authenticated values and one-time correlations; real AES PCG unchanged; PCS Fp3 and transcript unchanged'),
    accounting=dict(rust_tests=rust_tests,python_tests=python_tests,checks=len(checks),
        max_test_or_descendant_rss_bytes=max(c['max_rss_bytes'] for c in test_checks),
        max_test_wall_s=max(c['wall_s'] for c in test_checks),
        max_passing_test_wall_s=max(c['wall_s'] for c in test_checks if c['exit_code']==0),
        failed_checks=sum(c['exit_code']!=0 for c in checks),
        AS_per_test_bytes=2<<30,deadline_s=60,workers=1,
        serial=True,owner_host_bytes=37288,owner_stats_bytes=152,Rust_API_additional_bytes=48,
        salted_band_host_bytes=0,salt_seed_metadata_H2D_bytes=168,
        private_device_metadata_aligned_bytes=256,private_prescan_scratch_aligned_bytes=10519552,
        W_private_prescan_phase_bytes=27297024,A_private_prescan_phase_bytes=23102720,
        private_prescan_phase_retires_before_field_buffers=True,
        resource_scope='named geometry/phase envelope only; joint reduced Budget measured, complete canonical host/device/physical peak still open'),
    remaining=[
        'compile and verify actual CUDA prescan/select/replay and sm_90 kernels in newly authorized campaign',
        'resident A initial queries and S1; exact PCS v^3=v+1 FFT/remainders, bounded original readers and retention order',
        'GPU linear/GKR/range and attention selection/synchronizations according to measured profile',
        'full simultaneous capacities/physical envelope; separate installation/setup/inference/proof/verification and target measurements',
    ],
    artifact_manifest=manifest,artifacts=len(manifest))
with record_path.open('x') as output:
    json.dump(record,output,indent=2); output.write('\n')
print(json.dumps(dict(record=str(record_path.relative_to(root)),sha256=hashlib.sha256(record_path.read_bytes()).hexdigest(),
    source_git_sha=sha,rust_tests=rust_tests,python_tests=python_tests,artifacts=len(manifest),
    max_test_rss=record['accounting']['max_test_or_descendant_rss_bytes'],max_test_wall=record['accounting']['max_test_wall_s'])))
