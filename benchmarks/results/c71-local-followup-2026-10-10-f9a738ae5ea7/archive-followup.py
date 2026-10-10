import datetime, hashlib, json, pathlib, shutil, subprocess

root = pathlib.Path('/home/okrame/projects/volta-zk')
run = pathlib.Path(__file__).parent
sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
assert sha == 'f9a738ae5ea77da98fa0dbaffa369480fcb9b0f5'
assert not subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root)
stem = 'c71-local-followup-2026-10-10-' + sha[:12]
out = root / 'benchmarks/results' / stem
out.mkdir()
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
files = []
def copy(source, name):
    target = out / name
    target.parent.mkdir(parents=True, exist_ok=True)
    assert not target.exists()
    shutil.copy2(source, target)
    files.append(dict(path=str(target.relative_to(root)), bytes=target.stat().st_size, sha256=digest(target)))

for p in sorted(run.iterdir()):
    if p.suffix in {'.json', '.log', '.su'} or p.name in {
        'run-check.py', 'run-zero-comparison.py', 'public-zero-census.cpp',
        'range-runtime-8421fada.cpp', 'archive-followup.py'}:
        copy(p, p.name)
copy(pathlib.Path('/tmp/c71-gamma-packed-upper-20261010-02.py'), 'packed-analytic-upper.py')
excluded = []
for folder in ('zero-fixtures', 'trace-fixtures'):
    for p in sorted((run / folder).rglob('*')):
        if p.is_symlink():
            excluded.append(dict(path=str(p), reason='fixture symlink; target file preserved separately', target=str(p.readlink())))
        elif p.is_file():
            if p.suffix == '.jsonl':
                copy(p, str(p.relative_to(run)))
            else:
                excluded.append(dict(path=str(p), bytes=p.stat().st_size, sha256=digest(p), reason='built fixture binary; source and command preserved'))
for name in ('public-zero-baseline', 'public-zero-zero', 'owner-trace-stack'):
    p = run / name
    excluded.append(dict(path=str(p), bytes=p.stat().st_size, sha256=digest(p), reason='built fixture binary; source and command preserved'))

builds = []
for label, build_sha, binary_sha in (
    ('build-lib', 'e785fb1e848b7094b843bab8f068e1356c733328', '2ff305ed5e729bdab0567f9742f44a0ed4186d7baaeb2dd57291d39d9d535ca4'),
    ('build-lib-corrected', sha, 'eea6280439224ece4f3a5bc687749e9467c299e06e0760ccbb610698dc5114b1')):
    builds.append(dict(report=str((out / (label + '.json')).relative_to(root)), source_git_sha=build_sha,
        git_dirty=False, binary='rust/target/debug/deps/volta_pcs-b3228fb890c6a4d7', binary_sha256=binary_sha,
        build_monitor='benchmarks/results/c71-crypto-rms-local-2026-10-09-abd2de09efb4/c71-build-monitor-120-20261009.py'))
assert digest(root / builds[-1]['binary']) == builds[-1]['binary_sha256']
old_labels = ('gamma-weighted', 'gamma-unweighted', 'progress-clock', 'metadata-bound',
              'resident-pointwise', 'device-replay', 'source-mac-chain', 'linear-mac-chain')
checks = []
for p in sorted(run.glob('*.json')):
    value = json.loads(p.read_text())
    if 'exit_code' not in value or 'command' not in value: continue
    label = p.stem
    development = label.startswith('dev-')
    if not development:
        assert not value['git_dirty'] if 'git_dirty' in value else True
    item = dict(label=label, report=str((out / p.name).relative_to(root)), exit_code=value['exit_code'],
                wall_s=value['wall_s'], max_rss_bytes=value['max_rss_bytes'], development=development)
    if label in old_labels: item['binary_sha256'] = builds[0]['binary_sha256']
    if label in ('gamma-weighted-corrected', 'gamma-unweighted-corrected'): item['binary_sha256'] = builds[1]['binary_sha256']
    checks.append(item)

source_names = ('cuda/c71_dense_i16.cu', 'cuda/c71_dense_i16.cuh', 'cuda/c71_range_runtime.cpp',
    'cuda/c71_owner_trace.h', 'scripts/c71_executor_profile.py', 'scripts/c71_campaign_measure.py',
    'tests/c71_range_runtime_host.cpp', 'tests/c71_owner_trace_host.cpp', 'tests/c71_owner_trace_runtime_host.cpp',
    'tests/test_c71_range_native.py', 'tests/test_c71_owner_trace.py', 'tests/test_c71_campaign_measure.py',
    'rust/volta-pcs/src/c71_matrix/progress.rs', 'rust/volta-pcs/src/c71_matrix/gemma/native/canonical_metrics.rs',
    'rust/volta-pcs/src/c71_matrix/rms/gkr/gamma_screen_fixture.rs')
source_hashes = {name: digest(root / name) for name in source_names}
previous = root / 'benchmarks/results/c71-local-exploration-2026-10-10-f71a12519ad9.json'
previous_value = json.loads(previous.read_text())
reused_receipts = []
for entry in previous_value['artifacts']:
    p = root / entry['path']
    assert p.stat().st_size == entry['bytes'] and digest(p) == entry['sha256'], p
reused_receipts.append(dict(path=str(previous.relative_to(root)), sha256=digest(previous),
    linked_artifacts_verified=len(previous_value['artifacts']), scope='all retained artifacts of the previous local record; no packed or full trace acquisition'))

packed = json.loads((run / 'packed-analytic-upper-output.json').read_text())
census = json.loads((run / 'executor-census.log').read_text())
result = dict(schema='volta-c71-local-followup-v1', recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    source_git_sha=sha, git_dirty=False, branch='exploration/c71-local-20261010', credit=False,
    gpu_execution=False, hardware_performance=False, complete_proof=False, alternative_gamma_admitted=False,
    baseline_local_git_sha='8421fada206669641b2800aae94b4016004c9ccc',
    baseline_campaign_git_sha='072de372a3d1038b037856950bfffb84657920af',
    source_sha256=source_hashes, builds=builds, checks=checks, artifacts=files,
    excluded_artifacts=excluded, reused_receipts=reused_receipts,
    public_zero_comparison=json.loads((run / 'zero-counter-comparison.json').read_text()),
    analytic_executor_census=census,
    packed_analytic_upper=dict(report=str((out / 'packed-analytic-upper-output.json').relative_to(root)),
        maxima={name: row['maxima'] for name, row in packed['candidates'].items()},
        comparison_scope=packed['comparison_scope'], complete_physical_peak=False),
    diagnostic_trace=dict(default_host_owner_bytes=42096, diagnostic_host_owner_bytes=42128,
        additional_owner_state_bytes=32, maximum_records=131072, maximum_file_bytes=16777216,
        local_header_static_open_frame_bytes=4288, local_header_static_emit_frame_bytes=656,
        conservative_open_stack_reservation_bytes=8192, conservative_emit_stack_reservation_bytes=1024,
        stack_scope='local g++ O2 header fixture static frames; caller, libc, CUDA, profiler and target compiler must be counted separately',
        file_cache_scope='up to the bounded file content; may survive close, filesystem/profiler overhead excluded',
        a_group_scope='last validated source_begin; next-group preparatory allocations can carry the preceding group',
        selected_window_complete_on_real_workload=False, clock='CLOCK_MONOTONIC',
        native_cuda_events_or_correlation_ids=False, cuda_compilation=False),
    failures_preserved=[
        dict(label='dev-owner-zero', reason='sticky fixture selected a valid signed32 first word; fixed synthetic input without changing production', credit=False),
        dict(label='gamma-unweighted', source_git_sha=builds[0]['source_git_sha'],
            reason='selected indices missed positive X because two indices aliased modulo17; fixed index16 preserves row/W/coverage and checks',
            corrected_commit=sha, corrected_check='gamma-unweighted-corrected', credit=False)],
    compatibility='f9a738ae changes only test selection/comment in gamma_screen_fixture.rs; unchanged production hashes retain earlier passing regression provenance; corrected Gamma tests use the rebuilt binary',
    limits='tests serial 60s / AS2GiB /1worker; targeted Rust builds120s /onejob /64codegenunits /aggregateRSS stop3GiB; no extensions',
    exclusions='no pod/start/restart/spending/heavy run; no packed/full trace download; no H100 time claim, no Gamma quality/admission or full two-role physical bound')
with (root / 'benchmarks/results' / (stem + '.json')).open('x') as f:
    json.dump(result, f, indent=2, sort_keys=True); f.write('\n')
print(json.dumps(dict(record=stem, artifacts=len(files), bytes=sum(x['bytes'] for x in files), checks=len(checks), previous_artifacts_verified=len(previous_value['artifacts']))))
