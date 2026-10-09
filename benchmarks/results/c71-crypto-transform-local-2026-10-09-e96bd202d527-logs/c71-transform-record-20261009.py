import datetime
import hashlib
import json
import pathlib
import platform
import re
import shutil
import subprocess

root = pathlib.Path('/home/okrame/projects/volta-zk')
suite_path = pathlib.Path('/tmp/c71-transform-clean-suite-20261009-01.json')
suite = json.loads(suite_path.read_text())
sha = suite['source_git_sha']
assert sha == 'e96bd202d5279c8013c659649d2e703f99f7bd60'
assert len(suite['checks']) == 5
assert all(c['exit_code'] == 0 and not c['git_dirty'] and c['source_git_sha'] == sha
           for c in suite['checks'])
name = 'c71-crypto-transform-local-2026-10-09-' + sha[:12]
record_path = root / 'benchmarks/results' / (name + '.json')
logs = record_path.with_name(name + '-logs')
assert not record_path.exists() and not logs.exists()
logs.mkdir()
manifest = []

def save(path):
    path = pathlib.Path(path)
    destination = logs / path.name
    assert not destination.exists()
    shutil.copyfile(path, destination)
    destination.chmod(0o600)
    relative = str(destination.relative_to(root))
    manifest.append(dict(path=relative, bytes=destination.stat().st_size,
                         sha256=hashlib.sha256(destination.read_bytes()).hexdigest()))
    return relative

checks = []
metrics = {}
rust_tests = python_tests = 0
for original in suite['checks']:
    c = dict(original)
    contents = pathlib.Path(c['log']).read_text()
    c['log'] = save(c['log'])
    save(pathlib.Path(original['log']).with_suffix('.json'))
    if c['name'] == 'build':
        c['kind'] = 'warm_build'
    elif c['name'] in ['cpp', 'docs']:
        c['kind'] = 'python'
        c['passed'] = int(re.search(r'(\d+) passed', contents).group(1))
        python_tests += c['passed']
    else:
        c['kind'] = 'rust'
        c['passed'] = int(re.search(r'test result: ok\. (\d+) passed; 0 failed;', contents).group(1))
        rust_tests += c['passed']
    checks.append(c)
    for line in contents.splitlines():
        match = re.search(r'(C71_[A-Z0-9_]+) (\{.*\})$', line)
        if match:
            metrics.setdefault(match.group(1), []).append(json.loads(match.group(2)))

preliminary = []
for path in sorted(pathlib.Path('/tmp').glob('c71-transform-*-pre*-20261009.json')):
    c = json.loads(path.read_text())
    c.update(log=save(path.with_suffix('.log')), record_run=False, git_dirty=True)
    save(path)
    preliminary.append(c)
for path in ['/tmp/c71-local-check-20261008.py', '/tmp/c71-transform-clean-20261009.py',
             '/tmp/c71-transform-record-20261009.py', str(suite_path)]:
    save(path)
sources = subprocess.check_output(['git', 'diff-tree', '--no-commit-id', '--name-only', '-r', sha],
                                  cwd=root, text=True).splitlines()
inputs = {path: hashlib.sha256(subprocess.check_output(['git', 'show', sha + ':' + path],
                                                     cwd=root)).hexdigest() for path in sources}
binary = root / 'rust/target/debug/deps/volta_pcs-4cb98f0e88b6e8d1'
assert hashlib.sha256(binary.read_bytes()).hexdigest() == suite['binary_sha256']
test_checks = [c for c in checks if c['kind'] != 'warm_build']
record = dict(
    schema='c71-crypto-preparation-local-v1', date='2026-10-09',
    recorded_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    status='PASS_LOCAL_NATURAL_FORWARD_INVERSE_TRANSFORM_COMMON_OWNER_AND_W_REGRESSION',
    credit=False, source_git_sha=sha, git_dirty=False, baseline='9033c64',
    goal_complete=False, goal_status='active',
    canonical_diagnostic='benchmarks/results/c71-cuda-experiment-2026-10-07-868a3e8.json',
    prior_stage='benchmarks/results/c71-crypto-salts-owner-local-2026-10-09-f85f6a77dbb2.json',
    readiness=dict(common_owner_natural_transform_integrated=True,
                   resident_A_initial_query_caller_integrated=False,
                   resident_A_S1_integrated=False, H100_campaign_authorized=False),
    provenance=dict(platform=platform.platform(), machine=platform.machine(),
                    gpu_execution=False, cuda_compilation=False, inputs_sha256=inputs,
                    gamma_identities_unchanged=True,
                    native_fixture='deferred fake CUDA driver; C++ five-pass/odd FFT model compared word-for-word with independent Rust P3 DFT; no CUDA kernels executed',
                    clean_suite='each invocation asserted clean tree and same source SHA/binary digest before and after; completed before subsequent multi-agent edits',
                    warm_cargo='clean build reused exact binary from transform-build-pre03; full build 56.7145 s / 2515423232 B reported separately',
                    full_build_identity='Rust sources committed unchanged; later C++ model normalization and partial D2D-accounting corrections were exercised by the clean dynamically compiled fixture'),
    binary=dict(path=str(binary.relative_to(root)), bytes=binary.stat().st_size,
                sha256=suite['binary_sha256']),
    checks=checks, metrics=metrics, preliminary_checks=preliminary,
    failures_preserved=[dict(log='c71-transform-build-pre01-20261009.log', exit_code=101,
                             reason='E0425 typo &mut0; fixed to &mut 0, no tests ran')],
    invariants=dict(field='Goldilocks base p=2^64-2^32+1; no reinterpretation of PCS v^3=v+1 or MAC u^3=2',
                    transform='natural coefficient/evaluation order; inverse normalized exactly once by 1/N; odd parity packing and even five-pass FFT shared with microbench',
                    owner='same common owner and ordered stream; distinct values/scratch/twiddle buffers; twiddle orientation validated; failures terminal with no CPU fallback',
                    transfer='no H2D after initial values/twiddles; odd log>1 accounts one whole-buffer D2D packing copy even if a later launch fails',
                    download='full canonical PCS_BASE only, bounded to 2^20 words / 8 MiB; generic reads reject active private-salt phase and kind17',
                    W_regression='initial W Tree roots, pads, work and original getter openings unchanged; A schedules untouched'),
    accounting=dict(rust_tests=rust_tests, python_tests=python_tests, checks=len(checks),
                    max_test_or_descendant_rss_bytes=max(c['max_rss_bytes'] for c in test_checks),
                    max_test_wall_s=max(c['wall_s'] for c in test_checks),
                    AS_per_test_bytes=2 << 30, deadline_s=60, workers=1, serial=True,
                    owner_host_bytes=37288, owner_stats_bytes=152, Rust_API_additional_bytes=24,
                    independent_parity_cases=36, terminal_rejection_cases=18,
                    mandatory_symbol_rejections=3, reduced_device_capacity_peak_bytes=8389120,
                    reduced_joint_payload_peak_bytes=24176129, denied_allocations=0,
                    supported_log_lengths=[1,24], supported_batch_max=1 << 20,
                    supported_total_words_max=1 << 28, segment_batch_max=32767,
                    max_row_dynamic_shared_bytes=32768, transpose_dynamic_shared_bytes=16896,
                    query_q_2_pow_20_transform_workspace_bytes=67108864,
                    query_workspace_scope='one values vector, one scratch vector, forward and inverse twiddle at 2q; excludes query factors, original resident window, low/high, pad, output host, Tree/replay and other live owners; not a full admission'),
    measurements_scope='representative local owner/model timings only; no GPU throughput or H100 speedup',
    primary_sources=[dict(url='https://docs.nvidia.com/cuda/cuda-programming-guide/05-appendices/compute-capabilities.html',
                          accessed_on='2026-10-09', purpose='grid.y/z limit 65535; odd half-batch split requires at most 32767 original polynomials per five-pass launch')],
    remaining=['resident initial A query caller and factors/remainders with unchanged window/reconstruction count',
               'resident PCS S1, GPU linear/GKR/range, exact attention selection and synchronizations according to profile',
               'complete joint host/device/physical admission and separate installation/setup/inference/proof/verification measurements',
               'actual sm_90 compilation/parity/performance in a newly owner-authorized H100 campaign'],
    artifact_manifest=manifest, artifacts=len(manifest))
assert rust_tests == 5 and python_tests == 18
with record_path.open('x') as output:
    json.dump(record, output, indent=2)
    output.write('\n')
record_path.chmod(0o600)
print(json.dumps(dict(record=str(record_path.relative_to(root)),
                      sha256=hashlib.sha256(record_path.read_bytes()).hexdigest(),
                      source_git_sha=sha, rust_tests=rust_tests, python_tests=python_tests,
                      artifacts=len(manifest), artifact_bytes=sum(x['bytes'] for x in manifest),
                      max_test_rss=record['accounting']['max_test_or_descendant_rss_bytes'],
                      max_test_wall=record['accounting']['max_test_wall_s'])))
