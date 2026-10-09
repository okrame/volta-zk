import hashlib
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path('/home/okrame/projects/volta-zk')
manifest_path = pathlib.Path('/tmp/c71-query-e-rust-20261009/manifest.json')
manifest = json.loads(manifest_path.read_text())
binary = root/'rust/target/debug/deps/volta_pcs-efe6791186972026'
report_path = pathlib.Path('/tmp/c71-s1-query-final-suite-20261009.json')
ledger_logs = pathlib.Path('/tmp/c71-s1-query-final-ledger-logs-20261009')
claim_record = root/'benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1.json'
claim_log = root/'benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1-logs/c71-closure-retire-clean-claim-20261009.log'
reuse_a_prefix = pathlib.Path('/tmp/c71-s1-query-final-first-a-20261009')
expected_source = '9a5da712a2583be520fe342dfaa278c9651d60fc'
expected_binary = '102914a10c3db065abed941a82c12a4584b45d7c375e05770ab6f6eb75fab19d'


def digest(path):
    hashed = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1 << 20), b''):
            hashed.update(block)
    return hashed.hexdigest()


def state():
    return {'source_git_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
            'git_status': subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True),
            'binary_sha256': digest(binary)}


full = [name for name in manifest['serial_filters'] if '_query_full_whir_' in name]
assert len(full) == 2 and any('_full_whir_w_' in name for name in full) and any('_full_whir_a_' in name for name in full)
full.sort(key=lambda name: 0 if '_full_whir_w_' in name else 1)
checks = [(name, 'full WHIR W' if '_full_whir_w_' in name else 'full WHIR A') for name in full]
checks += [
    ('c71_b12_native_source_composed_full_chain_original_mac_and_transcript', 'D15 A composed, initial rows fixture'),
    ('c71_b12_native_weight_composed_full_chain_original_mac_and_transcript', 'D15 W composed, initial rows fixture'),
    ('c71_canonical_device_original_scan_coverage_rejects_duplicate_and_omitted_rows', 'canonical source-row coverage'),
    ('c71_b12_pcs_resident_source_tiles_original_biased_bytes', 'original biased byte packing'),
    ('c71_b12_native_weight_geometry_and_resource_envelope', 'native initial W geometry envelope'),
    ('c71_b12_native_source_geometry_and_resource_envelope', 'native initial A geometry envelope'),
    ('c71_b12_canonical_extension_geometry_tracks_every_native_stage_without_allocation', 'all extension stages, reference geometry metadata'),
    ('c71_canonical_device_allocation_geometry_without_canonical_buffers', 'canonical producer allocation geometry'),
]
assert len(checks) == 10
assert not report_path.exists()
for number in range(1, 11):
    prefix = pathlib.Path(f'/tmp/c71-s1-query-final-{number:02d}-20261009')
    assert not pathlib.Path(str(prefix) + '.log').exists() and not pathlib.Path(str(prefix) + '.json').exists()
receipt = json.loads(claim_record.read_text())
assert not receipt['git_dirty'] and receipt['accounting']['W_claims_and_proof_released_before_A'] is True
claim_rows = [json.loads(line.split('C71_CLAIM_ALLOCATION_GEOMETRY ', 1)[1])
              for line in claim_log.read_text().splitlines() if 'C71_CLAIM_ALLOCATION_GEOMETRY ' in line]
assert len(claim_rows) == 1 and claim_rows[0]['construction_capacity_released'] is True
initial = state()
assert not initial['git_status'] and initial['source_git_sha'] == expected_source and initial['binary_sha256'] == expected_binary
results = []
for number, (name, label) in enumerate(checks, 1):
    before = state()
    if before != initial:
        results.append({'case': number, 'name': name, 'label': label, 'preflight_failure': 'source or binary changed', 'before': before})
        break
    prefix = pathlib.Path(f'/tmp/c71-s1-query-final-{number:02d}-20261009')
    log, report = str(prefix) + '.log', str(prefix) + '.json'
    command = ['python3', '/tmp/c71-local-check-20261008.py', log, report, '2048', str(binary), name, '--test-threads=1', '--nocapture']
    if '_full_whir_a_' in name:
        reused_log, reused_report = pathlib.Path(str(reuse_a_prefix) + '.log'), pathlib.Path(str(reuse_a_prefix) + '.json')
        result = json.loads(reused_report.read_text())
        expected_command = [str(binary), name, '--test-threads=1', '--nocapture']
        assert result['command'] == expected_command and result['cwd'] == str(root)
        assert result['exit_code'] == 0 and result['as_limit_mib'] == 2048 and result['deadline_s'] == 60
        assert re.search(r'test result: ok\. 1 passed;', reused_log.read_text())
        pathlib.Path(log).symlink_to(reused_log)
        pathlib.Path(report).symlink_to(reused_report)
        result.update(log=log, reused=True, reused_raw_log=str(reused_log), reused_raw_report=str(reused_report),
                      reused_parent_clean_before_after_attestation=True, reused_root_source_sha=expected_source,
                      reused_binary_sha256=expected_binary)
        execution_rc = 0
    else:
        execution = subprocess.run(command, cwd=root, capture_output=True, text=True)
        execution_rc = execution.returncode
        if pathlib.Path(report).is_file():
            result = json.loads(pathlib.Path(report).read_text())
        else:
            result = {'exit_code': execution.returncode, 'wrapper_failure': execution.stderr, 'log': log}
    after = state()
    matched = re.search(r'test result: ok\. (\d+) passed;', pathlib.Path(log).read_text()) if pathlib.Path(log).is_file() else None
    passed = int(matched.group(1)) if matched else 0
    result.update(case=number, name=name, label=label, source_git_sha=initial['source_git_sha'],
                  git_dirty=bool(before['git_status'] or after['git_status']), binary_sha256=initial['binary_sha256'],
                  passed=passed, before=before, after=after, source_and_binary_unchanged=after == initial)
    results.append(result)
    print(json.dumps({'case': number, 'filter': name, 'label': label, 'exit': result['exit_code'], 'passed': passed,
                      'wall_s': result.get('wall_s'), 'max_rss_bytes': result.get('max_rss_bytes'), 'log': log,
                      'source_and_binary_unchanged': after == initial}), flush=True)
    if execution_rc or result['exit_code'] or passed != 1 or after != initial:
        break
success = len(results) == len(checks) and all(not row.get('exit_code', 1) and row.get('passed') == 1
    and row.get('source_and_binary_unchanged') for row in results)
if success:
    for result in results:
        link = ledger_logs/pathlib.Path(result['log']).name
        assert not link.exists() and not link.is_symlink()
        link.symlink_to(result['log'])
with report_path.open('x') as output:
    json.dump({'source_git_sha': initial['source_git_sha'], 'git_dirty': any(row.get('git_dirty') for row in results),
               'binary_sha256': initial['binary_sha256'], 'manifest_path': str(manifest_path),
               'manifest_sha256': digest(manifest_path), 'checks': results, 'complete': success,
               'as_limit_mib': 2048, 'deadline_s': 60, 'workers': 1,
               'skipped_case11': {'name': 'c71_original_claim_batch_releases_construction_capacity',
                   'reason': 'reuse existing clean 96b69de claim capacity marker; no new test',
                   'record': str(claim_record), 'record_sha256': digest(claim_record),
                   'log': str(claim_log), 'log_sha256': digest(claim_log)},
               'reused_cpp_check': {'log': '/tmp/c71-s1-query-final-c-20261009.log',
                   'report': '/tmp/c71-s1-query-final-c-20261009.json', 'parent_reported_pass': True},
               'preserved_build_attempt_reports': ['/tmp/c71-s1-query-build-pre03-20261009.json',
                   '/tmp/c71-s1-query-build-pre04-20261009.json'],
               'build_note': 'pre03 deadline exit124 at60.050837864s, aggregate RSS2498871296B; same-source one retry pre04 PASS56.185896800s, aggregate RSS2504699904B; limits unchanged',
               'ledger_log_directory': str(ledger_logs), 'ledger_final_links_published': success,
               'credit': False, 'gpu_execution': False}, output, indent=2)
    output.write('\n')
if not success:
    sys.exit(1)
