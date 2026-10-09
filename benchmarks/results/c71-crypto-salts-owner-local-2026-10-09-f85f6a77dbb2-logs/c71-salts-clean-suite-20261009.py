import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path('/home/okrame/projects/volta-zk')
binary = root / 'rust/target/debug/deps/volta_pcs-4cb98f0e88b6e8d1'
sha = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
digest = hashlib.sha256(binary.read_bytes()).hexdigest()

def clean():
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip() == sha
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == digest

checks = [('build', root / 'rust', 0, ['cargo', 'test', '--offline', '--locked', '-j', '1',
    '-p', 'volta-pcs', '--features', 'c71-seed6-reference', '--lib', '--no-run',
    '--config', 'profile.dev.package.volta-pcs.opt-level=0'])]
for name, selection in [
    ('private-coins', 'c71_b12_private_coins_'),
    ('owner-exact', 'c71_b12_native_private_salts_owner_exact_stream_hash_and_work'),
    ('owner-metadata', 'c71_b12_native_private_salts_owner_metadata_alias_and_stale_capability'),
    ('owner-rejections', 'c71_b12_native_private_salts_owner_rejections_and_fail_closed'),
    ('owner-symbols', 'c71_b12_native_private_salts_owner_symbols_are_mandatory'),
    ('w-tree', 'c71_b12_native_weight_tree'),
    ('a-tree', 'c71_b12_native_source_tree'),
    ('w-chain', 'c71_b12_native_weight_composed_full_chain_original_mac_and_transcript'),
    ('a-chain', 'c71_b12_native_source_composed_full_chain_original_mac_and_transcript'),
    ('resources', 'geometry_and_resource_envelope'),
    ('range-macs', 'c71_b12_native_streaming_lookup_gkr_whir_positive_original_macs'),
    ('source-coverage', 'c71_canonical_device_original_scan_coverage_rejects_duplicate_and_omitted_rows'),
]:
    checks.append((name, root, 2048, [str(binary), selection, '--test-threads=1', '--nocapture']))
for name, file in [('cpp', 'tests/test_c71_range_native.py'), ('docs', 'tests/test_c71_docs.py')]:
    checks.append((name, root, 2048, [str(root / '.venv/bin/python'), '-m', 'pytest',
        '-q', '-p', 'no:cacheprovider', file]))
results = []
for name, cwd, limit, command in checks:
    clean()
    prefix = '/tmp/c71-salts-clean-' + name + '-20261009-01'
    result = subprocess.run([sys.executable, '/tmp/c71-local-check-20261008.py',
        prefix + '.log', prefix + '.json', str(limit), *command], cwd=cwd)
    clean()
    report = json.loads(pathlib.Path(prefix + '.json').read_text())
    report.update(name=name, source_git_sha=sha, git_dirty=False, record_run=True)
    results.append(report)
    if result.returncode:
        break
with open('/tmp/c71-salts-clean-suite-20261009-01.json', 'x') as output:
    json.dump(dict(source_git_sha=sha, binary_sha256=digest, checks=results), output, indent=2)
    output.write('\n')
sys.exit(results[-1]['exit_code'])
