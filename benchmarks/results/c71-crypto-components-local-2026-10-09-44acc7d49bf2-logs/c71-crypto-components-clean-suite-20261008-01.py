import json
import subprocess
import sys
from pathlib import Path

ROOT = Path('/home/okrame/projects/volta-zk')
SHA = '44acc7d49bf2b917bc8b9806e805a8774f255d70'
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip() == SHA
def clean():
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT, text=True)
runner = '/tmp/c71-local-check-20261008.py'
binary = str(ROOT / 'rust/target/debug/deps/volta_pcs-4cb98f0e88b6e8d1')
checks = [('build', 0, ['cargo', 'test', '--offline', '--locked', '-j', '1', '-p', 'volta-pcs', '--features', 'c71-seed6-reference', '--lib', '--no-run', '--config', 'profile.dev.package.volta-pcs.opt-level=0'], ROOT / 'rust')]
for label, selection in [
    ('linear', 'c71_b12_sourcewise_linear'),
    ('original_scan', 'c71_b12_original_scan_live_prefix_order_and_errors'),
    ('salts', 'c71_b12_private_coins_'),
    ('tensor_owner', 'c71_b12_native_weight_tensor'),
    ('word_compare', 'c71_b12_native_pcs_compare_words'),
    ('w_tree', 'c71_b12_native_weight_tree'),
    ('w_chain', 'c71_b12_native_weight_composed_full_chain_original_mac_and_transcript'),
    ('a_tree', 'c71_b12_native_source_tree'),
    ('a_chain', 'c71_b12_native_source_composed_full_chain_original_mac_and_transcript'),
    ('a_coverage', 'c71_canonical_device_original_scan_coverage_rejects_duplicate_and_omitted_rows'),
    ('linear_bench_1', 'c71_b12_sourcewise_linear_scan_coefficients_and_component_benchmark'),
    ('linear_bench_2', 'c71_b12_sourcewise_linear_scan_coefficients_and_component_benchmark'),
    ('linear_bench_3', 'c71_b12_sourcewise_linear_scan_coefficients_and_component_benchmark'),
]:
    checks.append((label, 2048, [binary, selection, '--test-threads=1', '--nocapture'], ROOT))
for label, path in [('owner', 'tests/test_c71_range_native.py'), ('tensor_host', 'tests/test_c71_pcs_tensor.py'), ('attention', 'tests/test_c71_attention_mma.py'), ('docs', 'tests/test_c71_docs.py')]:
    checks.append((label, 2048, [str(ROOT / '.venv/bin/python'), '-m', 'pytest', '-q', '-s', '-p', 'no:cacheprovider', path], ROOT))
checks.append(('w_diagnostic_compile', 2048, ['g++', '-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-I', 'cuda', '-c', 'cuda/c71_pcs_weight_compare.cpp', '-o', '/tmp/c71-weight-compare-clean-20261008-01.o'], ROOT))
for label, limit, command, cwd in checks:
    clean()
    base = f'/tmp/c71-components-clean-{label}-20261008-01'
    result = subprocess.run([sys.executable, runner, base + '.log', base + '.json', str(limit), *command], cwd=cwd)
    clean()
    if result.returncode:
        raise SystemExit(result.returncode)
    print('PASS ' + label, flush=True)
