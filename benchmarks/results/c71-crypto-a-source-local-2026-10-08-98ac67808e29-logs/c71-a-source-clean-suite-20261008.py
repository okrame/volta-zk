import subprocess
from pathlib import Path
root = Path('/home/okrame/projects/volta-zk')
binary = root / 'rust/target/debug/deps/volta_pcs-4cb98f0e88b6e8d1'
cases = [
    ('source', [str(binary), 'c71_b12_native_source_', '--test-threads=1', '--nocapture']),
    ('metadata', [str(binary), 'c71_b12_pcs_resident_source_tiles_original_biased_bytes', '--test-threads=1', '--nocapture']),
    ('permutation', [str(binary), 'c71_b12_range_window_permutation_and_intersections', '--test-threads=1', '--nocapture']),
    ('producer', [str(binary), 'c71_canonical_device_replay_original_rows_windows_and_failure', '--test-threads=1', '--nocapture']),
    ('byte-gather', [str(binary), 'c71_canonical_resident_byte', '--test-threads=1', '--nocapture']),
    ('w-tree', [str(binary), 'c71_b12_native_weight_tree', '--test-threads=1', '--nocapture']),
    ('w-resource', [str(binary), 'c71_b12_native_weight_geometry_and_resource_envelope', '--test-threads=1', '--nocapture']),
    ('w-math', [str(binary), 'c71_b12_native_weight_columns_exact_signed_pads_fft_hash', '--test-threads=1', '--nocapture']),
    ('python-owner', [str(root / '.venv/bin/python'), '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/test_c71_range_native.py']),
    ('docs', [str(root / '.venv/bin/python'), '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/test_c71_docs.py']),
]
for name, command in cases:
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)
    subprocess.run(['python3', '/tmp/c71-local-check-20261008.py',
        f'/tmp/c71-a-source-clean-{name}-20261008-01.log',
        f'/tmp/c71-a-source-clean-{name}-20261008-01.json', '2048', *command], cwd=root, check=True)
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root)
