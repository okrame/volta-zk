import subprocess
import sys

binary = 'rust/target/debug/deps/volta_pcs-4cb98f0e88b6e8d1'
checks = [
    ('private-coins', [binary, 'c71_b12_private_coins_', '--test-threads=1', '--nocapture']),
    ('owner', [binary, 'c71_b12_native_private_salts_owner_', '--test-threads=1', '--nocapture']),
    ('w-chain', [binary, 'c71_b12_native_weight_composed_full_chain_original_mac_and_transcript', '--test-threads=1', '--nocapture']),
    ('a-chain', [binary, 'c71_b12_native_source_composed_full_chain_original_mac_and_transcript', '--test-threads=1', '--nocapture']),
    ('resources', [binary, 'geometry_and_resource_envelope', '--test-threads=1', '--nocapture']),
    ('cpp', ['.venv/bin/python', '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/test_c71_range_native.py']),
]
for name, command in checks:
    prefix = '/tmp/c71-salts-' + name + '-pre02-20261009'
    result = subprocess.run([sys.executable, '/tmp/c71-local-check-20261008.py',
        prefix + '.log', prefix + '.json', '2048', *command])
    if result.returncode:
        sys.exit(result.returncode)
