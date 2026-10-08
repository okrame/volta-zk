import json, os, resource, subprocess, sys, time
from pathlib import Path
root = Path('/home/okrame/projects/volta-zk')
destination = Path(sys.argv[1])
destination.mkdir()
environment = dict(os.environ, RAYON_NUM_THREADS='1', OMP_NUM_THREADS='1', OPENBLAS_NUM_THREADS='1', PYTHONDONTWRITEBYTECODE='1')
binary = root / 'rust/target/debug/deps/volta_pcs-1b032d88c9000486'
selectors = [
 'c71_b12_native_incremental_hash_exact_roots_and_salt_bands',
 'c71_b12_native_incremental_hash_coset_frontier_and_natural_root',
 'c71_b12_native_incremental_hash_rejections_and_fail_closed',
 'c71_b12_windowed_native_abi4_rejects_legacy_stats',
 'c71_canonical_device_replay_original_rows_windows_and_failure',
]
commands = [(name, [str(binary), name, '--nocapture', '--test-threads=1']) for name in selectors]
commands.append(('docs-and-owner', [str(root / '.venv/bin/python'), '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests/test_c71_docs.py', 'tests/test_c71_range_native.py']))
def limits():
 resource.setrlimit(resource.RLIMIT_AS, (2 << 30, 2 << 30))
records = []
for name, command in commands:
 log = destination / (name + '.log')
 start = time.monotonic()
 with log.open('xb') as output:
  process = subprocess.Popen(['timeout', '-k', '5s', '60s', *command], cwd=root, stdout=output, stderr=subprocess.STDOUT, env=environment, preexec_fn=limits)
  _, status, usage = os.wait4(process.pid, 0)
  process.returncode = os.waitstatus_to_exitcode(status)
 record = dict(name=name, exit_code=process.returncode, elapsed_seconds=time.monotonic()-start,
               user_seconds=usage.ru_utime, system_seconds=usage.ru_stime,
               max_rss_bytes=usage.ru_maxrss*1024, log=log.name,
               address_space_limit_bytes=2 << 30, deadline_seconds=60, workers=1)
 records.append(record)
 print(json.dumps(record), flush=True)
 if process.returncode:
  break
(destination / 'tests.json').write_text(json.dumps(records, indent=2)+'\n')
if any(record['exit_code'] for record in records):
 sys.exit(1)
