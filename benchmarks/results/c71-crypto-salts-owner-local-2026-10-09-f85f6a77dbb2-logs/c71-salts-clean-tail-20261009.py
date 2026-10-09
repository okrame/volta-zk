import hashlib
import json
import pathlib
import subprocess
import sys

root = pathlib.Path('/home/okrame/projects/volta-zk')
suite = json.loads(pathlib.Path('/tmp/c71-salts-clean-suite-20261009-01.json').read_text())
sha = suite['source_git_sha']
binary = root / 'rust/target/debug/deps/volta_pcs-4cb98f0e88b6e8d1'
checks = [('source-coverage', [str(binary),
    'c71_canonical_device_original_scan_coverage_rejects_duplicate_and_omitted_rows',
    '--test-threads=1','--nocapture'])]
for name,file in [('cpp','tests/test_c71_range_native.py'),('docs','tests/test_c71_docs.py')]:
    checks.append((name,[str(root / '.venv/bin/python'),'-m','pytest','-q','-p','no:cacheprovider',file]))
for name,command in checks:
    for after in [False,True]:
        assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==sha
        assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
        assert hashlib.sha256(binary.read_bytes()).hexdigest()==suite['binary_sha256']
        if not after:
            prefix='/tmp/c71-salts-clean-'+name+'-20261009-02'
            result=subprocess.run([sys.executable,'/tmp/c71-local-check-20261008.py',
                prefix+'.log',prefix+'.json','2048',*command],cwd=root)
    report=json.loads(pathlib.Path(prefix+'.json').read_text())
    report.update(name=name,source_git_sha=sha,git_dirty=False,record_run=True)
    suite['checks'].append(report)
    if result.returncode: break
with open('/tmp/c71-salts-clean-complete-checks-20261009-02.json','x') as output:
    json.dump(suite,output,indent=2); output.write('\n')
sys.exit(result.returncode)
