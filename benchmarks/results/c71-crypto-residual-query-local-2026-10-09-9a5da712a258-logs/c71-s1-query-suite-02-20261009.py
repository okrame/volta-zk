import hashlib
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path('/home/okrame/projects/volta-zk')
manifest = json.loads(pathlib.Path('/tmp/c71-query-e-rust-20261009/manifest.json').read_text())
binary = root/'rust/target/debug/deps/volta_pcs-efe6791186972026'
revision = subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
results=[]
filters=sorted(manifest['serial_filters'],key=lambda name: 0 if '_full_whir_w_' in name else (1 if '_full_whir_a_' in name else 2))
for number, name in enumerate(filters,1):
    assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==revision
    assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
    assert hashlib.sha256(binary.read_bytes()).hexdigest()==binary_digest
    prefix = pathlib.Path(f'/tmp/c71-s1-query-clean-02-{number:02d}-20261009')
    log, report = str(prefix)+'.log',str(prefix)+'.json'
    command=['python3','/tmp/c71-local-check-20261008.py',log,report,'2048',str(binary),name,'--test-threads=1','--nocapture']
    execution=subprocess.run(command,cwd=root,capture_output=True,text=True)
    result=json.loads(pathlib.Path(report).read_text())
    matched=re.search(r'test result: ok\. (\d+) passed;',pathlib.Path(log).read_text())
    passed=int(matched.group(1)) if matched else 0
    result.update(name=name,source_git_sha=revision,git_dirty=False,binary_sha256=binary_digest,passed=passed)
    results.append(result)
    print(json.dumps({'case':number,'filter':name,'exit':result['exit_code'],'passed':passed,
        'wall_s':result['wall_s'],'max_rss_bytes':result['max_rss_bytes'],'log':log}),flush=True)
    if execution.returncode or not passed:
        break
with pathlib.Path('/tmp/c71-s1-query-clean-suite-02-20261009.json').open('x') as output:
    json.dump({'source_git_sha':revision,'git_dirty':False,'binary_sha256':binary_digest,'checks':results},output,indent=2)
    output.write('\n')
if len(results)!=len(manifest['serial_filters']) or any(r['exit_code'] or not r['passed'] for r in results):
    sys.exit(1)
