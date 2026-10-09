import hashlib
import json
import pathlib
import subprocess
import sys

root=pathlib.Path('/home/okrame/projects/volta-zk')
binary=root/'rust/target/debug/deps/volta_pcs-4cb98f0e88b6e8d1'
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
digest=hashlib.sha256(binary.read_bytes()).hexdigest()
checks=[('build',root/'rust',0,['cargo','test','--offline','--locked','-j','1','-p','volta-pcs',
    '--features','c71-seed6-reference','--lib','--no-run','--config','profile.dev.package.volta-pcs.opt-level=0']),
    ('parity',root,2048,[str(binary),'c71_b12_native_transform_','--test-threads=1','--nocapture']),
    ('w-tree',root,2048,[str(binary),'c71_b12_native_weight_tree','--test-threads=1','--nocapture']),
    ('cpp',root,2048,[str(root/'.venv/bin/python'),'-m','pytest','-q','-p','no:cacheprovider',
        'tests/test_c71_fft_microbench.py','tests/test_c71_range_native.py']),
    ('docs',root,2048,[str(root/'.venv/bin/python'),'-m','pytest','-q','-p','no:cacheprovider','tests/test_c71_docs.py'])]
reports=[]
for name,cwd,limit,command in checks:
    for after in [False,True]:
        assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==sha
        assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
        assert hashlib.sha256(binary.read_bytes()).hexdigest()==digest
        if not after:
            prefix='/tmp/c71-transform-clean-'+name+'-20261009-01'
            result=subprocess.run([sys.executable,'/tmp/c71-local-check-20261008.py',prefix+'.log',prefix+'.json',str(limit),*command],cwd=cwd)
    report=json.loads(pathlib.Path(prefix+'.json').read_text())
    report.update(name=name,source_git_sha=sha,git_dirty=False,record_run=True)
    reports.append(report)
    if result.returncode: break
with open('/tmp/c71-transform-clean-suite-20261009-01.json','x') as output:
    json.dump(dict(source_git_sha=sha,binary_sha256=digest,checks=reports),output,indent=2); output.write('\n')
sys.exit(result.returncode)
