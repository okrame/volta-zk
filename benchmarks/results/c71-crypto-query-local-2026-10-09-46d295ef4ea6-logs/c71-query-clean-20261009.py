import hashlib
import json
import pathlib
import re
import subprocess
import sys

root=pathlib.Path('/home/okrame/projects/volta-zk')
binary=root/'rust/target/debug/deps/volta_pcs-efe6791186972026'
sha=subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()
digest=hashlib.sha256(binary.read_bytes()).hexdigest()
build=['cargo','rustc','--offline','--locked','-j','1','-p','volta-pcs',
    '--features','c71-seed6-reference','--lib','--profile','test',
    '--config','profile.dev.package.volta-pcs.opt-level=0',
    '--config','profile.dev.package.volta-pcs.codegen-units=256','--',
    '-Clink-arg=-fuse-ld=lld',
    '-Clink-arg=-B/home/okrame/.rustup/toolchains/stable-aarch64-unknown-linux-gnu/lib/rustlib/aarch64-unknown-linux-gnu/bin/gcc-ld',
    '-Clink-arg=-Wl,--threads=1']
checks=[('build',root/'rust',0,build)]
for name,filter in [
    ('parity','c71_b12_native_query_exact_horner_windows_pads_and_resources'),
    ('reader','c71_b12_native_query_reader_failure_without_host_fallback'),
    ('guards','c71_b12_native_query_rejections_and_fail_closed'),
    ('symbols','c71_b12_native_query_private_phase_read_and_mandatory_symbols'),
    ('chain','c71_b12_native_query_composed_uncached_chain_original_mac_and_transcript'),
    ('a-tree','c71_b12_native_source_tree_'),
    ('w-tree','c71_b12_native_weight_tree_')]:
    checks.append((name,root,2048,[str(binary),filter,'--test-threads=1','--nocapture']))
for name,files in [('cpp',['tests/test_c71_range_native.py','tests/test_c71_fft_microbench.py']),
                   ('docs',['tests/test_c71_docs.py'])]:
    checks.append((name,root,2048,[str(root/'.venv/bin/python'),'-m','pytest','-q',
        '-p','no:cacheprovider',*files]))
reports=[]
for name,cwd,limit,command in checks:
    for after in [False,True]:
        assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==sha
        assert not subprocess.check_output(['git','status','--porcelain'],cwd=root)
        assert hashlib.sha256(binary.read_bytes()).hexdigest()==digest
        if not after:
            prefix='/tmp/c71-query-clean-'+name+'-20261009-01'
            result=subprocess.run([sys.executable,'/tmp/c71-local-check-20261008.py',prefix+'.log',
                prefix+'.json',str(limit),*command],cwd=cwd)
    report=json.loads(pathlib.Path(prefix+'.json').read_text())
    report.update(name=name,source_git_sha=sha,git_dirty=False,record_run=True)
    if name!='build' and result.returncode==0:
        contents=pathlib.Path(prefix+'.log').read_text()
        pattern=(r'(\d+) passed' if name in ['cpp','docs'] else r'test result: ok\. (\d+) passed;')
        matched=re.search(pattern,contents)
        assert matched and int(matched.group(1))>0
        report['passed']=int(matched.group(1))
    reports.append(report)
    if result.returncode:
        break
with open('/tmp/c71-query-clean-suite-20261009-01.json','x') as output:
    json.dump(dict(source_git_sha=sha,binary_sha256=digest,checks=reports),output,indent=2); output.write('\n')
sys.exit(result.returncode)
