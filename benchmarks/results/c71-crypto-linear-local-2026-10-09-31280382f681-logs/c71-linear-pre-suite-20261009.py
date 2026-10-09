import json
import pathlib
import re
import subprocess
import sys

root=pathlib.Path('/home/okrame/projects/volta-zk')
binary=root/'rust/target/debug/deps/volta_pcs-efe6791186972026'
checks=[]
for name,filter in [
    ('owner','c71_b12_native_linear_owner_token_coverage_and_fail_closed'),
    ('symbols','c71_b12_native_linear_symbols_are_required'),
    ('faults','c71_b12_native_linear_producer_errors_burn_only_completed_rounds'),
    ('wire','c71_b12_native_linear_full_wire_fs_point_and_original_mac'),
    ('query','c71_b12_native_query_exact_horner_windows_pads_and_resources'),
    ('a-tree','c71_b12_native_source_tree_'),
    ('w-tree','c71_b12_native_weight_tree_')]:
    checks.append((name,[str(binary),filter,'--test-threads=1','--nocapture']))
checks.append(('components',[str(root/'.venv/bin/python'),'-m','pytest','-q','-s',
    '-p','no:cacheprovider','tests/test_c71_range_native.py','tests/test_c71_fft_microbench.py',
    'tests/test_c71_linear_native.py','tests/test_c71_pcs_residual.py']))
checks.append(('docs',[str(root/'.venv/bin/python'),'-m','pytest','-q',
    '-p','no:cacheprovider','tests/test_c71_docs.py']))
reports=[]
for name,command in checks:
    prefix='/tmp/c71-linear-'+name+'-pre01-20261009'
    print('C71_LOCAL_CHECK '+name,flush=True)
    result=subprocess.run([sys.executable,'/tmp/c71-local-check-20261008.py',
        prefix+'.log',prefix+'.json','2048',*command],cwd=root)
    report=json.loads(pathlib.Path(prefix+'.json').read_text())
    report.update(name=name,record_run=False,git_dirty=True)
    if result.returncode==0:
        contents=pathlib.Path(prefix+'.log').read_text()
        pattern=r'(\d+) passed' if name in ['components','docs'] else r'test result: ok\. (\d+) passed;'
        matched=re.search(pattern,contents)
        assert matched and int(matched.group(1))>0
        report['passed']=int(matched.group(1))
    reports.append(report)
    if result.returncode: break
with open('/tmp/c71-linear-pre-suite-20261009-01.json','x') as output:
    json.dump(dict(checks=reports),output,indent=2); output.write('\n')
sys.exit(result.returncode)
