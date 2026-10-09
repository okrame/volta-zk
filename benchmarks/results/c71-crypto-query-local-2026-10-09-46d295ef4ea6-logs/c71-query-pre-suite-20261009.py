import json
import pathlib
import re
import subprocess
import sys

root=pathlib.Path('/home/okrame/projects/volta-zk')
binary=root/'rust/target/debug/deps/volta_pcs-efe6791186972026'
checks=[
 ('reader', ['c71_b12_native_query_reader_failure_without_host_fallback']),
 ('guards', ['c71_b12_native_query_rejections_and_fail_closed']),
 ('symbols', ['c71_b12_native_query_private_phase_read_and_mandatory_symbols']),
 ('chain', ['c71_b12_native_query_composed_uncached_chain_original_mac_and_transcript']),
 ('a-tree', ['c71_b12_native_source_tree_']),
 ('w-tree', ['c71_b12_native_weight_tree_']),
 ('cpp', None),
]
reports=[]
for name, filters in checks:
    command=([str(binary), *filters, '--test-threads=1','--nocapture'] if filters else
        [str(root/'.venv/bin/python'),'-m','pytest','-q','-p','no:cacheprovider',
         'tests/test_c71_range_native.py','tests/test_c71_fft_microbench.py'])
    prefix='/tmp/c71-query-native-'+name+'-pre01-20261009'
    result=subprocess.run([sys.executable,'/tmp/c71-local-check-20261008.py',prefix+'.log',
        prefix+'.json','2048',*command],cwd=root)
    report=json.loads(pathlib.Path(prefix+'.json').read_text())
    report.update(name=name,git_dirty=True,record_run=False)
    contents=pathlib.Path(prefix+'.log').read_text()
    pattern=r'test result: ok\. (\d+) passed;' if filters else r'(\d+) passed'
    matched=re.search(pattern,contents)
    if result.returncode==0:
        assert matched and int(matched.group(1))>0, contents[-2000:]
        report['passed']=int(matched.group(1))
    reports.append(report)
    if result.returncode:
        break
with open('/tmp/c71-query-native-pre-suite-20261009.json','x') as output:
    json.dump(reports,output,indent=2); output.write('\n')
sys.exit(result.returncode)
