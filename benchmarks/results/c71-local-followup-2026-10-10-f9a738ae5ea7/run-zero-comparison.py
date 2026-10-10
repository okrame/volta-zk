import hashlib, json, pathlib, subprocess, sys
root=pathlib.Path('/home/okrame/projects/volta-zk'); run=pathlib.Path(__file__).parent
baseline_sha='8421fada206669641b2800aae94b4016004c9ccc'
baseline=run/'range-runtime-8421fada.cpp'
with baseline.open('xb') as output:
    subprocess.run(['git','show',baseline_sha+':cuda/c71_range_runtime.cpp'],cwd=root,stdout=output,check=True)
reports=[]
for label,source in [('baseline',baseline),('zero',root/'cuda/c71_range_runtime.cpp')]:
    binary=run/('public-zero-'+label)
    command=['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all','-DC71_RANGE_FFI_TEST','-I',str(root/'tests/cuda_stub'),'-I',str(root/'cuda'),str(source),str(root/'tests/c71_range_runtime_host.cpp'),str(run/'public-zero-census.cpp'),'-o',str(binary)]
    subprocess.run([sys.executable,str(run/'run-check.py'),'zero-build-'+label,*command],cwd=root,check=True)
    subprocess.run([sys.executable,str(run/'run-check.py'),'zero-run-'+label,str(binary)],cwd=root,check=True)
    reports.append(json.loads((run/('zero-run-'+label+'.log')).read_text().split('C71_PUBLIC_ZERO_COMPARISON ',1)[1]))
a,b=reports
assert (a['application_kernel_launches'],b['application_kernel_launches'])==(7,0)
assert (a['memset_api_bytes'],b['memset_api_bytes'])==(28,134316)
for key in a.keys()-{'application_kernel_launches','memset_api_bytes'}:
    assert a[key]==b[key],key
with (run/'zero-counter-comparison.json').open('x') as output:
    json.dump(dict(baseline=a,zero=b,baseline_runtime_git_sha=baseline_sha,baseline_runtime_sha256=hashlib.sha256(baseline.read_bytes()).hexdigest(),shared_headers_and_deferred_driver='current source; launcher validation extracted without changing conditions',exact_raw_parity=True,performance_measured=False,gpu_execution=False,credit=False),output,indent=2)
