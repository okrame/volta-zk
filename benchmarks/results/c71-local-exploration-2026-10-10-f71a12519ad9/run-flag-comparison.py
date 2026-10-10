import pathlib,subprocess,sys,json
root=pathlib.Path('/home/okrame/projects/volta-zk');run=pathlib.Path(__file__).parent
for label,source in [('baseline',run/'range-runtime-072de372.cpp'),('pooled',root/'cuda/c71_range_runtime.cpp')]:
 binary=run/f'flag-comparison-{label}'
 command=['g++','-std=c++17','-O2','-Wall','-Wextra','-Werror','-fsanitize=undefined','-fno-sanitize-recover=all','-DC71_RANGE_FFI_TEST','-I',str(root/'tests/cuda_stub'),'-I',str(root/'cuda'),str(source),str(root/'tests/c71_range_runtime_host.cpp'),'/tmp/c71-executor-flag-census.cpp','-o',str(binary)]
 subprocess.run([sys.executable,str(run/'run-check.py'),f'flag-build-{label}',*command],check=True)
 subprocess.run([sys.executable,str(run/'run-check.py'),f'flag-run-{label}',str(binary)],check=True)
records=[]
for label in ('baseline','pooled'):
 text=(run/f'flag-run-{label}.log').read_text()
 records.append(json.loads(text.split('C71_FLAG_COUNTER_COMPARISON ',1)[1]))
a,b=records
assert (a['flag_allocations'],b['flag_allocations'])==(32,1)
assert (a['flag_releases_before_close'],b['flag_releases_before_close'])==(32,0)
assert (a['retained_device_bytes_before_close'],b['retained_device_bytes_before_close'])==(0,256)
assert b['host_owner_bytes']-a['host_owner_bytes']==8
for key in ('launches','fences_including_observation_and_output_release','d2h_bytes_including_observation','flag_zeroed_bytes'):
 assert a[key]==b[key],key
with (run/'flag-counter-comparison.json').open('x') as f:
 json.dump(dict(baseline=a,pooled=b,driver='deferred fake driver',exact_numerical_parity=True,performance_measured=False,gpu_execution=False,credit=False),f,indent=2)
