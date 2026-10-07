"""Bounded phase runner with simultaneous sampled process-tree RSS and whole-GPU HBM."""
import csv,json,os,signal,subprocess,sys,time
from pathlib import Path


def host_tree(root_pid):
    rows={}
    for path in Path('/proc').iterdir():
        if not path.name.isdigit(): continue
        try:
            fields={k:v.strip() for k,v in (line.split(':',1) for line in (path/'status').read_text().splitlines() if ':' in line)}
            rows[int(path.name)]=(int(fields.get('PPid','0')),int(fields.get('VmRSS','0 kB').split()[0])*1024,int(fields.get('VmSwap','0 kB').split()[0])*1024)
        except (OSError,ValueError): continue
    selected={root_pid}
    while True:
        extra={pid for pid,row in rows.items() if row[0] in selected}-selected
        if not extra: break
        selected.update(extra)
    return sum(rows[p][1] for p in selected if p in rows),sum(rows[p][2] for p in selected if p in rows)


def stop_session(session_id):
    groups = set()
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit(): continue
        try:
            pid = int(proc.name)
            if os.getsid(pid) == session_id: groups.add(os.getpgid(pid))
        except ProcessLookupError: continue
    for group in groups:
        try: os.killpg(group, signal.SIGKILL)
        except ProcessLookupError: pass


if '--self-check' in sys.argv:
    rss,swap=host_tree(os.getpid())
    assert rss>0 and swap>=0
    child=subprocess.Popen([sys.executable,'-c',
        'import subprocess,time; subprocess.Popen(["sleep","60"],process_group=0); time.sleep(60)'],
        start_new_session=True)
    try:
        time.sleep(0.2)
        stop_session(child.pid)
        assert child.wait(timeout=5) != 0
    finally:
        stop_session(child.pid)
    print('process-tree RSS and multi-group session shutdown self-check passed'); sys.exit(0)

def interrupted(_signum, _frame):
    raise KeyboardInterrupt('monitor interrupted')

signal.signal(signal.SIGTERM, interrupted)

root=Path(sys.argv[1]); label=sys.argv[2]; seconds=int(sys.argv[3]); command=sys.argv[4:]
assert command and seconds>0 and label.replace('-','').isalnum()
deadline=float(os.environ['AUTHORIZED_END_EPOCH'])
assert time.time()+seconds<=deadline-1800, 'must preserve the closeout reserve'
gpu_uuid=os.environ['CUDA_VISIBLE_DEVICES']
assert gpu_uuid.startswith('GPU-') and ',' not in gpu_uuid
logs=root/'logs'; logs.mkdir(exist_ok=True)
assert not list(logs.glob(label+'.*')), 'new label required; no overwrite/retry'
start=time.time(); started=time.monotonic(); rows=0; joint_peak=0; host_peak=0; gpu_peak=0; failure=None
(logs/(label+'.start')).write_text(str(start)+'\n')
with (logs/(label+'.stdout')).open('x') as out,(logs/(label+'.stderr')).open('x') as err,(logs/(label+'.memory.csv')).open('x') as memory:
    writer=csv.writer(memory); writer.writerow(['unix_seconds','sample_duration_seconds','host_tree_rss_bytes','host_tree_swap_bytes','whole_gpu_used_bytes','sampled_joint_bytes','cgroup_memory_current_bytes','disk_available_bytes'])
    process=subprocess.Popen(['/usr/bin/time','-v','-o',str(logs/(label+'.time.txt')),'timeout','-k','5s',str(seconds)+'s',*command],stdout=out,stderr=err,start_new_session=True)
    try:
        while process.poll() is None:
            before=time.monotonic(); rss,swap=host_tree(process.pid)
            gpu=subprocess.run(['nvidia-smi','--id='+gpu_uuid,'--query-gpu=memory.used','--format=csv,noheader,nounits'],capture_output=True,text=True,timeout=10,check=True)
            used=int(gpu.stdout.strip())*1024**2
            rss2,swap2=host_tree(process.pid); rss=max(rss,rss2); swap=max(swap,swap2)
            cgroup=int(Path('/sys/fs/cgroup/memory.current').read_text()); stat=os.statvfs(root); disk=stat.f_bavail*stat.f_frsize
            joint=rss+used; writer.writerow([time.time(),time.monotonic()-before,rss,swap,used,joint,cgroup,disk]); memory.flush()
            rows+=1; joint_peak=max(joint_peak,joint); host_peak=max(host_peak,rss); gpu_peak=max(gpu_peak,used)
            if rss>96*1024**3 or used>=80000000000 or swap or disk<20000000000:
                raise RuntimeError('resource stop: RSS/HBM/swap/free disk limit')
            time.sleep(max(0,0.2-(time.monotonic()-before)))
    except BaseException as error:
        failure=type(error).__name__+": "+str(error); stop_session(process.pid)
    finally:
        stop_session(process.pid)
    code=process.wait()
if failure: code=code or 1
summary={'label':label,'gpu_uuid':gpu_uuid,'authorized_end_epoch':deadline,'command':command,'exit_code':code,'start_unix_seconds':start,'wall_seconds':time.monotonic()-started,'samples':rows,'sampling_target_seconds':0.2,'sampled_joint_peak_bytes':joint_peak,'sampled_host_rss_peak_bytes':host_peak,'sampled_whole_gpu_peak_bytes':gpu_peak,'physical_complete_peak':False,'sampling_limit':'Sampled lower bound; RSS may double count shared pages; includes whole GPU runtime/context. Does not by itself prove every transient peak or retained-capacity coverage.','resource_failure':failure}
(logs/(label+'.exit')).write_text(str(code)+'\n'); (logs/(label+'.end')).write_text(str(time.time())+'\n')
with (logs/(label+'.summary.json')).open('x') as sink: json.dump(summary,sink,indent=2,sort_keys=True); sink.write('\n')
print(json.dumps(summary),flush=True); sys.exit(code)
