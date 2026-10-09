import json
import os
import pathlib
import resource
import subprocess
import sys
import time

log, report, *command = sys.argv[1:]
environment = dict(os.environ, RAYON_NUM_THREADS="1", OMP_NUM_THREADS="1",
    OPENBLAS_NUM_THREADS="1", PYTHONDONTWRITEBYTECODE="1",
    CARGO_TARGET_DIR="/home/okrame/projects/volta-zk/rust/target",
    CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_DEV_OPT_LEVEL="2")
started = time.monotonic()
samples = {}
peak = 0
with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
    process = subprocess.Popen(["timeout", "-k", "5s", "60s", *command],
        stdout=output, stderr=subprocess.STDOUT, env=environment)
    while True:
        live = 0
        for path in pathlib.Path('/proc').iterdir():
            if not path.name.isdigit():
                continue
            try:
                stat = (path / 'stat').read_text().rsplit(')', 1)[1].split()
                if int(stat[1]) == 0 or int(path.name) == os.getpid():
                    continue
                name = (path / 'comm').read_text().strip()
                rss = int(stat[21]) * os.sysconf('SC_PAGE_SIZE')
                ticks = int(stat[11]) + int(stat[12])
            except (OSError, ValueError, IndexError):
                continue
            live += rss
            item = samples.setdefault(path.name, dict(name=name, max_rss_bytes=0, cpu_ticks=0,
                first_seen_s=time.monotonic()-started))
            item['max_rss_bytes'] = max(item['max_rss_bytes'], rss)
            item['cpu_ticks'] = max(item['cpu_ticks'], ticks)
            item['last_seen_s'] = time.monotonic()-started
        peak = max(peak, live)
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            break
        time.sleep(0.1)
result = dict(command=command, cwd=os.getcwd(), exit_code=process.returncode,
    wall_s=time.monotonic()-started, max_rss_bytes=usage.ru_maxrss*1024,
    sampled_aggregate_live_rss_peak_bytes=peak, sampled_processes=samples,
    sample_interval_s=0.1, clock_ticks_per_s=os.sysconf('SC_CLK_TCK'),
    deadline_s=60, workers=1, as_limit_mib=None,
    user_s=usage.ru_utime, system_s=usage.ru_stime, log=log)
with os.fdopen(os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
    json.dump(result, output, indent=2); output.write('\n')
print(json.dumps(result))
sys.exit(process.returncode)
