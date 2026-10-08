import json
import os
import resource
import subprocess
import sys
import time

log, report, as_mib, *command = sys.argv[1:]
environment = dict(os.environ, RAYON_NUM_THREADS="1", OMP_NUM_THREADS="1",
    OPENBLAS_NUM_THREADS="1", PYTHONDONTWRITEBYTECODE="1",
    CARGO_TARGET_DIR="/home/okrame/projects/volta-zk/rust/target",
    CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_DEV_OPT_LEVEL="2")
def limit():
    if int(as_mib):
        size = int(as_mib) * 1048576
        resource.setrlimit(resource.RLIMIT_AS, (size, size))
started = time.monotonic()
with os.fdopen(os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
    process = subprocess.Popen(["timeout", "-k", "5s", "60s", *command],
        stdout=output, stderr=subprocess.STDOUT, env=environment, preexec_fn=limit)
    _, status, usage = os.wait4(process.pid, 0)
    process.returncode = os.waitstatus_to_exitcode(status)
result = {"command": command, "cwd": os.getcwd(), "exit_code": process.returncode,
    "wall_s": time.monotonic() - started, "max_rss_bytes": usage.ru_maxrss * 1024,
    "as_limit_mib": int(as_mib) or None, "deadline_s": 60, "workers": 1,
    "user_s": usage.ru_utime, "system_s": usage.ru_stime, "log": log}
with os.fdopen(os.open(report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as output:
    json.dump(result, output, indent=2)
    output.write("\n")
print(json.dumps(result))
sys.exit(process.returncode)
