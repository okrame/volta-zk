#!/usr/bin/env python3
"""Bounded C7.1 CPU diagnostic. Defaults to preflight; --run executes one case."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 2 << 30


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def child_limits():
    resource.setrlimit(resource.RLIMIT_AS, (LIMIT, LIMIT))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.sched_setaffinity(0, sorted(os.sched_getaffinity(0))[:2])


def bounded(command, env):
    """Drain into files, monitor the child, preserve rejection output."""
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        start = time.monotonic()
        child = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr,
                                 preexec_fn=child_limits)
        peak_rss = peak_threads = 0
        failure = None
        while child.poll() is None:
            try:
                status = Path(f"/proc/{child.pid}/status").read_text()
                fields = dict(line.split(":", 1) for line in status.splitlines())
                peak_rss = max(peak_rss, int(fields.get("VmHWM", "0 kB").split()[0])*1024)
                peak_threads = max(peak_threads, int(fields.get("Threads", "0")))
            except FileNotFoundError:
                pass
            if time.monotonic() - start > 60:
                failure = "wall limit exceeded"
            elif peak_rss > LIMIT or peak_threads > 2:
                failure = "RSS or thread limit exceeded"
            if failure:
                child.kill()
                break
            time.sleep(0.02)
        child.wait()
        stdout.seek(0)
        stderr.seek(0)
        return {"returncode": child.returncode, "failure": failure,
                "wall_seconds": time.monotonic() - start,
                "sampled_peak_RSS_bytes": peak_rss, "sampled_peak_process_threads": peak_threads,
                "stdout": stdout.read().decode(errors="replace"),
                "stderr": stderr.read().decode(errors="replace")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=128)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.n not in (48, 128):
        parser.error("registered diagnostic cases are 48 (padding) and 128")
    head = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
    common = Path(git("rev-parse", "--path-format=absolute", "--git-common-dir"))
    target = common.parent / "rust" / "target"
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL="0",
               CARGO_PROFILE_DEV_DEBUG="0", RAYON_NUM_THREADS="1")
    cargo = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
    command = [cargo, "build", "--offline", "--locked", "-j", "2", "-p", "volta-pcs",
               "--features", "c71-cpu-matrix-reference", "--example", "c71_matrix"]
    build = subprocess.run(command, cwd=ROOT / "rust", env=env, capture_output=True, text=True)
    if build.returncode:
        raise SystemExit(build.stderr)
    binary = target / "debug" / "examples" / "c71_matrix"
    report = {"milestone": "c71-b2-matrix-diagnostic", "git_commit": head,
              "git_dirty": dirty, "run_of_record": not dirty, "credit": False,
              "build_profile": "dev unoptimized, debug symbols disabled, native CPU",
              "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
              "host": os.uname()._asdict() if hasattr(os.uname(), "_asdict") else list(os.uname()),
              "build_command": command, "runtime_limits": {"wall_seconds": 60,
              "address_space_and_RSS_bytes": LIMIT, "process_threads": 2, "rayon_workers": 1}}
    report["started_at_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    screen = bounded([str(binary), "preflight", str(args.n)], env)
    report["preflight_process"] = screen
    if screen["returncode"] == 0:
        report["preflight"] = json.loads(screen.pop("stdout"))
    if args.run and screen["returncode"] == 0:
        with tempfile.TemporaryDirectory(prefix="volta-c71-disposable-state-") as state:
            run = bounded([str(binary), "run", str(args.n), state], env)
        report["execution_process"] = run
        if run["returncode"] == 0:
            report["execution"] = json.loads(run.pop("stdout"))
    success = screen["returncode"] == 0 and screen["failure"] is None and (
        not args.run or (report.get("execution_process", {}).get("returncode") == 0
                        and report["execution_process"]["failure"] is None))
    report["status"] = "pass" if success else "failed"
    report["git_dirty"] = dirty or bool(git("status", "--porcelain", "--untracked-files=all"))
    report["source_changed_during_run"] = git("rev-parse", "HEAD") != head
    report["run_of_record"] = not report["git_dirty"] and not report["source_changed_during_run"]
    date = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = args.output or ROOT / "benchmarks" / "results" / f"c71-b2-matrix-{date}-{head[:10]}.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(output)
    if not success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
