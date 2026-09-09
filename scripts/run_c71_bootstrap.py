#!/usr/bin/env python3
"""Run one bounded B9 component case; preserve provenance and failed results."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from run_c71_matrix import ROOT, LIMIT, bounded, git

FAULTS = ("none", "prover-context", "verifier-context", "receiver-point", "sender-point",
          "seed-ciphertext", "cope-error", "check-response", "challenge-codec",
          "compression-codec", "frame-order")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, choices=(3, 32), default=3)
    parser.add_argument("--fault", choices=FAULTS, default="none")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    head = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--untracked-files=all"))
    common = Path(git("rev-parse", "--path-format=absolute", "--git-common-dir"))
    target = common.parent / "rust" / "target"
    env = dict(os.environ, CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL="0",
               CARGO_PROFILE_DEV_DEBUG="0", CARGO_PROFILE_DEV_OPT_LEVEL="2", RAYON_NUM_THREADS="1")
    cargo = shutil.which("cargo") or str(Path.home()/".cargo/bin/cargo")
    command = [cargo, "build", "--offline", "--locked", "-j", "2", "-p", "volta-pcg",
               "--features", "c71-bootstrap", "--example", "c71_bootstrap"]
    start = datetime.datetime.now(datetime.timezone.utc)
    report = {"milestone": "c71-b9-bootstrap", "git_commit": head, "git_dirty": dirty,
              "credit": False, "run_of_record": False, "rows": args.n, "fault": args.fault,
              "started_at_utc": start.isoformat(), "build_command": command,
              "build_profile": "dev opt-level=2, debug=0, native CPU; operation counters enabled",
              "runtime_limits": {"wall_seconds": 60, "address_space_and_RSS_bytes": LIMIT, "threads": 2},
              "host": list(os.uname()),
              "rustc_version": subprocess.check_output([str(Path(cargo).with_name("rustc")), "-vV"], text=True)}
    build = subprocess.run(command, cwd=ROOT/"rust", env=env, capture_output=True, text=True)
    report["build"] = {"returncode": build.returncode, "stderr": build.stderr}
    success = False
    if build.returncode == 0:
        binary = target/"debug/examples/c71_bootstrap"
        report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        run = bounded([str(binary), str(args.n), args.fault], env)
        report["execution_process"] = run
        success = run["returncode"] == 0 and run["failure"] is None
        if success:
            try:
                result = json.loads(run["stdout"])
                assert result["schema"] == "c71-b9-native-v1"
                assert result["accepted"] == (args.fault == "none")
                report["execution"] = result
                del run["stdout"]
            except (ValueError, KeyError, AssertionError) as error:
                success = False
                run["failure"] = f"native report rejected: {error}"
    report["status"] = "pass" if success else "failed"
    report["git_dirty"] = dirty or bool(git("status", "--porcelain", "--untracked-files=all"))
    report["source_changed_during_run"] = git("rev-parse", "HEAD") != head
    report["run_of_record"] = not report["git_dirty"] and not report["source_changed_during_run"]
    report["physical_traffic_probe"] = {
        "event_sources": sorted(p.name for p in Path("/sys/bus/event_source/devices").iterdir()),
        "perf_event_paranoid": Path("/proc/sys/kernel/perf_event_paranoid").read_text().strip(),
        "DRAM_traffic_measured": False}
    date = start.strftime("%Y%m%dT%H%M%S%fZ")
    output = args.output or ROOT/"benchmarks/results"/f"c71-b9-{args.n}-{args.fault}-{date}-{head[:10]}.json"
    with output.open("x") as stream:
        json.dump(report, stream, indent=2, allow_nan=False)
        stream.write("\n")
    print(output)
    if not success:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
