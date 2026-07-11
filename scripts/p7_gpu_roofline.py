#!/usr/bin/env python3
"""Compile and run the P7 CUDA Goldilocks/Fp2 roofline, then emit JSON."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import subprocess
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "cuda" / "p7_goldilocks_roofline.cu"
RESULTS = REPO / "benchmarks" / "results"

CLOUD_ENV = {
    "provider": "VOLTA_CLOUD_PROVIDER",
    "instance_id": "VOLTA_CLOUD_INSTANCE_ID",
    "region": "VOLTA_CLOUD_REGION",
    "image": "VOLTA_CLOUD_IMAGE",
    "driver_version": "VOLTA_CLOUD_DRIVER_VERSION",
    "cuda_version": "VOLTA_CLOUD_CUDA_VERSION",
    "gpu_sku": "VOLTA_CLOUD_GPU_SKU",
    "cpu_model": "VOLTA_CLOUD_CPU_MODEL",
    "ram_gib": "VOLTA_CLOUD_RAM_GIB",
    "vcpus": "VOLTA_CLOUD_VCPUS",
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=REPO, text=True).strip()


def git_dirty() -> bool:
    out = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO, text=True
    )
    return bool(out)


def cloud_metadata() -> dict[str, str]:
    missing = [env for env in CLOUD_ENV.values() if not os.environ.get(env)]
    if missing:
        raise SystemExit(f"missing required cloud environment: {', '.join(missing)}")
    return {name: os.environ[env] for name, env in CLOUD_ENV.items()}


def detected_cpu_threads() -> int:
    cpu_max = Path("/sys/fs/cgroup/cpu.max")
    if cpu_max.exists():
        quota, period = cpu_max.read_text().split()
        if quota != "max":
            return max(1, math.floor(int(quota) / int(period)))
    return os.cpu_count() or 1


def unique_result_path(label: str, date: str, sha: str) -> Path:
    first = RESULTS / f"{label}-{date}-{sha}.json"
    if not first.exists():
        return first
    for i in range(1, 1000):
        candidate = RESULTS / f"{label}-{date}-{sha}-{i}.json"
        if not candidate.exists():
            return candidate
    raise SystemExit("could not allocate an append-only result filename")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--arch", default="sm_80")
    parser.add_argument("--cpu-threads", type=int, default=detected_cpu_threads())
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    cloud = cloud_metadata()
    sha = git("rev-parse", "--short", "HEAD")
    dirty = git_dirty()
    if dirty:
        raise SystemExit("refusing GPU run of record from a dirty tracked tree")

    if args.quick:
        stream_log2, chain_log2, chain_rounds, gpu_reps, cpu_reps = 20, 16, 64, 3, 1
    else:
        stream_log2, chain_log2, chain_rounds, gpu_reps, cpu_reps = 24, 20, 256, 7, 3

    with tempfile.TemporaryDirectory(prefix="volta-p7-roofline-") as tmp:
        binary = Path(tmp) / "p7_goldilocks_roofline"
        compile_cmd = [
            args.nvcc,
            "-O3",
            "-std=c++17",
            f"-arch={args.arch}",
            "-Xcompiler=-fopenmp",
            str(SOURCE),
            "-o",
            str(binary),
        ]
        print("compile:", " ".join(compile_cmd), flush=True)
        subprocess.run(compile_cmd, cwd=REPO, check=True)
        run_cmd = [
            str(binary),
            str(stream_log2),
            str(chain_log2),
            str(chain_rounds),
            str(gpu_reps),
            str(cpu_reps),
            str(args.cpu_threads),
        ]
        print("run:", " ".join(run_cmd), flush=True)
        kernel = json.loads(subprocess.check_output(run_cmd, cwd=REPO, text=True))

    if not kernel.get("correctness"):
        raise SystemExit("GPU/CPU Goldilocks differential check failed")
    if not kernel.get("timing_sane"):
        raise SystemExit("GPU timing sanity check failed (completion was not observed)")
    required = {"prefill": 5.476393766687816, "decode": 3.9669730070632774}
    observed = min(
        kernel["stream"]["gpu_cpu_speedup"], kernel["chain"]["gpu_cpu_speedup"]
    )
    report = {
        "milestone": "P7-gpu-roofline-quick" if args.quick else "P7-gpu-roofline",
        "date": dt.date.today().isoformat(),
        "git_sha": sha,
        "git_dirty": dirty,
        "cloud": cloud,
        "compiler": {"nvcc": args.nvcc, "arch": args.arch},
        "kernel": kernel,
        "screening": {
            "required_relative_prover_vs_native_speedup": required,
            "min_observed_raw_gpu_cpu_speedup": observed,
            "plausible_headroom": observed >= max(required.values()),
            "note": "Roofline screening only; not an end-to-end proving-path gate.",
        },
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    label = "p7-gpu-roofline-quick" if args.quick else "p7-gpu-roofline"
    path = unique_result_path(label, report["date"], sha)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report["screening"], indent=2, sort_keys=True))
    print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
