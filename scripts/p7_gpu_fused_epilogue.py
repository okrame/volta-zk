#!/usr/bin/env python3
"""Compile and run the P7 fused GPU GEMM-MAC epilogue spike."""

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
SOURCE = REPO / "cuda" / "p7_fused_epilogue.cu"
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
    path = Path("/sys/fs/cgroup/cpu.max")
    if path.exists():
        quota, period = path.read_text().split()
        if quota != "max":
            return max(1, math.floor(int(quota) / int(period)))
    return os.cpu_count() or 1


def unique_path(label: str, date: str, sha: str) -> Path:
    first = RESULTS / f"{label}-{date}-{sha}.json"
    if not first.exists():
        return first
    for i in range(1, 1000):
        path = RESULTS / f"{label}-{date}-{sha}-{i}.json"
        if not path.exists():
            return path
    raise SystemExit("could not allocate append-only fused-epilogue result path")


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
        raise SystemExit("refusing fused-epilogue run from a dirty tracked tree")
    m, k, shift = (16, 128, 8) if args.quick else (100, 768, 8)
    gpu_rounds, cpu_reps = (3, 1) if args.quick else (9, 3)

    with tempfile.TemporaryDirectory(prefix="volta-p7-fused-") as tmp:
        binary = Path(tmp) / "p7_fused_epilogue"
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
            str(m),
            str(k),
            str(shift),
            str(gpu_rounds),
            str(cpu_reps),
            str(args.cpu_threads),
        ]
        print("run:", " ".join(run_cmd), flush=True)
        kernel = json.loads(subprocess.check_output(run_cmd, cwd=REPO, text=True))

    report = {
        "milestone": "P7-gpu-fused-epilogue-quick" if args.quick else "P7-gpu-fused-epilogue",
        "date": dt.date.today().isoformat(),
        "git_sha": sha,
        "git_dirty": dirty,
        "cloud": cloud,
        "compiler": {"nvcc": args.nvcc, "arch": args.arch},
        "kernel": kernel,
        "scope": {
            "proving_path_integrated": False,
            "pcg_masks": "resident pre-expanded pool; setup/expansion budgeted separately",
            "correction_only_followup_kernel": False,
            "note": "P1-equivalent GPU spike; not an e2e rho measurement.",
        },
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    label = "p7-gpu-fused-epilogue-quick" if args.quick else "p7-gpu-fused-epilogue"
    path = unique_path(label, report["date"], sha)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "correctness": kernel["correctness"],
                "weighted_rho_kernel": kernel["weighted_rho_kernel"],
                "gate_weighted_rho_le_1_30": kernel["gate_weighted_rho_le_1_30"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    print(f"wrote {path.relative_to(REPO)}")
    return 0 if kernel["gate_weighted_rho_le_1_30"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
