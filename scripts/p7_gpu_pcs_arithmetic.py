#!/usr/bin/env python3
"""Compile and run P7 GPU PCS NTT + combine_rows arithmetic spikes."""

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
SOURCE = REPO / "cuda" / "p7_pcs_arithmetic.cu"
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


def dirty() -> bool:
    return bool(
        subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO, text=True
        )
    )


def cloud() -> dict[str, str]:
    missing = [env for env in CLOUD_ENV.values() if not os.environ.get(env)]
    if missing:
        raise SystemExit(f"missing required cloud environment: {', '.join(missing)}")
    return {key: os.environ[env] for key, env in CLOUD_ENV.items()}


def cpu_threads() -> int:
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
        candidate = RESULTS / f"{label}-{date}-{sha}-{i}.json"
        if not candidate.exists():
            return candidate
    raise SystemExit("could not allocate append-only PCS arithmetic result path")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--arch", default="sm_80")
    parser.add_argument("--cpu-threads", type=int, default=cpu_threads())
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()
    sha = git("rev-parse", "--short", "HEAD")
    is_dirty = dirty()
    if is_dirty:
        raise SystemExit("refusing PCS arithmetic GPU run from a dirty tracked tree")
    if args.quick:
        rows, code_bits, msg_len, cols, gpu_reps, cpu_reps = 32, 12, 2304, 2048, 3, 1
    else:
        rows, code_bits, msg_len, cols, gpu_reps, cpu_reps = 1024, 15, 16896, 16384, 7, 3

    with tempfile.TemporaryDirectory(prefix="volta-p7-pcs-") as tmp:
        binary = Path(tmp) / "p7_pcs_arithmetic"
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
            str(rows),
            str(code_bits),
            str(msg_len),
            str(cols),
            str(gpu_reps),
            str(cpu_reps),
            str(args.cpu_threads),
        ]
        print("run:", " ".join(run_cmd), flush=True)
        kernel = json.loads(subprocess.check_output(run_cmd, cwd=REPO, text=True))

    report = {
        "milestone": "P7-gpu-pcs-arithmetic-quick" if args.quick else "P7-gpu-pcs-arithmetic",
        "date": dt.date.today().isoformat(),
        "git_sha": sha,
        "git_dirty": is_dirty,
        "cloud": cloud(),
        "compiler": {"nvcc": args.nvcc, "arch": args.arch},
        "kernel": kernel,
        "scope": {
            "ligero_params": "P4_LAYER" if not args.quick else "quick",
            "ntt_and_combine_rows": True,
            "pad_tail_integrated": False,
            "mask_rows_integrated": False,
            "column_gather_integrated": False,
            "blake3_integrated": False,
            "proving_path_integrated": False,
        },
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    label = "p7-gpu-pcs-arithmetic-quick" if args.quick else "p7-gpu-pcs-arithmetic"
    path = unique_path(label, report["date"], sha)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "correctness": kernel["correctness"],
                "ntt_speedup": kernel["ntt"]["gpu_cpu_speedup"],
                "combine_rows_speedup": kernel["combine_rows"]["gpu_cpu_speedup"],
                "gate_each_speedup_ge_5_48": kernel["gate_each_speedup_ge_5_48"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    print(f"wrote {path.relative_to(REPO)}")
    return 0 if kernel["gate_each_speedup_ge_5_48"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
