#!/usr/bin/env python3
"""Compile/run CUDA PCS gather+Blake3/Merkle and cross-check Rust blake3."""

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
SOURCE = REPO / "cuda" / "p7_blake3_merkle.cu"
RESULTS = REPO / "benchmarks" / "results"
CLOUD_ENV = {
    "provider": "VOLTA_CLOUD_PROVIDER", "instance_id": "VOLTA_CLOUD_INSTANCE_ID",
    "region": "VOLTA_CLOUD_REGION", "image": "VOLTA_CLOUD_IMAGE",
    "driver_version": "VOLTA_CLOUD_DRIVER_VERSION", "cuda_version": "VOLTA_CLOUD_CUDA_VERSION",
    "gpu_sku": "VOLTA_CLOUD_GPU_SKU", "cpu_model": "VOLTA_CLOUD_CPU_MODEL",
    "ram_gib": "VOLTA_CLOUD_RAM_GIB", "vcpus": "VOLTA_CLOUD_VCPUS",
}


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=REPO, text=True).strip()


def cpu_threads() -> int:
    quota, period = Path("/sys/fs/cgroup/cpu.max").read_text().split()
    return max(1, math.floor(int(quota) / int(period))) if quota != "max" else (os.cpu_count() or 1)


def unique_path(label: str, date: str, sha: str) -> Path:
    first = RESULTS / f"{label}-{date}-{sha}.json"
    if not first.exists(): return first
    for i in range(1, 1000):
        p = RESULTS / f"{label}-{date}-{sha}-{i}.json"
        if not p.exists(): return p
    raise SystemExit("could not allocate append-only blake3 result path")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    ap.add_argument("--arch", default="sm_80")
    ap.add_argument("--cargo", default="cargo")
    ap.add_argument("--cpu-threads", type=int, default=cpu_threads())
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    cloud = {k: os.environ.get(v, "") for k, v in CLOUD_ENV.items()}
    if not all(cloud.values()): raise SystemExit("missing VOLTA_CLOUD_* metadata")
    sha = git("rev-parse", "--short", "HEAD")
    is_dirty = bool(subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO, text=True))
    if is_dirty: raise SystemExit("refusing blake3 run from dirty tracked tree")
    rows, cols, gpu_reps, cpu_reps = (32, 1024, 3, 1) if args.quick else (1024, 32768, 7, 3)

    with tempfile.TemporaryDirectory(prefix="volta-p7-blake3-") as tmp:
        binary = Path(tmp) / "p7_blake3_merkle"
        compile_cmd = [args.nvcc, "-O3", "-std=c++17", f"-arch={args.arch}",
                       "-Xcompiler=-fopenmp", str(SOURCE), "-o", str(binary)]
        print("compile:", " ".join(compile_cmd), flush=True)
        subprocess.run(compile_cmd, cwd=REPO, check=True)
        kernel = json.loads(subprocess.check_output(
            [str(binary), str(rows), str(cols), str(gpu_reps)], cwd=REPO, text=True))
        env = dict(os.environ, RAYON_NUM_THREADS=str(args.cpu_threads))
        rust = json.loads(subprocess.check_output(
            [args.cargo, "run", "--release", "-q", "-p", "volta-bench", "--bin",
             "p7_blake3_reference", "--", str(rows), str(cols), str(cpu_reps),
             str(args.cpu_threads)], cwd=REPO / "rust", env=env, text=True))

    root_matches = kernel["root"] == rust["root"]
    gate = (kernel["host_device_correctness"] and root_matches and kernel["timing_sane"]
            and kernel["gpu_s"] <= 0.075)
    report = {
        "milestone": "P7-gpu-blake3-merkle-quick" if args.quick else "P7-gpu-blake3-merkle",
        "date": dt.date.today().isoformat(), "git_sha": sha, "git_dirty": is_dirty,
        "cloud": cloud, "compiler": {"nvcc": args.nvcc, "arch": args.arch},
        "kernel": kernel, "rust_reference": rust, "root_matches_rust_blake3": root_matches,
        "gate_gpu_s_le_0_075_and_correct": gate,
        "scope": {"column_gather_fused": True, "blake3_merkle": True,
                  "mask_rows_integrated": False, "proving_path_integrated": False},
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    label = "p7-gpu-blake3-merkle-quick" if args.quick else "p7-gpu-blake3-merkle"
    path = unique_path(label, report["date"], sha)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"gpu_s": kernel["gpu_s"], "rust_cpu_s": rust["cpu_s"],
                      "root_matches": root_matches, "gate": gate}, indent=2, sort_keys=True))
    print(f"wrote {path.relative_to(REPO)}")
    return 0 if gate else 1


if __name__ == "__main__": raise SystemExit(main())
