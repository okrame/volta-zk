#!/usr/bin/env python3
"""Compile/run the preregistered Thunder CUDA-over-TCP RTT microbenchmark."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "cuda" / "p7b_thunder_cuda_rtt.cu"
RESULTS = REPO / "benchmarks" / "results"
BURST_SIZES = (1, 8, 64, 512, 4096)
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
    return bool(
        subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=REPO,
            text=True,
        )
    )


def cloud_metadata() -> dict[str, str]:
    missing = [name for name in CLOUD_ENV.values() if not os.environ.get(name)]
    if missing:
        raise SystemExit(f"missing required cloud environment: {', '.join(missing)}")
    return {key: os.environ[name] for key, name in CLOUD_ENV.items()}


def unique_result_path(label: str, date: str, sha: str) -> Path:
    first = RESULTS / f"{label}-{date}-{sha}.json"
    if not first.exists():
        return first
    for suffix in range(1, 1000):
        candidate = RESULTS / f"{label}-{date}-{sha}-{suffix}.json"
        if not candidate.exists():
            return candidate
    raise SystemExit("could not allocate an append-only result filename")


def _by_size(rows: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    return {int(row["kernels"]): row for row in rows}


def classify(kernel: dict[str, Any]) -> dict[str, Any]:
    """Apply only the decision thresholds preregistered in the ledger."""

    direct = _by_size(kernel["direct_bursts"])
    graphs = _by_size(kernel["cuda_graphs"])
    largest = BURST_SIZES[-1]
    baseline_us = float(kernel["empty_launch_sync"]["median_us"])
    enqueue_per_launch_us = float(
        direct[largest]["enqueue_per_launch"]["median_us"]
    )
    total_per_launch_us = float(direct[largest]["total_per_launch"]["median_us"])
    direct_total_us = float(direct[largest]["total"]["median_us"])
    graph_total_us = float(graphs[largest]["total"]["median_us"])
    async_pipelined = (
        enqueue_per_launch_us <= baseline_us * 0.10
        and total_per_launch_us <= baseline_us * 0.10
    )
    graph_speedup = direct_total_us / graph_total_us
    return {
        "largest_burst_kernels": largest,
        "empty_launch_sync_median_us": baseline_us,
        "blocking_d2h_8b_median_us": float(
            kernel["blocking_d2h_8b"]["median_us"]
        ),
        "cuda_malloc_8b_median_us": float(
            kernel["allocation_8b"]["malloc"]["median_us"]
        ),
        "cuda_free_8b_median_us": float(
            kernel["allocation_8b"]["free"]["median_us"]
        ),
        "direct_enqueue_per_launch_us": enqueue_per_launch_us,
        "direct_total_per_launch_us": total_per_launch_us,
        "direct_async_launches_pipelined": async_pipelined,
        "pipelined_threshold_fraction_of_blocking_rtt": 0.10,
        "graph_replay_total_us": graph_total_us,
        "graph_speedup_vs_direct_burst": graph_speedup,
        "cuda_graph_material_lever": graph_speedup >= 1.20,
        "graph_material_threshold_speedup": 1.20,
        "implementation_branch": (
            "eliminate-blocking-d2h-first"
            if async_pipelined
            else "coarsen-launch-surface-and-eliminate-blocking-d2h"
        ),
        "note": (
            "Classification selects the P7b implementation order only; it is "
            "not an end-to-end prover performance claim."
        ),
    }


def validate_kernel(kernel: dict[str, Any], duration_seconds: float) -> None:
    if not kernel.get("correctness"):
        raise SystemExit("CUDA microbenchmark D2H sentinel check failed")
    if not kernel.get("timing_sane"):
        raise SystemExit("CUDA microbenchmark did not observe completed operations")
    direct_sizes = tuple(row["kernels"] for row in kernel["direct_bursts"])
    graph_sizes = tuple(row["kernels"] for row in kernel["cuda_graphs"])
    if direct_sizes != BURST_SIZES or graph_sizes != BURST_SIZES:
        raise SystemExit("CUDA microbenchmark burst grid differs from preregistration")
    expected_graph_samples = 31 if duration_seconds >= 60 else 7
    if any(
        row["total"]["count"] != expected_graph_samples
        for row in kernel["cuda_graphs"]
    ):
        raise SystemExit("CUDA graph replay sample count differs from preregistration")
    if duration_seconds >= 60 and kernel["measurement_wall_s"] < duration_seconds * 0.90:
        raise SystemExit("CUDA microbenchmark ended materially before its target duration")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--arch", default="sm_80")
    parser.add_argument(
        "--duration-seconds",
        type=float,
        help="timed-case budget; defaults to 1800 (12 in --quick mode)",
    )
    parser.add_argument("--quick", action="store_true")
    args = parser.parse_args()

    duration_seconds = args.duration_seconds
    if duration_seconds is None:
        duration_seconds = 12.0 if args.quick else 1800.0
    if duration_seconds <= 0:
        raise SystemExit("--duration-seconds must be positive")

    cloud = cloud_metadata()
    sha = git("rev-parse", "--short", "HEAD")
    dirty = git_dirty()
    if dirty:
        raise SystemExit("refusing CUDA microbenchmark from a dirty tracked tree")

    with tempfile.TemporaryDirectory(prefix="volta-p7b-thunder-rtt-") as tmp:
        binary = Path(tmp) / "p7b_thunder_cuda_rtt"
        compile_cmd = [
            args.nvcc,
            "-O3",
            "-std=c++17",
            f"-arch={args.arch}",
            str(SOURCE),
            "-o",
            str(binary),
        ]
        print("compile:", " ".join(compile_cmd), flush=True)
        subprocess.run(compile_cmd, cwd=REPO, check=True)
        run_cmd = [str(binary), str(duration_seconds)]
        print("run:", " ".join(run_cmd), flush=True)
        kernel = json.loads(subprocess.check_output(run_cmd, cwd=REPO, text=True))

    validate_kernel(kernel, duration_seconds)
    report = {
        "milestone": "P7b-thunder-cuda-rtt-quick" if args.quick else "P7b-thunder-cuda-rtt",
        "date": dt.date.today().isoformat(),
        "git_sha": sha,
        "git_dirty": dirty,
        "cloud": cloud,
        "compiler": {"nvcc": args.nvcc, "arch": args.arch},
        "kernel": kernel,
        "decision": classify(kernel),
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    label = "p7b-thunder-cuda-rtt-quick" if args.quick else "p7b-thunder-cuda-rtt"
    path = unique_result_path(label, report["date"], sha)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report["decision"], indent=2, sort_keys=True))
    print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
