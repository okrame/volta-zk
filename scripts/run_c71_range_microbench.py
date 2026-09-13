#!/usr/bin/env python3
"""Build the bounded C7.1 range kernels; GPU execution is always explicit."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import shutil
import subprocess
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "cuda" / "c71_range_microbench.cu"
RESULTS = REPO / "benchmarks" / "results"
SCHEMA = "volta-c71-range-microbench-v1"
SEED = "0xc701351125020001"
ARENA = 6_442_450_944
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


def tracked_dirty() -> bool:
    return bool(
        subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO, text=True
        )
    )


def benchmark_sources_dirty() -> bool:
    return bool(
        subprocess.check_output(
            [
                "git", "status", "--porcelain", "--untracked-files=all", "--",
                str(SOURCE.relative_to(REPO)),
                str(Path(__file__).resolve().relative_to(REPO)),
                "tests/test_c71_range_microbench.py",
            ],
            cwd=REPO,
            text=True,
        )
    )


def source_sha256() -> str:
    return hashlib.sha256(SOURCE.read_bytes()).hexdigest()


def range_device_bytes(log2_n: int) -> int:
    n = 1 << log2_n
    blocks0 = ((n // 2) + 255) // 256
    blocks1 = (blocks0 + 255) // 256
    return 180 * n + 96 * (blocks0 + blocks1)


def gram_device_bytes(log2_n: int, width: int) -> int:
    n = 1 << log2_n
    buckets = n // width
    groups = (buckets + 255) // 256
    return 24 * ((4 * n + buckets) + buckets * width * width + groups * width * width)


def validate(kernel: dict, mode: str, log2_n: int, gram_log2_n: int, gram_width: int) -> None:
    if kernel.get("schema") != SCHEMA or kernel.get("mode") != mode:
        raise SystemExit("range microbenchmark schema or mode differs")
    if kernel.get("field") != {
        "base_modulus": 18_446_744_069_414_584_321,
        "extension": "Fp[u]/(u^3-2)",
        "fp3_bytes": 24,
    }:
        raise SystemExit("range microbenchmark field differs from volta-field")
    if kernel.get("input") != {
        "generator": "splitmix64-v1",
        "seed": SEED,
        "log2_n": log2_n,
        "gram_width": gram_width,
        **({"gram_log2_n": gram_log2_n} if mode == "cuda" else {}),
    }:
        raise SystemExit("range microbenchmark input provenance differs")
    if kernel.get("operation_model") != {
        "cubic_direct_oracle_fp3_mul_per_pair": 27,
        "cubic_factored_kernel_fp3_mul_per_pair": 18,
    }:
        raise SystemExit("range microbenchmark operation model differs")
    expected_correctness = (
        {"small_cpu_gpu_reference": True}
        if mode == "cuda"
        else {"field": True, "merge": True, "cubic_coeff": True, "fold": True, "gram": True}
    )
    if kernel.get("correctness") != expected_correctness:
        raise SystemExit("range microbenchmark correctness check failed")
    if mode == "cuda":
        allocation = kernel.get("allocation", {})
        range_expected = range_device_bytes(log2_n)
        gram_expected = gram_device_bytes(gram_log2_n, gram_width)
        expected = max(range_expected, gram_expected)
        if (
            allocation.get("range_requested_peak_bytes") != range_expected
            or allocation.get("gram_requested_peak_bytes") != gram_expected
            or allocation.get("requested_peak_bytes") != expected
        ):
            raise SystemExit("range microbenchmark allocation census differs")
        if expected > ARENA:
            raise SystemExit("range microbenchmark requested buffers exceed the C7.1 arena")
        allocation_times = [float(allocation.get(key, 0))
                            for key in ("allocation_ms", "gram_allocation_ms")]
        if any(not math.isfinite(value) or value <= 0 for value in allocation_times):
            raise SystemExit("range microbenchmark allocation timing is not positive")
        timing = kernel.get("timing_ms")
        expected_timing = {
            "initialize", "merge", "cubic_coeff_and_reduce", "fold_five_arrays",
            "gram_initialize", "gram_private_matrices_and_reduce",
        }
        if not isinstance(timing, dict) or set(timing) != expected_timing or any(
            not math.isfinite(float(timing[key])) or float(timing[key]) <= 0
            for key in expected_timing
        ):
            raise SystemExit("range microbenchmark timing is not positive")


def cloud_metadata() -> dict[str, str]:
    missing = [name for name in CLOUD_ENV.values() if not os.environ.get(name)]
    if missing:
        raise SystemExit(f"missing required cloud environment: {', '.join(missing)}")
    return {key: os.environ[name] for key, name in CLOUD_ENV.items()}


def unique_result_path(date: str, sha: str, quick: bool) -> Path:
    label = "c71-range-microbench-quick" if quick else "c71-range-microbench"
    first = RESULTS / f"{label}-{date}-{sha}.json"
    if not first.exists():
        return first
    for suffix in range(1, 1000):
        candidate = RESULTS / f"{label}-{date}-{sha}-{suffix}.json"
        if not candidate.exists():
            return candidate
    raise SystemExit("could not allocate append-only range result path")


def compile_and_run(
    compiler: str, compile_args: list[str], run_args: list[str], timeout_seconds: int
) -> dict:
    with tempfile.TemporaryDirectory(prefix="volta-c71-range-") as tmp:
        binary = Path(tmp) / "c71_range_microbench"
        command = [compiler, *compile_args, str(SOURCE), "-o", str(binary)]
        print("compile:", " ".join(command), flush=True)
        subprocess.run(command, cwd=REPO, check=True, timeout=timeout_seconds)
        run = [str(binary), *run_args]
        print("run:", " ".join(run), flush=True)
        return json.loads(
            subprocess.check_output(run, cwd=REPO, text=True, timeout=timeout_seconds)
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-only", action="store_true")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--host-log2", type=int, default=10)
    parser.add_argument("--cxx", default=shutil.which("g++") or "g++")
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--arch", default="sm_90")
    parser.add_argument("--gram-width", type=int, choices=(8, 16, 32), default=8)
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 3600:
        raise SystemExit("--timeout-seconds must be in [1, 3600]")
    provenance = {"source": str(SOURCE.relative_to(REPO)), "source_sha256": source_sha256()}
    if args.host_only:
        kernel = compile_and_run(
            args.cxx, ["-O2", "-std=c++17", "-x", "c++"],
            ["--host-check", str(args.host_log2), str(args.gram_width)], args.timeout_seconds,
        )
        validate(kernel, "host-check", args.host_log2, args.host_log2, args.gram_width)
        print(json.dumps({"provenance": provenance, "kernel": kernel}, indent=2, sort_keys=True))
        return 0

    cloud = cloud_metadata()
    if tracked_dirty() or benchmark_sources_dirty():
        raise SystemExit("refusing CUDA microbenchmark from a dirty tree or untracked benchmark source")
    sha = git("rev-parse", "HEAD")
    log2_n, reps = (18, 3) if args.quick else (25, 7)
    gram_log2_n = 18 if args.quick else 25 - args.gram_width.bit_length() + 1
    kernel = compile_and_run(
        args.nvcc, ["-O3", "-std=c++17", f"-arch={args.arch}"],
        ["--gpu", str(log2_n), str(reps), str(gram_log2_n), str(args.gram_width)],
        args.timeout_seconds,
    )
    validate(kernel, "cuda", log2_n, gram_log2_n, args.gram_width)
    if git("rev-parse", "HEAD") != sha or tracked_dirty() or benchmark_sources_dirty():
        raise SystemExit("checkout changed during the microbenchmark; no clean-run credit")
    date = dt.date.today().isoformat()
    report = {
        "milestone": "C7.1-range-kernels-quick" if args.quick else "C7.1-range-kernels",
        "date": date,
        "git_sha": sha,
        "git_dirty": False,
        "cloud": cloud,
        "compiler": {"nvcc": args.nvcc, "arch": args.arch},
        "provenance": provenance,
        "kernel": kernel,
        "scope": {
            "range_fp3_arithmetic_only": True,
            "cubic_factored_18_mul_kernel_with_direct_27_mul_oracle": True,
            "contiguous_materialized_arrays": True,
            "bounded_gram_component_only": True,
            "full_gram_schedule": False,
            "gather_or_checkpoint_schedule": False,
            "transcript_or_mac": False,
            "pcs": False,
            "complete_prover": False,
        },
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = unique_result_path(date, sha[:12], args.quick)
    with path.open("x") as output:
        output.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"correctness": kernel["correctness"], "timing_ms": kernel["timing_ms"]}, indent=2))
    print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
