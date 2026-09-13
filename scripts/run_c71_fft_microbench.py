#!/usr/bin/env python3
"""Build the bounded five-pass Goldilocks FFT; GPU execution is explicit."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "cuda" / "c71_fft_microbench.cu"
RESULTS = REPO / "benchmarks" / "results"
SCHEMA = "volta-c71-fft-microbench-v1"
SEED = "0xc701ff7025020001"
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


def source_sha256() -> str:
    return hashlib.sha256(SOURCE.read_bytes()).hexdigest()


def device_bytes(log2_m: int, batch: int) -> int:
    n = 1 << (2 * log2_m)
    return 8 * n * (batch + 1)


def dirty() -> bool:
    tracked = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO, text=True
    )
    relevant = subprocess.check_output(
        [
            "git", "status", "--porcelain", "--untracked-files=all", "--",
            str(SOURCE.relative_to(REPO)), str(Path(__file__).resolve().relative_to(REPO)),
        ],
        cwd=REPO,
        text=True,
    )
    return bool(tracked or relevant)


def cloud_metadata() -> dict[str, str]:
    missing = [name for name in CLOUD_ENV.values() if not os.environ.get(name)]
    if missing:
        raise SystemExit(f"missing required cloud environment: {', '.join(missing)}")
    return {key: os.environ[name] for key, name in CLOUD_ENV.items()}


def compile_and_run(
    compiler: str, compile_args: list[str], run_args: list[str], timeout_seconds: int
) -> tuple[dict, str]:
    with tempfile.TemporaryDirectory(prefix="volta-c71-fft-") as tmp:
        binary = Path(tmp) / "c71_fft_microbench"
        compile_command = [compiler, *compile_args, str(SOURCE), "-o", str(binary)]
        print("compile:", " ".join(compile_command), flush=True)
        built = subprocess.run(
            compile_command, cwd=REPO, check=True, timeout=timeout_seconds,
            text=True, capture_output=True,
        )
        if built.stdout:
            print(built.stdout, end="")
        if built.stderr:
            print(built.stderr, end="")
        run_command = [str(binary), *run_args]
        print("run:", " ".join(run_command), flush=True)
        kernel = json.loads(
            subprocess.check_output(run_command, cwd=REPO, text=True, timeout=timeout_seconds)
        )
        return kernel, built.stderr


def ptxas_report(stderr: str) -> dict:
    lines = [line.strip() for line in stderr.splitlines() if "ptxas info" in line]
    registers = [int(value) for value in re.findall(r"Used (\d+) registers", stderr)]
    stack = [tuple(map(int, match)) for match in re.findall(
        r"(\d+) bytes stack frame, (\d+) bytes spill stores, (\d+) bytes spill loads", stderr
    )]
    shared = [int(value) for value in re.findall(r"(\d+) bytes smem", stderr)]
    return {
        "lines": lines,
        "max_registers_per_thread": max(registers, default=None),
        "max_stack_frame_bytes": max((row[0] for row in stack), default=0),
        "max_spill_store_bytes": max((row[1] for row in stack), default=0),
        "max_spill_load_bytes": max((row[2] for row in stack), default=0),
        "max_static_shared_bytes": max(shared, default=0),
    }


def validate(kernel: dict, mode: str, log2_m: int, batch: int) -> None:
    n = 1 << (2 * log2_m)
    if kernel.get("schema") != SCHEMA or kernel.get("mode") != mode:
        raise SystemExit("FFT microbenchmark schema or mode differs")
    if kernel.get("field") != {
        "base_modulus": 18_446_744_069_414_584_321,
        "generator": 7,
        "element_bytes": 8,
    }:
        raise SystemExit("FFT microbenchmark field differs")
    expected_input = {
        "generator": "splitmix64-v1", "seed": SEED, "log2_m": log2_m, "length": n,
    }
    if mode == "cuda":
        expected_input |= {"m": 1 << log2_m, "batch": batch}
    if kernel.get("input") != expected_input:
        raise SystemExit("FFT microbenchmark input provenance differs")
    if kernel.get("algorithm") != {
        "passes": 5,
        "layout": "natural-order",
        "steps": ["transpose", "row-fft", "twiddle-transpose", "row-fft", "transpose"],
    }:
        raise SystemExit("FFT microbenchmark algorithm differs")
    expected_correctness = (
        {"small_cpu_gpu_natural_order": True}
        if mode == "cuda"
        else {
            "field": True,
            "primitive_root": True,
            "radix2_vs_dft": True,
            "five_pass_vs_dft": True,
            "tile_pair_plain_m64": True,
            "tile_pair_twiddle_m64": True,
            "tile_pair_unique_coverage_m64": True,
        }
    )
    if kernel.get("correctness") != expected_correctness:
        raise SystemExit("FFT microbenchmark correctness check failed")
    if mode == "cuda":
        allocation = kernel.get("allocation", {})
        expected_bytes = device_bytes(log2_m, batch)
        if (
            allocation.get("requested_peak_bytes") != expected_bytes
            or allocation.get("transpose_static_shared_bytes_per_block") != 16_896
            or allocation.get("row_fft_dynamic_shared_bytes_per_block") != 8 * (1 << log2_m)
            or expected_bytes > ARENA
        ):
            raise SystemExit("FFT microbenchmark allocation census exceeds its arena")
        allocation_ms = float(allocation.get("allocation_ms", 0))
        if not math.isfinite(allocation_ms) or allocation_ms <= 0:
            raise SystemExit("FFT microbenchmark allocation timing is invalid")
        timing = kernel.get("timing_ms")
        timing_keys = {"initialize", "twiddle_initialize", "five_pass_fft"}
        if not isinstance(timing, dict) or set(timing) != timing_keys or any(
            not math.isfinite(float(timing[key])) or float(timing[key]) <= 0 for key in timing_keys
        ):
            raise SystemExit("FFT microbenchmark kernel timing is invalid")
        if kernel.get("logical_global_traffic_bytes") != 10 * 8 * n * batch:
            raise SystemExit("FFT microbenchmark five-pass traffic census differs")


def unique_result_path(date: str, sha: str, quick: bool) -> Path:
    label = "c71-fft-microbench-quick" if quick else "c71-fft-microbench"
    base = RESULTS / f"{label}-{date}-{sha}.json"
    if not base.exists():
        return base
    for suffix in range(1, 1000):
        candidate = RESULTS / f"{label}-{date}-{sha}-{suffix}.json"
        if not candidate.exists():
            return candidate
    raise SystemExit("could not allocate append-only FFT result path")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-only", action="store_true")
    parser.add_argument("--quick", action="store_true")
    parser.add_argument("--host-log2-m", type=int, default=3)
    parser.add_argument("--cxx", default=shutil.which("g++") or "g++")
    parser.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    parser.add_argument("--arch", default="sm_90")
    parser.add_argument("--timeout-seconds", type=int, default=900)
    args = parser.parse_args()
    if not 1 <= args.timeout_seconds <= 3600:
        raise SystemExit("--timeout-seconds must be in [1, 3600]")
    provenance = {"source": str(SOURCE.relative_to(REPO)), "source_sha256": source_sha256()}
    if args.host_only:
        kernel, _ = compile_and_run(
            args.cxx, ["-O2", "-std=c++17", "-x", "c++"],
            ["--host-check", str(args.host_log2_m)], args.timeout_seconds,
        )
        validate(kernel, "host-check", args.host_log2_m, 1)
        print(json.dumps({"provenance": provenance, "kernel": kernel}, indent=2, sort_keys=True))
        return 0

    cloud = cloud_metadata()
    if dirty():
        raise SystemExit("refusing CUDA FFT microbenchmark from a dirty tree or untracked source")
    clean_sha = git("rev-parse", "HEAD")
    clean_source_sha = source_sha256()
    log2_m, batch, reps = (8, 8, 3) if args.quick else (11, 128, 7)
    kernel, compiler_stderr = compile_and_run(
        args.nvcc, ["-O3", "-std=c++17", f"-arch={args.arch}", "-Xptxas=-v"],
        ["--gpu", str(log2_m), str(batch), str(reps)], args.timeout_seconds,
    )
    if dirty() or git("rev-parse", "HEAD") != clean_sha or source_sha256() != clean_source_sha:
        raise SystemExit("FFT sources or clean SHA changed during the run")
    validate(kernel, "cuda", log2_m, batch)
    date = dt.date.today().isoformat()
    sha = clean_sha
    report = {
        "milestone": "C7.1-five-pass-FFT-quick" if args.quick else "C7.1-five-pass-FFT",
        "date": date,
        "git_sha": sha,
        "git_dirty": False,
        "cloud": cloud,
        "compiler": {
            "nvcc": args.nvcc,
            "arch": args.arch,
            "ptxas": ptxas_report(compiler_stderr),
        },
        "provenance": provenance,
        "kernel": kernel,
        "scope": {
            "physical_cuda_component": True,
            "one_coset_buffer": True,
            "finite_reference_only_for_host": True,
            "full_pcs_encoding": False,
            "reader_hash_salts_frontier": False,
            "complete_prover": False,
        },
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    path = unique_result_path(date, sha[:12], args.quick)
    with path.open("x") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")
    print(json.dumps({"correctness": kernel["correctness"], "timing_ms": kernel["timing_ms"]}, indent=2))
    print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
