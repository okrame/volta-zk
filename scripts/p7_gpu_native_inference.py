#!/usr/bin/env python3
"""Compile and run the exact P7 native fixed-point GPU inference anchor."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import subprocess
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "cuda" / "p7_native_inference.cu"
RESULTS = REPO / "benchmarks" / "results"
WEIGHTS = REPO / "benchmarks" / "weights" / "gpt2s-q.bin"
PARAMS = REPO / "benchmarks" / "weights" / "gpt2s-q.params"
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


def cloud() -> dict[str, str]:
    missing = [v for v in CLOUD_ENV.values() if not os.environ.get(v)]
    if missing:
        raise SystemExit(f"missing required cloud environment: {', '.join(missing)}")
    return {k: os.environ[v] for k, v in CLOUD_ENV.items()}


def baseline(instance_id: str, explicit: str | None) -> tuple[Path, dict]:
    allowed = {"P6", "P7-integrated-hybrid"}

    def accepted(_path: Path, data: dict) -> bool:
        return (
            data.get("milestone") in allowed
            and data.get("accepted")
            and not data.get("git_dirty")
            and (data.get("cloud") or {}).get("instance_id") == instance_id
            and isinstance(data.get("generated_tokens"), list)
            and data.get("t_native_prefill_s", 0) > 0
            and data.get("t_native_decode_s", 0) > 0
        )

    if explicit:
        path = Path(explicit)
        if not path.is_absolute():
            path = REPO / path
        path = path.resolve()
        try:
            path.relative_to(REPO)
            data = json.loads(path.read_text())
        except (ValueError, OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"invalid explicit native baseline {path}: {exc}") from exc
        if not accepted(path, data):
            raise SystemExit(
                f"baseline {path} must be clean, accepted, same-instance P6/P7-integrated-hybrid"
            )
        return path, data

    rows: list[tuple[float, Path, dict]] = []
    candidates = list(RESULTS.glob("p6-*.json")) + list(
        RESULTS.glob("p7-integrated-hybrid-*.json")
    )
    for path in candidates:
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        if accepted(path, data):
            rows.append((path.stat().st_mtime, path, data))
    if not rows:
        raise SystemExit(
            f"no clean accepted P6/P7-integrated-hybrid baseline for cloud instance {instance_id}"
        )
    _, path, data = max(rows)
    return path, data


def unique_path(label: str, date: str, sha: str) -> Path:
    path = RESULTS / f"{label}-{date}-{sha}.json"
    if not path.exists():
        return path
    for i in range(1, 1000):
        candidate = RESULTS / f"{label}-{date}-{sha}-{i}.json"
        if not candidate.exists():
            return candidate
    raise SystemExit("could not allocate append-only native-inference result path")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nvcc", default="/usr/local/cuda/bin/nvcc")
    ap.add_argument("--arch", default="sm_80")
    ap.add_argument("--quick", action="store_true")
    ap.add_argument(
        "--baseline",
        help="explicit clean same-instance P6 or P7-integrated-hybrid JSON",
    )
    args = ap.parse_args()
    meta = cloud()
    sha = git("rev-parse", "--short", "HEAD")
    dirty = bool(git("status", "--porcelain", "--untracked-files=no"))
    if dirty:
        raise SystemExit("refusing native-inference run from a dirty tracked tree")
    if not WEIGHTS.exists() or not PARAMS.exists():
        raise SystemExit("missing benchmarks/weights/gpt2s-q.{bin,params}")
    base_path, base = baseline(meta["instance_id"], args.baseline)
    reps = 1 if args.quick else 7

    with tempfile.TemporaryDirectory(prefix="volta-p7-native-inference-") as tmp:
        binary = Path(tmp) / "p7_native_inference"
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
        run_cmd = [str(binary), str(WEIGHTS), str(PARAMS), str(reps)]
        print("run:", " ".join(run_cmd), flush=True)
        kernel = json.loads(subprocess.check_output(run_cmd, cwd=REPO, text=True))

    expected = base["generated_tokens"]
    golden = kernel["prefill_argmax"] == expected[0] and kernel["generated_tokens"] == expected
    correctness = golden and kernel["deterministic"] and not kernel["fixed_point_errors"]
    for name, legacy in (("prefill_timing", "prefill_s"), ("decode_50_timing", "decode_50_s")):
        timing = kernel[name]
        if len(timing["samples_s"]) != reps or timing["median_s"] != kernel[legacy]:
            raise SystemExit(f"invalid {name} distribution from CUDA harness")
    if kernel["memory"]["peak_device_bytes"] <= 0 or kernel["memory"]["peak_rss_bytes"] <= 0:
        raise SystemExit("native CUDA harness did not report peak memory")
    prefill_speedup = base["t_native_prefill_s"] / kernel["prefill_s"]
    decode_speedup = base["t_native_decode_s"] / kernel["decode_50_s"]
    report = {
        "report_schema_version": 2,
        "milestone": "P7-gpu-native-inference-quick" if args.quick else "P7-gpu-native-inference",
        "date": dt.date.today().isoformat(),
        "git_sha": sha,
        "git_dirty": dirty,
        "cloud": meta,
        "compiler": {"nvcc": args.nvcc, "arch": args.arch},
        "baseline": {
            "source": str(base_path.relative_to(REPO)),
            "milestone": base["milestone"],
            "native_prefill_s": base["t_native_prefill_s"],
            "native_decode_50_s": base["t_native_decode_s"],
        },
        "kernel": kernel,
        "golden_match": golden,
        "correctness": correctness,
        "native_gpu_speedup": {"prefill": prefill_speedup, "decode": decode_speedup},
        "scope": {
            "exact_fixed_point_full_model": True,
            "kv_cached_incremental_decode": True,
            "weights_upload_timed": False,
            "decode_logits_d2h_and_argmax_timed": True,
            "decode_cache_seed_prefill_timed": False,
            "decode_exactly_50_append_steps_timed": True,
            "proving_path_integrated": False,
        },
    }
    RESULTS.mkdir(parents=True, exist_ok=True)
    label = "p7-gpu-native-inference-quick" if args.quick else "p7-gpu-native-inference"
    path = unique_path(label, report["date"], sha)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "correctness": correctness,
                "prefill_s": kernel["prefill_s"],
                "decode_50_s": kernel["decode_50_s"],
                "prefill_speedup": prefill_speedup,
                "decode_speedup": decode_speedup,
            },
            indent=2,
            sort_keys=True,
        )
    )
    print(f"wrote {path.relative_to(REPO)}")
    return 0 if correctness else 1


if __name__ == "__main__":
    raise SystemExit(main())
