"""Pool cache charging and failure cleanup; simulated driver only."""
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_async_pool_reserve_and_cleanup_failures(tmp_path):
    binary = tmp_path / "async-owner"
    subprocess.run(["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=undefined", "-fno-sanitize-recover=all", "-DC71_OWNER_TRACE",
        "-DC71_OWNER_TRACE_PHYSICAL", "-DC71_ASYNC_ALLOCATOR_EXPERIMENT",
        "-I", str(ROOT / "tests/cuda_stub"), "-I", str(ROOT / "cuda"),
        str(ROOT / "cuda/c71_range_runtime.cpp"), str(ROOT / "tests/c71_async_allocator_host.cpp"),
        "-o", str(binary)], check=True, timeout=30)
    for scenario in ("normal", "reserve_failure", "allocation_failure", "query_failure",
                     "trim_failure", "fence_failure", "cache_limit", "free_failure", "free_fence_failure"):
        environment = os.environ.copy()
        environment.pop("C71_OWNER_TRACE_A_FIRST", None)
        trace = tmp_path / f"{scenario}.jsonl"
        environment["C71_OWNER_TRACE_PATH"] = str(trace)
        result = subprocess.run([str(binary), scenario], env=environment,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stdout + result.stderr
        marker, payload = result.stdout.strip().split(" ", 1)
        assert marker == "C71_ASYNC_ALLOCATOR_HOST"
        report = json.loads(payload)
        assert report["scenario"] == scenario and report["credit"] is False
        assert report["owner_bytes"] == 42160 and report["fixed_cache_reserve_bytes"] == 64 << 20
        rejected = 0
        for line in trace.read_text().splitlines():
            record = json.loads(line)
            if record["op"] == "pool_account":
                assert record["edge"] == "after" and record["status"] == -1
                assert scenario in ("query_failure", "cache_limit")
                rejected += 1
                continue
            assert record["pool_used_bytes"] <= record["pool_reserved_bytes"]
            assert record["pool_reserved_bytes"] <= record["arena_bytes"] + (64 << 20)
            assert record["pool_cache_peak_bytes"] <= 64 << 20
        assert rejected == int(scenario in ("query_failure", "cache_limit"))
        print(result.stdout.strip())
