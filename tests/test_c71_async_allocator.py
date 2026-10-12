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
                     "trim_failure", "fence_failure", "cache_limit", "free_failure", "free_fence_failure",
                     "nested_begin", "end_without_begin", "end_live", "end_query_failure", "end_trim_failure"):
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
        assert report["owner_bytes"] == 42576 and report["fixed_cache_reserve_bytes"] == 128 << 20
        rejected = 0
        records = [json.loads(line) for line in trace.read_text().splitlines()]
        if scenario == "normal":
            assert not any(r["op"] == "allocate" for r in records)
            assert any(r["op"] == "fence" and
                       r["cuda_used_bytes"] - r["pool_reserved_bytes"] == 20 << 20
                       for r in records)
            assert any(r["op"] == "c71_range_source_pool_end" and
                       r["pool_phase_active"] == 0 and r["pool_live_bytes"] == 0 and
                       r["arena_bytes"] == 512 for r in records)
        for record in records:
            if record["op"] == "pool_account":
                assert record["edge"] == "after" and record["status"] == -1
                assert scenario in ("query_failure", "cache_limit", "end_query_failure")
                rejected += 1
                continue
            assert record["pool_used_bytes"] <= record["pool_reserved_bytes"]
            assert record["pool_reserved_bytes"] <= record["pool_live_bytes"] + (128 << 20)
            assert record["pool_cache_peak_bytes"] <= 128 << 20
        assert rejected == int(scenario in ("query_failure", "cache_limit", "end_query_failure"))
        print(result.stdout.strip())
        if scenario == "normal":
            print("C71_SOURCE_POOL_PHASE " + json.dumps({
                "reserve_bytes": report["fixed_cache_reserve_bytes"],
                "host_owner_bytes": report["owner_bytes"],
                "initial_commitment_only": True, "end_requires_empty_pool": True,
                "gpu_execution": False, "credit": False}))
