"""Deferred backing preserves values, ownership and debt on failures."""
import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("pool", [False, True])
def test_deferred_backing_and_failure_debt(tmp_path, pool):
    binary = tmp_path / "source-tail"
    subprocess.run(["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=undefined", "-fno-sanitize-recover=all", "-DC71_OWNER_TRACE",
        "-DC71_OWNER_TRACE_PHYSICAL", "-DC71_SOURCE_VMM_EXPERIMENT",
        *(["-DC71_ASYNC_ALLOCATOR_EXPERIMENT"] if pool else []),
        "-I", str(ROOT / "tests/cuda_stub"), "-I", str(ROOT / "cuda"),
        str(ROOT / "cuda/c71_range_runtime.cpp"), str(ROOT / "tests/c71_source_tail_host.cpp"),
        "-o", str(binary)], check=True, timeout=30)
    for scenario in ("source", "kv", "kv_duplicate", "kv_upload", "kv_numeric", "kv_fence",
                     "capability", "unsupported", "granularity", "large_granularity",
                     "reserve", "create", "map", "access", "budget", "grow_create",
                     "grow_map", "grow_access", "grow_budget", "unmap", "release", "address_free",
                     *(["combined"] if pool else [])):
        environment = os.environ.copy()
        environment.pop("C71_OWNER_TRACE_A_FIRST", None)
        environment["C71_OWNER_TRACE_PATH"] = str(tmp_path / f"{scenario}.jsonl")
        result = subprocess.run([str(binary), scenario], env=environment,
                                capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, scenario + result.stdout + result.stderr
        marker, payload = result.stdout.strip().split(" ", 1)
        assert marker == "C71_SOURCE_TAIL_HOST"
        report = json.loads(payload)
        assert report["scenario"] == scenario and report["credit"] is False
        print(result.stdout.strip())
