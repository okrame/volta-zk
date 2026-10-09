"""Reduced independent signed-W loader fixture; no CUDA execution or credit."""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pcs_query_weight_direct_signed_packed_and_public_suffix(tmp_path):
    binary = tmp_path / "pcs-query-weight-host"
    shared_cuda = Path(os.environ.get("C71_PCS_SHARED_CUDA", ROOT / "cuda"))
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=undefined", "-fno-sanitize-recover=all",
         "-I", str(ROOT / "cuda"), "-I", str(shared_cuda),
         str(ROOT / "tests/c71_pcs_query_weight_host.cpp"), "-o", str(binary)],
        check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=20)
    print(result.stdout.strip())
    report = json.loads(result.stdout.removeprefix("C71_PCS_QUERY_WEIGHT_HOST "))
    assert report["column_cases"] == 992
    assert report["horner_checks"] == 4 * report["column_cases"]
    assert report["expected_W_reads"] == 328040
    assert report["loader_outputs"] > report["expected_W_reads"]
    assert report["pad_outputs"] > 0 and report["zero_outputs"] > 0
    assert report["loader_blocks"] > 0 and report["geometry_rejections"] == 25
    assert report["named_fixture_heap_upper_bytes"] < 4 * 1024**2
    assert report["host_component_s"] > 0
    assert report["max_low_payload_bytes"] == 2**20 * 8
    assert report["loader_extra_device_bytes"] == 0 and report["loader_shared_bytes"] == 0
    assert report["loader_launches_per_block"] == 1 and report["D35_sparse_geometry"]
    assert not report["gpu_execution"] and not report["integrated"] and not report["credit"]
