"""Finite exact attention fragment model; no CUDA execution or hardware credit."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_attention_mma_fragment_model(tmp_path):
    binary = tmp_path / "attention-mma-host"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I", str(ROOT / "cuda"),
         str(ROOT / "tests/c71_attention_mma_host.cpp"), "-o", str(binary)],
        check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=45)
    print(result.stdout, end="")
    lines = result.stdout.splitlines()
    cases = [json.loads(line.removeprefix("C71_ATTENTION_MMA_CASE "))
             for line in lines if line.startswith("C71_ATTENTION_MMA_CASE ")]
    report = json.loads(lines[-1].removeprefix("C71_ATTENTION_MMA_HOST "))
    assert len(cases) == 8
    assert {case["rows"] for case in cases} == {1, 15, 16, 17}
    assert {case["old"] for case in cases} == {0, 150, 300}
    assert {case["groups"] for case in cases} == {4, 8, 16}
    assert {case["lanes"] for case in cases} == {256, 512}
    assert all(case["naive_i128_seconds"] >= 0 and case["fragment_model_seconds"] >= 0 for case in cases)
    assert report["qk_head_cases"] == 41 and report["pv_head_cases"] == 60
    assert report["rejections"] == 6 and report["max_keys"] == 450 and report["max_lanes"] == 512
    assert report["canary_reads"] == 0 and report["output_coverage_exact"]
    assert report["host_named_capacity_bytes"] < 16 * 1024 * 1024
    assert report["max_observed_int8_accumulator"] <= 512 * 128 * 128
    assert report["mma_named_register_integer_bytes_per_thread"] == 124
    assert report["mma_shared_bytes"] == 0 and report["new_global_staging_bytes"] == 0
    assert report["gpu_execution"] is False and report["credit"] is False
