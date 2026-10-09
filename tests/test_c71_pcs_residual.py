"""Independent PCS basis/sourcewise parity. Host component, no CUDA credit."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pcs_sourcewise_residual_originals_and_msb_fold(tmp_path):
    binary = tmp_path / "pcs-residual-host"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I", str(ROOT / "cuda"),
         str(ROOT / "tests/c71_pcs_residual_host.cpp"), "-o", str(binary)],
        check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=20)
    lines = result.stdout.splitlines()
    timings = [json.loads(line.removeprefix("C71_PCS_RESIDUAL_BENCH "))
               for line in lines if line.startswith("C71_PCS_RESIDUAL_BENCH ")]
    assert {case["dimension"] for case in timings} == {15, 17}
    assert all(case["dense_fold_oracle_host_s"] > 0
               and case["checked_fixture_helper_phases_host_s"] > 0
               and case["other_oracle_checks_and_fixture_overhead_host_s"] > 0
               and case["original_scans"] == 4
               and case["named_heap_upper_bytes"] < 16 * 1024**2
               and case["stack_array_bytes"] == 12288
               and not case["gpu_execution"] and not case["integrated"] and not case["credit"]
               for case in timings)
    report = json.loads(lines[-1].removeprefix("C71_PCS_RESIDUAL_HOST "))
    print(result.stdout.strip())
    for key, expected in {"arithmetic_cases": 2304, "equality_cases": 432,
                          "phase_cases": 41, "original_scans": 161,
                          "singleton_outputs": 5248, "ood_outputs": 41,
                          "singleton_shared_bytes": 3072, "ood_shared_bytes": 6144,
                          "max_dimension": 35, "max_coset_log_rows": 23,
                          "PCS_basis_v3_v1": True, "gpu_execution": False,
                          "integrated": False, "credit": False}.items():
        assert report[key] == expected
    assert report["original_visits"] > report["input_word_loads"] > 0
    assert report["retained_outputs"] > 0 and report["coset_prefft_words"] > 0
    assert report["fold_outputs"] > 0 and report["codec_checks"] > 0
    assert report["rejections"] >= 40
    assert report["named_heap_upper_max_bytes"] < 16 * 1024**2
