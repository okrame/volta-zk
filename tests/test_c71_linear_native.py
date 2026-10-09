"""Dense independent original products against the bounded GPU helper algebra."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_original_linear_coefficients_against_dense_folded_products(tmp_path):
    binary = tmp_path / "linear-native-host"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I", str(ROOT / "cuda"),
         str(ROOT / "tests/c71_linear_native_host.cpp"), "-o", str(binary)],
        check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=20)
    lines = result.stdout.splitlines()
    timings = [json.loads(line.removeprefix("C71_LINEAR_NATIVE_BENCH "))
               for line in lines if line.startswith("C71_LINEAR_NATIVE_BENCH ")]
    assert {case["dimension"] for case in timings} == {15, 17}
    assert all(case["dense_oracle_host_s"] > 0 and case["helper_prepare_and_scan_host_s"] > 0
               and not case["gpu_execution"] and not case["credit"] for case in timings)
    report = json.loads(lines[-1].removeprefix("C71_LINEAR_NATIVE_HOST "))
    print(result.stdout.strip())
    assert report["cases"] == 167
    assert report["original_visits"] > 0
    assert report["shared_bytes"] == 30720 and report["max_dimension"] == 35
    assert report["rejections"] == 16 and report["MAC_basis_u3_2"]
    assert not report["gpu_execution"] and not report["credit"]
