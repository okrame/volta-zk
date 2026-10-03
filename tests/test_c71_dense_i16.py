"""Exact integer decomposition and fragment layout, not CUDA execution."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_dense_i16_fragment_model(tmp_path):
    binary = tmp_path / "dense-i16-host"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=undefined", "-fno-sanitize-recover=all",
         str(ROOT / "cuda/c71_dense_i16_host.cpp"), "-o", str(binary)],
        check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=20)
    report = json.loads(result.stdout.removeprefix("C71_DENSE_I16_HOST "))
    assert report == {"matrix_cases": 40, "pointwise_cases": 216, "split_values": 65535, "max_k_executed": 21504,
                      "gpu_execution": False, "credit": False}
