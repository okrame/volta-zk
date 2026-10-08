"""Independent integer parity of the candidate; no CUDA execution or credit."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pcs_weight_tensor_fragments_and_original_polynomial(tmp_path):
    binary = tmp_path / "pcs-weight-tensor-host"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=undefined", "-fno-sanitize-recover=all", "-I", str(ROOT / "cuda"),
         str(ROOT / "tests/c71_pcs_weight_tensor_host.cpp"), "-o", str(binary)],
        check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=20)
    report = json.loads(result.stdout.removeprefix("C71_PCS_TENSOR_HOST "))
    print(result.stdout.strip())
    for key, value in {"digit_values": 65536, "digit_checks": 262144, "canonical_edges": 11,
                       "dot_cases": 28, "dot_outputs": 14336, "max_k": 256,
                       "pcs_cases": 8, "source_scans": 8, "w_loads": 5808,
                       "pcs_outputs": 720896, "shared_bytes": 8448, "rejections": 5,
                       "gpu_execution": False, "credit": False}.items():
        assert report[key] == value
    assert report["mma"] > 0 and report["high_loads"] > 0 and report["prefix_checks"] > 0
