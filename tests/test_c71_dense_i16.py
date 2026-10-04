"""Exact integer decomposition and fragment layout, not CUDA execution."""
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cuda_parity_pointwise_inputs_pass_launcher_validation(tmp_path):
    source = (ROOT / "cuda/c71_nonlinear_parity.cu").read_text()
    operations = re.findall(r"c71_dense::Pointwise\{([^{}]+)\}", source)
    assert len(operations) == 2
    check = tmp_path / "parity-pointwise.cpp"
    check.write_text('#include "c71_dense_i16.cuh"\n#include <cassert>\n'
                     'int main() { for (const auto op : {'
                     + ','.join('c71_dense::Pointwise{' + op + '}' for op in operations)
                     + '}) assert(c71_dense::valid_pointwise(op)); }\n')
    binary = tmp_path / "parity-pointwise"
    subprocess.run(["g++", "-std=c++17", "-include", "initializer_list",
                    "-I", str(ROOT / "cuda"), str(check), "-o", str(binary)],
                   check=True, timeout=30)
    subprocess.run([str(binary)], check=True, timeout=5)


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
