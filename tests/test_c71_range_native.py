"""Native range arithmetic/geometry only; does not execute CUDA."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_native_range_host_algebra_and_bounded_groups(tmp_path):
    binary = tmp_path / "native-range-host"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         str(ROOT / "cuda/c71_range_native_host.cpp"), "-o", str(binary)],
        check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=10)
    report = json.loads(result.stdout.removeprefix("C71_NATIVE_RANGE_HOST "))
    assert report == {"cases": 37, "max_original_words": 2048,
                      "max_shared_payload_bytes": 52224, "gpu_execution": False, "credit": False}
