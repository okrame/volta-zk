"""Original-index ownership; the deferred fake driver supplies no GPU math."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_index_owner_coverage_history_staging_and_retirement(tmp_path):
    binary = tmp_path / "rms-index-owner"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=undefined", "-fno-sanitize-recover=all",
         "-I", str(ROOT / "tests/cuda_stub"), "-I", str(ROOT / "cuda"),
         str(ROOT / "cuda/c71_range_runtime.cpp"), str(ROOT / "tests/c71_rms_index_host.cpp"),
         "-o", str(binary)], check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout.removeprefix("C71_RMS_INDEX_OWNER ")) == {
        "success": 2, "terminal_rejections": 32, "publication_after_free": True,
        "failed_fence_staging_retained": True, "gpu_execution": False, "credit": False,
    }
