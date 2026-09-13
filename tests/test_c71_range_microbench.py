import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run_c71_range_microbench.py"


def load_runner():
    spec = importlib.util.spec_from_file_location("run_c71_range_microbench", RUNNER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_materialized_m25_buffers_fit_arena_exactly():
    runner = load_runner()
    assert runner.range_device_bytes(25) == 6_046_113_792
    assert runner.range_device_bytes(25) < runner.ARENA
    assert runner.gram_device_bytes(22, 8) == 1_223_688_192
    assert runner.gram_device_bytes(21, 16) == 1_012_924_416
    assert runner.gram_device_bytes(20, 32) == 909_901_824


def test_small_host_field_merge_coeff_fold_and_gram():
    compiler = shutil.which("g++")
    if compiler is None:
        pytest.skip("g++ is required for the host reference check")
    for width in (8, 16, 32):
        subprocess.run(
            [
                "python3", str(RUNNER), "--host-only", "--host-log2", "8",
                "--gram-width", str(width), "--timeout-seconds", "30", "--cxx", compiler,
            ],
            cwd=ROOT,
            check=True,
            stdout=subprocess.DEVNULL,
        )
