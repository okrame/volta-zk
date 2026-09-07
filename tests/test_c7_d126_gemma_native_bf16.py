"""Small native/Python equality checks. All generated files stay in rust/target."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def native():
    rustc = shutil.which("rustc")
    if rustc is None:
        pytest.fail("rustup rustc is required for the Gemma native equality gate")
    target = ROOT / "rust" / "target"
    target.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gemma31b-bf16-", dir=target) as temporary:
        executable = Path(temporary) / "fixture"
        subprocess.run([
            rustc, "--edition", "2021", "-O",
            str(ROOT / "rust/volta-pcs/examples/gemma31b_bf16_fixture.rs"),
            "-o", str(executable),
        ], check=True, capture_output=True, timeout=60)
        yield executable


def reference():
    spec = importlib.util.spec_from_file_location("gemma_ingest_reference", ROOT / "scripts/c7_d126_gemma_weight_ingest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_tensor_packing_matches_python_across_bf16_ranges(native):
    ref = reference()
    for maximum in (0, 1, 3, 127, 128, 0x1080, 0x3080, 0x3f80, 0x46ff, 0x6080, 0x7f7f):
        # Include both signs and every magnitude up to this maximum.
        body = b"".join(bits.to_bytes(2, "little") for m in range(maximum + 1) for bits in (m, m | 0x8000))
        run = subprocess.run([native], input=body, capture_output=True, timeout=10, check=True)
        exponent = ref.minimum_weight_exponent(maximum)
        assert int.from_bytes(run.stdout[:4], "little", signed=True) == exponent
        assert int.from_bytes(run.stdout[4:6], "little") == maximum
        assert run.stdout[6:] == ref.convert_bf16le_chunk(body, exponent)


def test_native_fixture_rejects_invalid_or_oversized_before_output(native):
    for body in (b"", b"\x00", bytes.fromhex("803f807f"), bytes.fromhex("803fc17f"), b"\0" * 1_048_578):
        run = subprocess.run([native], input=body, capture_output=True, timeout=10)
        assert run.returncode != 0
        assert run.stdout == b""
