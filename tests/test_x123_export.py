from __future__ import annotations

import json
import struct
import subprocess
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
PYTHON = REPO / ".venv" / "bin" / "python"
SCRIPT = REPO / "scripts" / "x123_export.py"
FIXTURES = REPO / "tests" / "fixtures" / "x123"


def run_exporter(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(PYTHON), str(SCRIPT), *args],
        cwd=REPO,
        check=True,
        text=True,
        capture_output=True,
    )


def test_toy_export_is_deterministic_and_checked_in(tmp_path: Path) -> None:
    checked = run_exporter("--check")
    assert "fixtures OK" in checked.stdout
    generated = tmp_path / "x123"
    run_exporter("--output-dir", str(generated))
    expected_names = {path.name for path in FIXTURES.iterdir() if path.is_file()}
    assert expected_names == {path.name for path in generated.iterdir() if path.is_file()}
    for name in expected_names:
        assert (generated / name).read_bytes() == (FIXTURES / name).read_bytes(), name


def test_d2_d4_calibration_and_x1_reference_self_tests() -> None:
    completed = run_exporter("--self-test")
    assert completed.stdout.strip() == "x123 exporter self-test OK"


def test_manifest_denies_real_gpt_oss_export_and_pins_both_source_kinds() -> None:
    manifest = json.loads((FIXTURES / "toy-moe-v1.manifest.json").read_text())
    assert manifest["real_gpt_oss_export"] is False
    assert {tensor["source_kind"] for tensor in manifest["tensors"]} == {"bf16", "mxfp4"}
    assert all(len(row["payload_sha256"]) == 64 for row in manifest["tensors"])


def test_x1_golden_header_and_crafted_tie_are_external_binary_data() -> None:
    blob = (FIXTURES / "x1-router-v1.golden.bin").read_bytes()
    assert blob[:16] == b"VOLTA-X1-GOLD-V1"
    assert struct.unpack_from("<9I", blob, 16) == (31, 4, 48, 32, 4, 8, 12, 6, 12)
    # The final 68 bytes are the independent crafted-tie D1 vector followed
    # by its 32 little-endian u16 comparison limbs.
    assert blob[-68:-64] == bytes([28, 29, 30, 31])
    assert blob[-64:] == bytes(64)


def test_x2_golden_header_pins_non_power_of_two_moe_shape() -> None:
    blob = (FIXTURES / "x2-moe-v1.golden.bin").read_bytes()
    assert blob[:16] == b"VOLTA-X2-GOLD-V1"
    assert struct.unpack_from("<11I", blob, 16) == (7, 2, 48, 80, 6, 2, 8, 8, 2, 97, 8)
