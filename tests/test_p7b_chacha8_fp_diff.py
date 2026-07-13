import importlib.util
import json
import subprocess
from pathlib import Path

import pytest


def load_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "p7b_chacha8_fp_diff.py"
    spec = importlib.util.spec_from_file_location("p7b_chacha8_fp_diff", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # dataclasses consult sys.modules while resolving postponed annotations.
    import sys

    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def vector_payload(module, case, value="0x0000000000000001"):
    item = value if case.mode == "fp" else [value, value]
    return {
        "schema": module.VECTOR_SCHEMA,
        "mode": case.mode,
        "seed_hex": case.seed_hex,
        "base_domain": f"0x{case.base_domain:016x}",
        "rows": case.rows,
        "count": case.count,
        "values": [[item for _ in range(case.count)] for _ in range(case.rows)],
    }


def encoded(payload, *, compact=False):
    separators = (",", ":") if compact else None
    return (json.dumps(payload, separators=separators) + "\n").encode()


def test_compare_distinguishes_structural_from_byte_identity():
    module = load_module()
    case = module.CASES[0]
    payload = vector_payload(module, case)
    cuda = encoded(payload, compact=True)
    rust = encoded(payload, compact=False)

    comparison = module.compare_outputs(case, cuda, rust)

    assert comparison["structurally_identical"] is True
    assert comparison["byte_identical"] is False
    assert comparison["cuda"]["stdout_sha256"] != comparison["rust"]["stdout_sha256"]
    assert (
        comparison["cuda"]["canonical_json_sha256"]
        == comparison["rust"]["canonical_json_sha256"]
    )


def test_parser_rejects_noncanonical_field_value():
    module = load_module()
    case = module.CASES[1]
    payload = vector_payload(module, case, value="0xffffffff00000001")

    with pytest.raises(ValueError, match="canonical Goldilocks"):
        module.parse_vector_output(encoded(payload), case, "cuda")


def completed(command, returncode=0, stdout=b"", stderr=b""):
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def test_git_dirty_includes_untracked_and_failed_status():
    module = load_module()

    def untracked_run(command, **_kwargs):
        if command[1] == "rev-parse":
            return completed(command, stdout=b"a" * 40 + b"\n")
        return completed(command, stdout=b"?? new-file\0")

    metadata = module.git_metadata(untracked_run)
    assert metadata["git_dirty"] is True
    assert metadata["git_status_entries"] == 1

    def failed_run(command, **_kwargs):
        if command[1] == "rev-parse":
            return completed(command, stdout=b"b" * 40 + b"\n")
        return completed(command, returncode=128, stderr=b"status failed")

    failed = module.git_metadata(failed_run)
    assert failed["git_dirty"] is True
    assert failed["git_status_exit_code"] == 128


def test_exclusive_report_write_refuses_overwrite(tmp_path):
    module = load_module()
    path = tmp_path / "result.json"
    module.write_report_exclusive(path, {"schema": "first"})
    original = path.read_bytes()

    with pytest.raises(FileExistsError):
        module.write_report_exclusive(path, {"schema": "second"})

    assert path.read_bytes() == original


def test_nvidia_smi_parser_is_strict_and_handles_multiple_devices():
    module = load_module()
    stdout = (
        "0, NVIDIA A100-SXM4-80GB, GPU-aaa, 610.43.02, 81920\n"
        "1, NVIDIA A100-SXM4-80GB, GPU-bbb, 610.43.02, 81920\n"
    )
    devices = module.parse_nvidia_smi_rows(stdout)

    assert [device["index"] for device in devices] == [0, 1]
    assert devices[0]["memory_total_mib"] == 81920

    with pytest.raises(ValueError, match="expected 5"):
        module.parse_nvidia_smi_rows("0, A100, GPU-aaa\n")
