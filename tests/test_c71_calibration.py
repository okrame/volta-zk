"""Public input bridge and fail-closed provenance, without a full model replay."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import c71_calibrate as calibration


def test_certified_tables_match_native_input_and_scale_recipes(tmp_path):
    binary = os.environ.get("C71_CALIBRATION_BINARY")
    assert binary, "build c71_calibration and set C71_CALIBRATION_BINARY"

    def run(*args, check=True):
        return subprocess.run([binary, *map(str, args)], capture_output=True, text=True,
                              timeout=60, check=check)

    description = json.loads(run("describe").stdout)
    assert len(description["weight_sources"]) == 772
    assert len(description["activation_sources"]) == 1435
    candidate = {
        "weight_exponents_by_tensor": {source["name"]: 0 for source in description["weight_sources"]},
        "activation_exponents_by_source": {str(source["id"]): 0 for source in description["activation_sources"]},
    }
    candidate["activation_exponents_by_source"].update(description["fixed_pi_exponents"])
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(candidate))
    recipes = calibration.native_recipes(Path(binary), path)
    assert recipes["gelu"] == [[0, 0]] * 60
    assert recipes["exp30"] == [0] * 60
    assert len(recipes["rms"]) == 421
    tables = tmp_path / "tables.bin"
    report = calibration.write_tables(recipes, tables)
    assert report["table_bytes"] == tables.stat().st_size == 24_414_870
    body = tables.read_bytes()
    assert hashlib.sha256(body).hexdigest() == report["table_sha256"]
    assert struct.unpack_from("<h", body, 2 * (32767 + 1))[0] == 1
    exp_offset = 60 * 65535 * 2
    assert struct.unpack_from("<ii", body, exp_offset) == (1 << 30, 395007542)
    assert struct.unpack_from("<ii", body, len(body) - 64 * 8) == calibration.plan.gemma_rope_q30_coefficients("global", 449)[0]
    checked = json.loads(run("check-input", path, tables).stdout)
    assert checked["calibrated"] is False
    assert checked["complete_integer_trial"] is False
    assert len(checked["required_rows"]) == 3 and min(checked["required_rows"]) > 0
    assert checked["tables_numerically_certified_by_this_binary"] is False
    with pytest.raises(FileExistsError):
        calibration.write_tables(recipes, tables)
    empty = tmp_path / "empty"
    empty.touch()
    rejected = run("run", path, tables, empty, 512 * 1024**2, check=False)
    assert rejected.returncode and "packed W byte length differs" in rejected.stderr
    assert run("check-input", path, empty, check=False).returncode
    bad = copy.deepcopy(candidate)
    bad["activation_exponents_by_source"][next(iter(description["fixed_pi_exponents"]))] = 0
    path.write_text(json.dumps(bad))
    assert run("recipes", path, check=False).returncode
    print("C71_CALIBRATION_INPUT tables=24414870 offsets=0/150/300 calibrated=false full_model=false")


def test_candidate_ledger_uses_nonzero_rms_recipes_and_certified_tables(tmp_path):
    import c71_gkr_screen as gkr
    binary = os.environ.get("C71_CALIBRATION_BINARY")
    assert binary, "build c71_calibration and set C71_CALIBRATION_BINARY"
    description = json.loads(subprocess.run([binary, "describe"], capture_output=True, text=True,
                                            timeout=60, check=True).stdout)
    candidate = dict(
        weight_exponents_by_tensor={source["name"]: 0 for source in description["weight_sources"]},
        activation_exponents_by_source={str(source["id"]): 0 for source in description["activation_sources"]})
    candidate["activation_exponents_by_source"].update(description["fixed_pi_exponents"])
    first_norm = next(step for step in description["pilot"]["steps"] if step["operation"] == "norm")
    candidate["activation_exponents_by_source"][str(first_norm["output"])] = -1
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(candidate))
    output = tmp_path / "ledger.json"
    command = [sys.executable, str(Path(calibration.__file__)), "ledger", "--native", binary,
               "--candidate", str(path), "--output", str(output)]
    run = subprocess.run(command, capture_output=True, text=True, timeout=60, check=True)
    result = json.loads(run.stdout)
    assert result == json.loads(output.read_text())
    assert result["candidate_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["tables_generated_by_certified_reference"] and result["table_bytes"] == 24_414_870
    assert not result["calibrated"] and not result["full_model_execution"]
    assert not result["credit"] and not result["complete_work"] and not result["complete_physical_peak"]
    assert [context["old_tokens"] for context in result["contexts"]] == [0, 150, 300]
    assert result["three_attempt_reservation_base_rows"] == 3 * sum(
        context["required_rows_fp3"] for context in result["contexts"])
    for context in result["contexts"]:
        native = context["rms"]
        assert gkr.native_record(output, old=context["old_tokens"]) == native
        assert bytes(native["profile_digest"]).hex() == result["recipe_digest"]
        assert native["rms_parameters"][0] == [0, 0, -1]
        assert len(native["rms_parameters"]) == 421
        assert context["rms_structural_support"]["factored_arithmetic_after_structural_support_pruning"][
            "Fp3_mul"] != 377_460_232_230_821
        assert not context["rms_source_prover"]["complete_work"]
    with pytest.raises(ValueError, match="context missing"):
        gkr.native_record(output, old=450)
    native = copy.deepcopy(result["contexts"][0]["rms"])
    native["rms_parameters"] = native["rms_parameters"][:-1]
    with pytest.raises(ValueError, match="scale recipes"):
        gkr.canonical(native)
    native.pop("rms_parameters")
    with pytest.raises(AssertionError):
        gkr.canonical(native)
    before = output.read_bytes()
    assert subprocess.run(command, capture_output=True, timeout=60).returncode
    assert output.read_bytes() == before
    print("C71_CANDIDATE_LEDGER offsets=0/150/300 nonzero_rms=true calibrated=false full_model=false")


def test_weight_provenance_failure_precedes_large_file_access(tmp_path, monkeypatch):
    ingest = calibration.ingest
    candidate = {"weight_exponents_by_tensor": {"test": -14}}
    report = dict(model=ingest.MODEL, revision=ingest.REVISION,
                  metadata_sha256=ingest.METADATA_SHA256,
                  terminal_manifest_sha256=ingest.TERMINALS_SHA256,
                  status="PACKED_UNADMITTED", full_source_bodies_verified=True,
                  source_sha256={name: spec["lfs_sha256"] for name, spec in ingest.SHARDS.items()},
                  weight_exponents_by_tensor={"test": -14}, packed_bytes=ingest.PACKED_BYTES)
    absent = tmp_path / "absent"
    for key in ("revision", "source_sha256", "weight_exponents_by_tensor", "full_source_bodies_verified"):
        bad = {**report, key: None}
        with pytest.raises(ValueError, match="pinned weight ingest report"):
            calibration.validate_weights(bad, candidate, absent)
    small = tmp_path / "small"
    small.write_bytes(b"\0\0")
    with pytest.raises(ValueError, match="byte length"):
        calibration.validate_weights(report, candidate, small)
    monkeypatch.setattr(ingest, "PACKED_BYTES", 2)
    report["packed_bytes"] = 2
    report["packed_sha256"] = "00" * 32
    with pytest.raises(ValueError, match="hash differs"):
        calibration.validate_weights(report, candidate, small)


def test_failed_table_generation_never_publishes(tmp_path, monkeypatch):
    output = tmp_path / "tables.bin"

    def broken(_recipes):
        yield b"prefix"
        raise ArithmeticError("uncertified rounding boundary")

    monkeypatch.setattr(calibration, "table_chunks", broken)
    with pytest.raises(ArithmeticError, match="uncertified"):
        calibration.write_tables({}, output)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("deadline", [False, True])
def test_failed_trial_keeps_record_and_uses_frozen_candidate(tmp_path, monkeypatch, deadline):
    candidate = tmp_path / "candidate.json"
    candidate.write_text("{}")
    report = tmp_path / "ingest.json"
    report.write_text('{"packed_sha256":"fixture"}')
    native = tmp_path / "native"
    native.write_bytes(b"fixture")
    output = tmp_path / "result.json"
    monkeypatch.setattr(calibration, "native_recipes", lambda *_args: {})
    monkeypatch.setattr(calibration, "validate_weights", lambda *_args: None)
    monkeypatch.setattr(calibration, "write_tables", lambda *_args: {"calibrated": False})

    def failed(command, **_kwargs):
        candidate.write_text('{"changed":true}')
        assert Path(command[2]).read_text() == "{}"
        if deadline:
            raise subprocess.TimeoutExpired(command, 1)
        return subprocess.CompletedProcess(command, 1, stdout="", stderr="fixture overflow")

    monkeypatch.setattr(calibration.subprocess, "run", failed)
    monkeypatch.setattr(sys, "argv", ["c71_calibrate", "run", "--native", str(native),
                        "--candidate", str(candidate), "--output", str(output),
                        "--ingest-report", str(report), "--packed", str(tmp_path / "packed"),
                        "--payload-bytes", "100", "--timeout-seconds", "1"])
    with pytest.raises(SystemExit) as stopped:
        calibration.main()
    result = json.loads(output.read_text())
    assert result["exit_code"] == stopped.value.code == (124 if deadline else 1)
    assert result["candidate_sha256"] == hashlib.sha256(b"{}").hexdigest()
    assert not result["complete_integer_trial"] and not result["calibrated"]
    with pytest.raises(FileExistsError):
        calibration.main()
