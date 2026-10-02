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


@pytest.mark.parametrize("outcome", ["exit", "timeout", "json", "array", "duplicate", "incomplete", "success"])
def test_trial_output_keeps_record_and_uses_frozen_candidate(tmp_path, monkeypatch, outcome):
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
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(command, 1, output=b"trial prefix", stderr=b"fixture timeout prefix")
        stdout = {
            "exit": "trial prefix",
            "json": '{"complete_integer_trial":',
            "array": "[]",
            "duplicate": '{"complete_integer_trial":false,"complete_integer_trial":true}',
            "incomplete": '{"complete_integer_trial":false}',
            "success": '{"complete_integer_trial":true}',
        }[outcome]
        return subprocess.CompletedProcess(command, int(outcome == "exit"), stdout=stdout, stderr="fixture overflow")

    monkeypatch.setattr(calibration.subprocess, "run", failed)
    monkeypatch.setattr(sys, "argv", ["c71_calibrate", "run", "--native", str(native),
                        "--candidate", str(candidate), "--output", str(output),
                        "--ingest-report", str(report), "--packed", str(tmp_path / "packed"),
                        "--payload-bytes", "100", "--timeout-seconds", "1"])
    if outcome == "success":
        calibration.main()
        code = 0
    else:
        with pytest.raises(SystemExit) as stopped:
            calibration.main()
        code = stopped.value.code
    result = json.loads(output.read_text())
    assert result["exit_code"] == code == (0 if outcome == "success" else 124 if outcome == "timeout" else 1)
    assert result["native_exit_code"] == (None if outcome == "timeout" else int(outcome == "exit"))
    if outcome != "success":
        assert result["stdout"]
        assert result["stderr"] == ("fixture timeout prefix" if outcome == "timeout" else "fixture overflow")
        assert result["failure"]
    assert result["candidate_sha256"] == hashlib.sha256(b"{}").hexdigest()
    assert result["complete_integer_trial"] is (outcome == "success")
    assert not result["calibrated"] and not result["credit"]
    with pytest.raises(FileExistsError):
        calibration.main()


@pytest.mark.parametrize("outcome", ["success", "failure", "race"])
def test_atomic_output_never_publishes_partial_or_replaces_existing(tmp_path, outcome):
    output = tmp_path / "report.json"
    body = b'{"calibrated":false}\n'
    if outcome == "success":
        with calibration.atomic_output(output) as sink:
            sink.write(body)
            assert not output.exists()
        assert output.read_bytes() == body
        with pytest.raises(FileExistsError):
            with calibration.atomic_output(output):
                pytest.fail("existing output opened for replacement")
    else:
        with pytest.raises(RuntimeError if outcome == "failure" else FileExistsError):
            with calibration.atomic_output(output) as sink:
                sink.write(b"incomplete")
                assert not output.exists()
                if outcome == "failure":
                    raise RuntimeError("report encoding failed")
                output.write_bytes(body)
        assert output.read_bytes() == body if outcome == "race" else not output.exists()
    assert list(tmp_path.iterdir()) == ([output] if outcome != "failure" else [])


@pytest.mark.parametrize("outcome", ["success", "timeout"])
def test_trace_mode_binds_native_and_independent_censuses(tmp_path, monkeypatch, outcome):
    candidate = tmp_path / "candidate.json"
    candidate.write_text("{}")
    report = tmp_path / "ingest.json"
    report.write_text('{"packed_sha256":"fixture"}')
    native = tmp_path / "native"
    native.write_bytes(b"fixture")
    packed = tmp_path / "packed"
    packed.write_bytes(b"fixture")
    output = tmp_path / "result.json"
    trace_output = tmp_path / "trace.bin"
    census = {
        "format": "C71TRC01", "bytes": 100, "records": 9, "logical_words": 20,
        "stored_words": 21, "final_kv_sources": 1,
        "blake3_before_footer": "11" * 32, "sha256": "22" * 32,
        "recipe_digest": "33" * 32,
        "structural_validation_complete": True, "exact_comparison_complete": False,
    }
    monkeypatch.setattr(calibration, "native_recipes", lambda *_args: {"recipe_digest": "33" * 32})
    monkeypatch.setattr(calibration, "validate_weights", lambda *_args: None)
    monkeypatch.setattr(calibration, "write_tables", lambda *_args: {"calibrated": False})
    staged = None

    def validate_trace(path):
        nonlocal staged
        staged = path
        assert path.parent.parent == tmp_path and path.name == "trace.bin"
        return census

    monkeypatch.setattr(calibration.trace_codec, "validate", validate_trace)

    def completed(command, **_kwargs):
        nonlocal staged
        assert command[1] == "run-trace" and Path(command[-1]).parent.parent == tmp_path
        staged = Path(command[-1])
        staged.write_bytes(b"private fixture")
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(command, 1, output=b"trace prefix")
        return subprocess.CompletedProcess(
            command, 0,
            stdout=json.dumps({"complete_integer_trial": True, "trace": census}),
            stderr="",
        )

    monkeypatch.setattr(calibration.subprocess, "run", completed)
    monkeypatch.setattr(sys, "argv", [
        "c71_calibrate", "trace", "--native", str(native), "--candidate", str(candidate),
        "--output", str(output), "--ingest-report", str(report), "--packed", str(packed),
        "--payload-bytes", "100", "--timeout-seconds", "1",
        "--trace-output", str(trace_output),
    ])
    if outcome == "success":
        calibration.main()
    else:
        with pytest.raises(SystemExit) as stopped:
            calibration.main()
        assert stopped.value.code == 124
    result = json.loads(output.read_text())
    assert staged is not None and not staged.exists()
    if outcome == "success":
        assert trace_output.read_bytes() == b"private fixture"
        assert trace_output.stat().st_mode & 0o777 == 0o600
        assert result["trace_validation"] == census
        assert result["trace_validation"]["structural_validation_complete"]
        assert not result["trace_validation"]["exact_comparison_complete"]
    else:
        assert not trace_output.exists()
        assert result["exit_code"] == 124 and not result["complete_integer_trial"]
