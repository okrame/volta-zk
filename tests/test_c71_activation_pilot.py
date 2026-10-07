import copy
from concurrent.futures import ThreadPoolExecutor
from fractions import Fraction
import hashlib
import io
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import time

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import c71_activation_pilot as pilot


def small_inputs():
    descriptors = [
        dict(id=0, name="embedding/head", rows=2, columns=2, packed_offset=0),
        dict(id=1, name="norm", rows=1, columns=2, packed_offset=4),
        dict(id=2, name="projection", rows=2, columns=2, packed_offset=6),
    ]
    body = np.array([1, 2, 2, 1, 1, 2, 1, 0, 0, 1], dtype="<i2").tobytes()
    weights = pilot.PackedWeights(io.BytesIO(body), descriptors, {source["name"]: 0 for source in descriptors})
    steps = []

    def add(operation, inputs, output, **parameters):
        steps.append(dict(operation=operation, inputs=inputs, output=output, parameters=parameters))

    add("embedding", [], 0, weight=0)
    add("affine", [0], 1, scale=[147, -1])
    add("norm", [1], 2, heads=1, columns=2, weight=1)
    add("matrix", [2], 3, weight=2)
    add("norm", [3], 4, heads=1, columns=2, weight=None)
    add("rope", [4], 5, heads=1, width=2, family=0)
    add("qk", [5, 5], 6, groups=1, repeats=1, lanes=2)
    add("softmax", [6], 7)
    add("pv", [7, 4], 8, groups=1, repeats=1, lanes=2)
    add("gelu", [8], 9)
    add("gate", [9, 2], 10)
    add("affine", [10, 1], 11, scale=None)
    add("matrix", [11], 12, weight=0, decision_only=True)
    add("softcap", [12], 13, decision_only=True)
    add("argmax", [13], None, decision_only=True)
    description = dict(weight_sources=descriptors,
                       activation_sources=[dict(id=index, columns=2) for index in range(14)],
                       fixed_pi_exponents={"7": -14},
                       pilot=dict(steps=steps, kv_sources=[4, 5], decision_first=0,
                                  decision_count=1, tokens_per_response=2, responses=3))
    return description, weights


def test_exact_scale_selection_at_rounding_boundaries():
    values = [0.0, 1.0, math.nextafter(32767.5, 0), 32767.5,
              math.nextafter(32767.5, math.inf), 2.0**-128, 2.0**128]
    for value in values:
        exponent = pilot.exponent_for_maximum(value)
        assert abs(round(Fraction(value) / Fraction(2)**exponent)) <= 32767
        if value:
            assert round(Fraction(value) / Fraction(2)**(exponent - 1)) > 32767
    assert pilot.exponent_for_maximum(32767.5) == 1
    for value in (-1, math.inf, math.nan):
        with pytest.raises(ValueError):
            pilot.exponent_for_maximum(value)


def test_complete_small_pilot_retains_causal_kv_and_absorbs_final_token():
    description, weights = small_inputs()
    runner = pilot.Pilot(description, weights, time.monotonic() + 10)
    candidate, result = runner.run([0])
    assert len(result["responses"]) == 3 and all(len(tokens) == 2 for tokens in result["responses"])
    assert all(tokens[0] == 0 for tokens in result["responses"])
    assert len(runner.history[4]) == len(runner.history[5]) == 6
    assert not runner.current
    assert result["history_payload_bytes"] == 6 * 2 * 2 * 8
    assert result["matrix_scalar_products"] == (6 + 3) * 4
    planned = pilot.work_plan(description)
    assert result["matrix_scalar_products"] == planned["matrix_scalar_products"]
    assert result["weight_read_bytes"] == planned["logical_weight_read_bytes"]
    assert result["history_payload_bytes"] == planned["final_f64_kv_payload_bytes"]
    assert set(result["extents"]) == set(range(14))
    assert result["extents"][0]["words"] == 12
    assert result["extents"][12]["words"] == 6
    assert result["extents"][7]["words"] == sum(range(1, 7))
    assert candidate["activation_exponents_by_source"]["0"] == 0
    assert candidate["activation_exponents_by_source"]["7"] == -14
    assert not result["calibrated"] and result["integer_replay_required"]
    before = weights.bytes_read
    with pytest.raises(ValueError, match="already used"):
        runner.run([0])
    assert weights.bytes_read == before
    repeated = pilot.Pilot(description, small_inputs()[1], time.monotonic() + 10).run([0])
    assert repeated[0] == candidate and repeated[1]["responses"] == result["responses"]


def test_parallel_matrix_blocks_and_causal_pilot_match_serial_exactly(tmp_path):
    descriptor = dict(id=0, name="ragged", rows=257, columns=129, packed_offset=0)
    body = np.random.default_rng(71).integers(-32767, 32768, (257, 129), dtype=np.int16).tobytes()
    matrix_description = dict(weight_sources=[descriptor], pilot=dict(steps=[], kv_sources=[]))
    step = dict(operation="matrix", inputs=[1], parameters=dict(weight=0))
    def evaluate(pool, source=None):
        weights = pilot.PackedWeights(source if source is not None else io.BytesIO(body),
                                     [descriptor], {"ragged": -13})
        runner = pilot.Pilot(matrix_description, weights, time.monotonic() + 10, pool)
        runner.current[1] = np.arange(129, dtype=np.float64) / 16
        return runner.evaluate(step, 0, 0), runner.matrix_scalar_products, weights.bytes_read
    serial = evaluate(None)
    description, weights = small_inputs()
    serial_trial = pilot.Pilot(description, weights, time.monotonic() + 10).run([0])
    packed = tmp_path / "readonly.i16"
    packed.write_bytes(body)
    with packed.open("rb") as source:
        mapped_serial = evaluate(None, source)
    with ThreadPoolExecutor(max_workers=2) as pool:
        parallel = evaluate(pool)
        with packed.open("rb") as source:
            mapped_parallel = evaluate(pool, source)
        parallel_trial = pilot.Pilot(description, small_inputs()[1], time.monotonic() + 10, pool).run([0])
    assert parallel[0].tobytes() == serial[0].tobytes()
    assert parallel[1:] == serial[1:] == (257 * 129, len(body))
    for mapped in (mapped_serial, mapped_parallel):
        assert mapped[0].tobytes() == serial[0].tobytes() and mapped[1:] == serial[1:]
    assert packed.read_bytes() == body
    assert parallel_trial == serial_trial


def test_operator_routes_weighted_rms_groups_and_global_rope():
    description, weights = small_inputs()
    runner = pilot.Pilot(description, weights, time.monotonic() + 10)
    runner.current[1] = np.array([3.0, 4.0])
    norm = description["pilot"]["steps"][2]
    actual = runner.evaluate(norm, 0, 0)
    np.testing.assert_allclose(actual, np.array([3.0, 8.0]) / math.sqrt(12.5 + 1e-6))
    groups, repeats, lanes = 2, 2, 3
    queries = np.arange(groups * repeats * lanes, dtype=np.float64)
    keys = np.arange(2 * groups * lanes, dtype=np.float64).reshape(2, groups * lanes)
    runner.current.update({100: queries, 101: keys[-1]})
    runner.history[101] = list(keys)
    step = dict(operation="qk", inputs=[100, 101], parameters=dict(groups=groups, repeats=repeats, lanes=lanes))
    scores = runner.evaluate(step, 0, 1)
    expected = [[sum(queries[head * lanes + lane] * keys[token, (head // repeats) * lanes + lane]
                     for lane in range(lanes)) for token in range(2)] for head in range(4)]
    np.testing.assert_array_equal(scores, expected)
    step["operation"] = "pv"
    runner.current[100] = np.array([[1., 0.], [0., 1.], [.5, .5], [1., 0.]])
    expected = [[sum(runner.current[100][head, token] * keys[token, (head // repeats) * lanes + lane]
                     for token in range(2)) for lane in range(lanes)] for head in range(4)]
    np.testing.assert_array_equal(runner.evaluate(step, 0, 1), np.array(expected).ravel())
    runner.history[101].append(keys[0])
    with pytest.raises(ValueError, match="causal prefix"):
        runner.evaluate(step, 0, 1)
    runner.current[200] = np.arange(512, dtype=np.float64)
    rope = dict(operation="rope", inputs=[200], parameters=dict(family=1, heads=1, width=512))
    rotated = runner.evaluate(rope, 0, 449)
    np.testing.assert_array_equal(rotated[64:256], runner.current[200][64:256])
    np.testing.assert_array_equal(rotated[320:], runner.current[200][320:])
    cosine, sine = pilot.calibration.plan.gemma_rope_q30_coefficients("global", 449)[0]
    assert rotated[0] == -256 * sine / 2**30
    assert rotated[256] == 256 * cosine / 2**30
    np.testing.assert_array_equal(runner.evaluate(rope, 0, 0), runner.current[200])


def test_pilot_rejects_invalid_weights_nonfinite_values_and_expired_trial():
    description, weights = small_inputs()
    with pytest.raises(ValueError, match="outside tensor"):
        weights.block(0, 2, 1)
    weights.source.getbuffer()[:2] = b"\x00\x80"
    with pytest.raises(ValueError, match="symmetric i16"):
        weights.block(0, 0, 1)
    weights.source.truncate(4)
    with pytest.raises(ValueError, match="truncated"):
        weights.block(2, 0, 2)
    runner = pilot.Pilot(description, small_inputs()[1], time.monotonic() - 1)
    with pytest.raises(TimeoutError):
        runner.run([0])
    assert runner.weights.bytes_read == 0
    altered = copy.deepcopy(description)
    altered["pilot"]["steps"][1]["parameters"]["scale"] = [math.inf, 0]
    runner = pilot.Pilot(altered, small_inputs()[1], time.monotonic() + 10)
    with pytest.raises(ValueError, match="nonfinite"):
        runner.run([0])


def test_native_pilot_export_covers_all_semantic_sources_and_pre_norm_aliases():
    native = os.environ.get("C71_CALIBRATION_BINARY")
    assert native, "build c71_calibration and set C71_CALIBRATION_BINARY"
    result = subprocess.run([native, "describe"], capture_output=True, text=True, timeout=60, check=True)
    description = json.loads(result.stdout)
    graph = description["pilot"]
    assert len(graph["steps"]) == 1436
    available = set()
    for step in graph["steps"]:
        assert set(step["inputs"]) <= available
        if step["output"] is not None:
            assert step["output"] not in available
            available.add(step["output"])
    assert available == {source["id"] for source in description["activation_sources"]}
    assert (graph["decision_first"], graph["decision_count"], graph["tokens_per_response"]) == (99, 50, 150)
    outputs = {step["output"]: step for step in graph["steps"] if step["output"] is not None}
    for step in graph["steps"]:
        if step["operation"] == "qk" and step["parameters"]["lanes"] == 512:
            key_norm = outputs[outputs[step["inputs"][1]]["inputs"][0]]
            value_norms = [node for node in graph["steps"] if node["operation"] == "norm"
                           and node["parameters"]["weight"] is None
                           and node["inputs"] == key_norm["inputs"]]
            assert len(value_norms) == 1
    assert sum(step["operation"] == "matrix" for step in graph["steps"]) == 411
    assert sum(step["operation"] == "norm" for step in graph["steps"]) == 421
    planned = pilot.work_plan(description)
    assert planned["final_f64_kv_payload_bytes"] == 4 * 405_504_000
    assert planned["weight_block_i16_plus_f64_payload_bytes"] == 10 * 128 * 21504
    expected = 450 * (61_394_690_560 - 2_818_572_288) + 150 * 2_818_572_288 + 450 * 5376 * 2
    assert planned["logical_weight_read_bytes"] == expected
    print("C71_ACTIVATION_PILOT semantic_sources=1435 producer_steps=1436 calibrated=false full_model=false")


@pytest.mark.parametrize("failure", [None, "timeout", "compiler"])
def test_pilot_cli_preserves_provenance_and_never_overwrites(tmp_path, monkeypatch, failure):
    description, weights = small_inputs()
    native = tmp_path / "native"
    native.write_bytes(b"fixture")
    packed = tmp_path / "packed"
    packed.write_bytes(weights.source.getvalue())
    ingest = tmp_path / "ingest.json"
    ingest.write_text(json.dumps(dict(weight_exponents_by_tensor=weights.exponents,
                                     packed_sha256=hashlib.sha256(packed.read_bytes()).hexdigest())))
    (tmp_path / "manifests").mkdir()
    workload = tmp_path / "manifests/c7-d126-gemma31b-workload-v1.json"
    workload.write_text('{ "prompt": {"token_ids": [0]} }\n')
    monkeypatch.setattr(pilot.calibration.ingest, "ROOT", tmp_path)
    monkeypatch.setattr(pilot.calibration, "validate_weights", lambda *_args: None)

    def native_command(command, **_kwargs):
        if command[1] == "describe":
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(description))
        assert command[1] == "recipes"
        assert json.loads(Path(command[2]).read_text())["weight_exponents_by_tensor"] == weights.exponents
        return subprocess.CompletedProcess(command, int(failure == "compiler"), stderr="fixture")

    monkeypatch.setattr(pilot.subprocess, "run", native_command)
    if failure == "timeout":
        def expired(_self):
            raise TimeoutError("fixture timeout")
        monkeypatch.setattr(pilot.Pilot, "check_deadline", expired)
    output = tmp_path / "result"
    monkeypatch.setattr(sys, "argv", ["c71_activation_pilot", "run", "--native", str(native),
                        "--ingest-report", str(ingest), "--packed", str(packed),
                        "--output", str(output), "--timeout-seconds", "1"])
    if failure:
        with pytest.raises(TimeoutError if failure == "timeout" else ValueError):
            pilot.main()
    else:
        pilot.main()
    result = json.loads((output / "report.json").read_text())
    assert result["success"] == (failure is None)
    assert result["complete"] == (failure != "timeout")
    assert not result["calibrated"] and not result["credit"]
    assert result["workload_sha256"] == hashlib.sha256(workload.read_bytes()).hexdigest()
    assert result["ingest_report_sha256"] == hashlib.sha256(ingest.read_bytes()).hexdigest()
    assert result["packed_hash_checked"]
    progress = output / "progress.jsonl"
    events = [json.loads(line) for line in progress.read_text().splitlines()]
    assert events and events[-1]["state"] == ("complete" if failure is None else "failed")
    assert progress.stat().st_mode & 0o777 == 0o600
    assert (output / "report.json").stat().st_mode & 0o777 == 0o600
    assert events[-1]["completed_tokens"] == (0 if failure == "timeout" else 6)
    assert events[-1]["context"] == (0 if failure == "timeout" else 4)
    assert all(not {"extents", "responses", "minimum", "maximum", "values"} & event.keys()
               for event in events)
    assert result["progress"]["weight_read_bytes"] == events[-1]["weight_read_bytes"]
    if failure != "timeout":
        timings = result["operator_timings"]
        assert timings["3"]["calls"] == 6 and timings["12"]["calls"] == 3
        assert all(row["wall_seconds"] >= 0 and row["failures"] == 0 for row in timings.values())
    candidate = output / "candidate.json"
    assert candidate.exists() == (failure != "timeout")
    if candidate.exists():
        assert result["candidate_sha256"] == hashlib.sha256(candidate.read_bytes()).hexdigest()
        assert result["candidate_compiles"] == (failure is None)
    before = (output / "report.json").read_bytes()
    with pytest.raises(FileExistsError):
        pilot.main()
    assert (output / "report.json").read_bytes() == before


def test_progress_preserves_partial_operator_failure(tmp_path):
    description, weights = small_inputs()
    description["pilot"]["steps"][3]["parameters"]["weight"] = 99
    with (tmp_path / "progress.jsonl").open("x") as sink:
        runner = pilot.Pilot(description, weights, time.monotonic() + 10, progress=sink)
        with pytest.raises(IndexError):
            runner.run([0])
        runner.emit_progress("failed", force=True)
    events = [json.loads(line) for line in (tmp_path / "progress.jsonl").read_text().splitlines()]
    assert events[-1]["step_index"] == 3 and events[-1]["operation"] == "matrix"
    assert events[-1]["completed_tokens"] == 0 and events[-1]["weight_read_bytes"] > 0
    assert runner.operator_timings["3"]["failures"] == 1
    assert runner.operator_timings["2"]["calls"] == 1
