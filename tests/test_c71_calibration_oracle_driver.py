"""Independent full-driver scheduling and operator glue on bounded inputs."""
from pathlib import Path
import struct
import sys

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import c71_calibration_oracle as numeric
import c71_calibration_oracle_driver as driver
import c71_calibration_trace as trace


def _files(tmp_path, monkeypatch):
    weights = [
        {"id": 0, "name": "embedding", "rows": 262144, "columns": 2, "packed_offset": 0},
        {"id": 1, "name": "matrix", "rows": 2, "columns": 2, "packed_offset": 524288},
        {"id": 2, "name": "norm", "rows": 1, "columns": 2, "packed_offset": 524292},
    ]
    packed = tmp_path / "packed.i16"
    with packed.open("wb") as sink:
        sink.write(np.array([1, 0], dtype="<i2").tobytes())
        sink.truncate(524294 * 2)
    with packed.open("r+b") as sink:
        sink.seek(524288 * 2)
        sink.write(np.array([1, 0, 0, 1, 1, 1], dtype="<i2").tobytes())
    monkeypatch.setattr(driver.ingest, "PACKED_BYTES", packed.stat().st_size)
    tables = tmp_path / "tables.bin"
    with tables.open("wb") as sink:
        sink.truncate(24_414_870)
    with tables.open("r+b") as sink:
        sink.seek(32767 * 2)
        sink.write(struct.pack("<h", 5))
        sink.seek(60 * driver.LOOKUP_ENTRIES * 2)
        sink.write(struct.pack("<i", 1 << 30))
        sink.seek(60 * driver.LOOKUP_ENTRIES * 2 + 60 * driver.LOOKUP_ENTRIES * 4 + 32767 * 2)
        sink.write(struct.pack("<h", 7))
    return weights, packed, tables


def test_driver_schedules_three_causal_contexts_and_completes_coverage(tmp_path, monkeypatch):
    weights, packed, tables = _files(tmp_path, monkeypatch)
    sources = [
        {"id": 0, "name": "embedding", "rows": 150, "columns": 2, "codec_bytes": 2},
        {"id": 1, "name": "decision", "rows": 50, "columns": 2, "codec_bytes": 6},
        {"id": 2, "name": "U/global/argmax_slack", "rows": 50, "columns": 2,
         "codec_bytes": 2},
    ]
    steps = [
        {"kind": "embedding", "inputs": [], "outputs": [0], "parameters": {"weight": 0}},
        {"kind": "matrix", "inputs": [0], "outputs": [1],
         "parameters": {"weight": 1, "input_row_offset": 99, "decision_only": True}},
        {"kind": "argmax", "inputs": [1], "outputs": [2],
         "parameters": {"token_offset": 100}},
    ]
    contexts = [dict(old_tokens=150 * slot, sources=sources, weights=weights, kv_sources=[],
                     steps=steps, decision_first=99, decision_count=50, tokens=150)
                for slot in range(3)]
    oracle = driver.Driver({"contexts": contexts}, packed, tables, prompt=[0] * 100)
    frames = list(oracle.frames())
    assert len(frames) == 3 * (150 + 50 + 50 + 1)
    token_frames = [frame for frame in frames if frame[0] == trace.TOKENS]
    assert len(token_frames) == 3
    assert all(struct.unpack("<150I", frame[-1]) == (0,) * 150 for frame in token_frames)
    assert oracle.report["complete"] and oracle.report["contexts"] == 3


def test_driver_operator_glue_matches_exact_primitives(tmp_path, monkeypatch):
    weights, packed, tables = _files(tmp_path, monkeypatch)
    oracle = driver.Driver({"contexts": [{"weights": weights}]}, packed, tables, prompt=[0] * 100)
    rows = {
        (10, 0): np.array([3, 4]),
        (20, 0): np.array([0, 0]),
        (30, 0): np.arange(32, dtype=np.int64) + 1,
        (40, 0): np.zeros(150, dtype=np.int64),
        (50, 0): np.array([16384] + [0] * 149),
    }
    rows.update({(50, head * 256): np.array([16384] + [0] * 149)
                 for head in range(32)})
    get = lambda source, row: rows[(source, row)]
    context = {"old_tokens": 0}

    values, _, _ = oracle._evaluate(
        context, {"kind": "matrix", "inputs": [10], "outputs": [11],
                  "parameters": {"weight": 1, "input_row_offset": 0,
                                 "decision_only": False}}, 0, 0, get)
    assert values[0][2].tolist() == [3, 4]

    values, _, _ = oracle._evaluate(
        context, {"kind": "norm", "inputs": [10], "outputs": [12, 13, 14],
                  "parameters": {"heads": 1, "columns": 2, "weight": 2,
                                 "recipe": [0, 0, 0]}}, 0, 0, get)
    expected = numeric.rms([3, 4], [1, 1], [0, 0, 0])
    assert values[0][2].tolist() == expected[1]
    assert values[1][2] == expected[0]
    assert values[2][2].tolist() == expected[2]

    assert oracle._evaluate(
        context, {"kind": "rne", "inputs": [10], "outputs": [11],
                  "parameters": {"shift": 1}}, 0, 0, get)[0][0][2].tolist() == [2, 2]
    assert oracle._evaluate(
        context, {"kind": "affine", "inputs": [10], "outputs": [11],
                  "parameters": {"coefficients": [2, 0]}}, 0, 0, get)[0][0][2].tolist() == [6, 8]
    gelu = oracle._evaluate(
        context, {"kind": "gelu", "inputs": [20], "outputs": [21, 22],
                  "parameters": {"table": 0, "histogram": 22}}, 0, 0, get)
    assert gelu[0][0][2].tolist() == [5, 5] and gelu[1][1].tolist() == [32767, 32767]
    rows[(20, 0)] = np.array([-32768, 0])
    with pytest.raises(ValueError, match="GELU lookup"):
        oracle._evaluate(
            context, {"kind": "gelu", "inputs": [20], "outputs": [21, 22],
                      "parameters": {"table": 0, "histogram": 22}}, 0, 0, get)
    rows[(20, 0)] = np.array([0, 0])
    rows[(21, 0)] = np.array([5, 5])
    assert oracle._evaluate(
        context, {"kind": "gate", "inputs": [21, 10], "outputs": [23], "parameters": {}},
        0, 0, get)[0][0][2].tolist() == [15, 20]
    rope = oracle._evaluate(
        context, {"kind": "rope", "inputs": [10], "outputs": [24],
                  "parameters": {"family": 0, "heads": 1, "width": 2, "position": 0}},
        0, 0, get)[0][0][2]
    assert rope == [3 << 30, 4 << 30]

    oracle.kv[31] = np.ones((450, 16), dtype=np.int16)
    qk = oracle._evaluate(
        context, {"kind": "qk", "inputs": [30, 31], "outputs": [32],
                  "parameters": {"groups": 16, "repeats": 2, "lanes": 1}},
        0, 0, get)[0][0][2]
    assert qk[0] == 1 and not np.any(qk[1:])
    softmax = oracle._evaluate(
        context, {"kind": "softmax", "inputs": [40], "outputs": [50, 41, 42, 43, 44, 45],
                  "parameters": {"table": 0, "maximum": 41, "difference": 42,
                                 "exponential": 43, "denominator": 44,
                                 "probability": 50, "histogram": 45}},
        0, 0, get)
    assert softmax[0][-1][2][0] == 16384 and softmax[1][1][0] == 0
    oracle.kv[51] = np.ones((450, 16), dtype=np.int16)
    pv = oracle._evaluate(
        context, {"kind": "pv", "inputs": [50, 51], "outputs": [52],
                  "parameters": {"groups": 16, "repeats": 2, "lanes": 1}},
        0, 0, get)[0][0][2]
    assert np.all(pv == 16384)
    softcap = oracle._evaluate(
        context, {"kind": "softcap", "inputs": [20], "outputs": [53, 54],
                  "parameters": {"table": 0, "lower": -32767, "histogram": 54}},
        0, 0, get)
    assert softcap[0][0][2].tolist() == [7, 7]
    rows[(53, 0)] = np.array([7, 7])
    argmax = oracle._evaluate(
        context, {"kind": "argmax", "inputs": [53], "outputs": [55],
                  "parameters": {"token_offset": 100}}, 0, 0, get)
    assert argmax[2] == 0 and argmax[0][0][2] == [-32768, -32768]
