"""Fail-closed framing and exact-comparison checks for the private trace."""
from __future__ import annotations

import json
from pathlib import Path
import struct
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import c71_calibration_trace as trace


def _fixture(*, altered=False, omit=False, duplicate=False, bad_coordinate=False,
             metadata_mismatch=False, overflow_marker=False):
    body = bytearray(trace.MAGIC)
    expected = []
    records = logical = stored_total = 0

    def frame(kind, context, codec, source, first, rows, columns, repeat, payload,
              logical_count, compare=True):
        nonlocal records, logical, stored_total
        assert len(payload) % codec == 0
        stored = len(payload) // codec
        body.extend(trace.HEADER.pack(kind, context, codec, 0, source, first, rows,
                                      columns, repeat, stored))
        body.extend(payload)
        records += 1
        logical += logical_count
        stored_total += stored
        if compare:
            expected.append((kind, context, codec, source, first, rows, columns, repeat, payload))

    metadata_rows = []
    for context in range(3):
        metadata = json.dumps({
            "schema": "volta-c71-calibration-trace-context-v1",
            "old_tokens": 150 * context,
            "recipe_digest": "11" * 32,
            "sources": [
                {"id": 0, "name": "changed" if metadata_mismatch and context == 1 else "kv",
                 "rows": 1, "columns": 2, "codec_bytes": 2},
                {"id": 1, "name": "hist", "rows": 1, "columns": 3, "codec_bytes": 4},
                {"id": 2, "name": "padded", "rows": 8192, "columns": 1,
                 "codec_bytes": 2},
            ],
            "kv_sources": [0],
            "padding_row_first": 150,
            "padding_rows_per_block": 106,
            "padding_repeat": 32,
            "padding_row_stride": 256,
            "tokens": 150,
        }, separators=(",", ":")).encode()
        frame(trace.METADATA, context, 1, trace.U32_MAX, 0, 0, 0, 0, metadata, 0,
              compare=False)
        metadata_rows.append(metadata)

        value_payload = struct.pack("<hh", -32768 if overflow_marker and context == 1 else context + 1,
                                    -context - 1)
        if altered and context == 1:
            value_payload = struct.pack("<hh", 99, -context - 1)
        if not (omit and context == 1):
            frame(trace.VALUES, context, 2, 0, 0, 1, 2, 1, value_payload, 2)
        if duplicate and context == 1:
            frame(trace.VALUES, context, 2, 0, 0, 1, 2, 1, value_payload, 2)
        frame(trace.HISTOGRAM, context, 4, 1, 0, 1, 3, 1,
              struct.pack("<III", 1, 2, 3), 3)
        for block in range(32):
            frame(trace.VALUES, context, 2, 2, block * 256, 150, 1, 1,
                  struct.pack("<150h", *([context] * 150)), 150)
        frame(trace.PADDING, context, 2, 2, 151 if bad_coordinate and context == 1 else 150,
              106, 1, 32, struct.pack("<h", 0), 32 * 106)
        frame(trace.TOKENS, context, 4, trace.U32_MAX, 0, 1, 150, 1,
              struct.pack("<150I", *range(150)), 150)

    frame(trace.FINAL_KV, 2, 2, 0, 0, 450, 2, 1,
          struct.pack("<900h", *([7] * 900)), 900)
    before_footer = len(body)
    body.extend(trace.HEADER.pack(trace.FOOTER, 255, 1, 0, trace.U32_MAX, records,
                                  logical, stored_total, before_footer, 32))
    body.extend(b"\x22" * 32)
    return bytes(body), expected


def test_trace_structure_and_exact_frame_stream(tmp_path):
    body, expected = _fixture()
    path = tmp_path / "trace.bin"
    path.write_bytes(body)
    report = trace.validate(path, expected)
    assert report["structural_validation_complete"]
    assert report["exact_comparison_complete"]
    assert [row["old_tokens"] for row in report["contexts"]] == [0, 150, 300]
    assert report["final_kv_sources"] == 1


def test_trace_altered_value_needs_and_fails_independent_comparison(tmp_path):
    clean, expected = _fixture()
    changed, _ = _fixture(altered=True)
    path = tmp_path / "trace.bin"
    path.write_bytes(changed)
    assert trace.validate(path)["structural_validation_complete"]
    with pytest.raises(ValueError, match="value comparison"):
        trace.validate(path, expected)
    assert clean != changed


@pytest.mark.parametrize(
    ("options", "message"),
    [
        ({"omit": True}, "coverage is incomplete"),
        ({"duplicate": True}, "duplicates or misaddresses"),
        ({"bad_coordinate": True}, "padding frame differs"),
        ({"metadata_mismatch": True}, "context metadata differs"),
        ({"overflow_marker": True}, "i16 overflow marker"),
    ],
)
def test_trace_rejects_omission_duplicate_and_bad_coordinate(tmp_path, options, message):
    body, _ = _fixture(**options)
    path = tmp_path / "trace.bin"
    path.write_bytes(body)
    with pytest.raises(ValueError, match=message):
        trace.validate(path)


def test_trace_rejects_truncation(tmp_path):
    body, _ = _fixture()
    path = tmp_path / "trace.bin"
    path.write_bytes(body[:-1])
    with pytest.raises(ValueError, match="truncated"):
        trace.validate(path)
