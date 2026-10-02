#!/usr/bin/env python3
"""Strict streaming validator for C71TRC01 calibration traces.

The parser validates framing, compiled source coverage, padding, histograms,
tokens, final KV and the terminal census.  Passing ``expected_frames`` also
performs an exact byte comparison with an independent producer.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct


MAGIC = b"C71TRC01"
HEADER = struct.Struct("<BBBBIQQQQQ")
METADATA, VALUES, HISTOGRAM, PADDING, TOKENS, FINAL_KV, FOOTER = 1, 2, 3, 4, 5, 6, 255
MAX_METADATA_BYTES = 4 * 1024**2
MAX_FRAME_BYTES = 64 * 1024**2
MAX_SOURCES = 10_000
MAX_TOTAL_ROWS = 100_000_000
U32_MAX = (1 << 32) - 1


def _read_exact(source, count: int, label: str) -> bytes:
    body = source.read(count)
    if len(body) != count:
        raise ValueError(f"calibration trace truncated in {label}")
    return body


def _json_no_duplicates(body: bytes) -> dict:
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError(f"calibration trace metadata duplicates {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("calibration trace metadata is not canonical JSON") from error
    if not isinstance(value, dict):
        raise ValueError("calibration trace metadata is not an object")
    return value


def _frame_tuple(frame: dict, payload: bytes):
    return (
        frame["kind"], frame["context"], frame["codec"], frame["source"],
        frame["first"], frame["rows"], frame["columns"], frame["repeat"], payload,
    )


def validate(path: Path, expected_frames=None) -> dict:
    """Validate one trace; optional expected frames make the comparison exact."""
    expected = iter(expected_frames) if expected_frames is not None else None
    sha256 = hashlib.sha256()
    contexts = []
    current = None
    final_kv = set()
    records = logical_words = stored_words = byte_count = 0

    with path.open("rb") as source:
        magic = _read_exact(source, len(MAGIC), "magic")
        sha256.update(magic)
        byte_count += len(magic)
        if magic != MAGIC:
            raise ValueError("calibration trace magic differs")

        while True:
            raw_header = _read_exact(source, HEADER.size, "frame header")
            sha256.update(raw_header)
            byte_count += HEADER.size
            kind, context, codec, flags, source_id, first, rows, columns, repeat, stored = (
                HEADER.unpack(raw_header)
            )
            frame = dict(kind=kind, context=context, codec=codec, source=source_id,
                         first=first, rows=rows, columns=columns, repeat=repeat)
            if flags:
                raise ValueError("calibration trace reserved flags are nonzero")

            if kind == FOOTER:
                if (context != 255 or codec != 1 or source_id != U32_MAX or stored != 32
                        or first != records or rows != logical_words or columns != stored_words
                        or repeat != byte_count - HEADER.size):
                    raise ValueError("calibration trace footer census differs")
                digest = _read_exact(source, 32, "footer digest")
                sha256.update(digest)
                byte_count += 32
                if source.read(1):
                    raise ValueError("calibration trace has bytes after footer")
                if current is not None or len(contexts) != 3:
                    raise ValueError("calibration trace contexts are incomplete")
                expected_kv = set(contexts[2]["metadata"]["kv_sources"])
                if final_kv != expected_kv:
                    raise ValueError("calibration trace final KV census differs")
                if expected is not None:
                    try:
                        next(expected)
                    except StopIteration:
                        pass
                    else:
                        raise ValueError("independent comparison has extra frames")
                return {
                    "format": MAGIC.decode(),
                    "bytes": byte_count,
                    "records": records,
                    "logical_words": logical_words,
                    "stored_words": stored_words,
                    "contexts": [{"old_tokens": row["metadata"]["old_tokens"],
                                  "sources": len(row["metadata"]["sources"])} for row in contexts],
                    "recipe_digest": contexts[0]["metadata"]["recipe_digest"],
                    "final_kv_sources": len(final_kv),
                    "blake3_before_footer": digest.hex(),
                    "sha256": sha256.hexdigest(),
                    "structural_validation_complete": True,
                    "exact_comparison_complete": expected is not None,
                }

            if not 1 <= codec <= 8:
                raise ValueError("calibration trace codec differs")
            payload_bytes = stored * codec
            if payload_bytes > MAX_FRAME_BYTES and kind != METADATA:
                raise ValueError("calibration trace frame exceeds parser bound")
            if kind == METADATA and payload_bytes > MAX_METADATA_BYTES:
                raise ValueError("calibration trace metadata exceeds parser bound")
            payload = _read_exact(source, payload_bytes, "frame payload")
            has_i16_minimum = codec == 2 and kind in (VALUES, PADDING, FINAL_KV) and any(
                value == -32768 for (value,) in struct.iter_unpack("<h", payload)
            )
            if has_i16_minimum and not (
                kind == VALUES and current is not None and source_id < len(current["metadata"]["sources"])
                and current["metadata"]["sources"][source_id]["name"] == "U/global/argmax_slack"
            ):
                raise ValueError("calibration trace contains the i16 overflow marker")
            sha256.update(payload)
            byte_count += payload_bytes
            records += 1
            stored_words += stored

            if kind == METADATA:
                if (current is not None or context != len(contexts) or context >= 3 or codec != 1
                        or source_id != U32_MAX or any((first, rows, columns, repeat))):
                    raise ValueError("calibration trace metadata order differs")
                metadata = _json_no_duplicates(payload)
                sources = metadata.get("sources")
                if (set(metadata) != {"schema", "old_tokens", "recipe_digest", "sources",
                                      "kv_sources", "padding_row_first",
                                      "padding_rows_per_block", "padding_repeat",
                                      "padding_row_stride", "tokens"}
                        or metadata.get("schema") != "volta-c71-calibration-trace-context-v1"
                        or metadata.get("old_tokens") != 150 * context
                        or not isinstance(sources, list) or not 0 < len(sources) <= MAX_SOURCES
                        or metadata.get("padding_row_first") != 150
                        or metadata.get("padding_rows_per_block") != 106
                        or metadata.get("padding_repeat") != 32
                        or metadata.get("padding_row_stride") != 256
                        or metadata.get("tokens") != 150):
                    raise ValueError("calibration trace metadata contract differs")
                try:
                    if (type(metadata["recipe_digest"]) is not str
                            or len(metadata["recipe_digest"]) != 64):
                        raise ValueError
                    bytes.fromhex(metadata["recipe_digest"])
                    if (any(type(row) is not dict
                            or set(row) != {"id", "name", "rows", "columns", "codec_bytes"}
                            or type(row["id"]) is not int
                            or type(row["name"]) is not str or not row["name"]
                            or type(row["rows"]) is not int
                            or type(row["columns"]) is not int
                            or type(row["codec_bytes"]) is not int for row in sources)
                            or [row["id"] for row in sources] != list(range(len(sources)))
                            or len({row["name"] for row in sources}) != len(sources)):
                        raise ValueError
                    shapes = [(row["rows"], row["columns"], row["codec_bytes"])
                              for row in sources]
                    kv_sources = metadata["kv_sources"]
                except (KeyError, TypeError, ValueError) as error:
                    raise ValueError("calibration trace source metadata differs") from error
                if (any(r <= 0 or c <= 0 or not 1 <= width <= 8 for r, c, width in shapes)
                        or sum(r for r, _, _ in shapes) > MAX_TOTAL_ROWS
                        or not isinstance(kv_sources, list)
                        or len(set(kv_sources)) != len(kv_sources)
                        or kv_sources != sorted(kv_sources)
                        or any(type(item) is not int or not 0 <= item < len(sources)
                               for item in kv_sources)):
                    raise ValueError("calibration trace source bounds differ")
                if contexts and (metadata["recipe_digest"] != contexts[0]["metadata"]["recipe_digest"]
                                 or sources != contexts[0]["metadata"]["sources"]
                                 or kv_sources != contexts[0]["metadata"]["kv_sources"]):
                    raise ValueError("calibration trace context metadata differs")
                current = {"metadata": metadata, "shapes": shapes,
                           "coverage": [bytearray(r) for r, _, _ in shapes]}
                contexts.append(current)
                continue

            if kind == FINAL_KV:
                if current is not None or len(contexts) != 3 or context != 2 or repeat != 1:
                    raise ValueError("calibration trace final KV order differs")
                metadata = contexts[2]["metadata"]
                shapes = contexts[2]["shapes"]
                if (source_id not in metadata["kv_sources"] or source_id in final_kv
                        or codec != 2 or first != 0 or rows != 450
                        or columns != shapes[source_id][1] or stored != rows * columns):
                    raise ValueError("calibration trace final KV shape/duplicate differs")
                final_kv.add(source_id)
                logical_words += rows * columns
            else:
                if current is None or context != len(contexts) - 1:
                    raise ValueError("calibration trace frame is outside its context")
                shapes = current["shapes"]
                coverage = current["coverage"]
                if kind == TOKENS:
                    if (source_id != U32_MAX or codec != 4 or first != 0 or rows != 1
                            or columns != 150 or repeat != 1 or stored != 150):
                        raise ValueError("calibration trace token frame differs")
                    if any(sum(row) != len(row) for row in coverage):
                        raise ValueError("calibration trace source coverage is incomplete")
                    if any(value >= 262144 for value in struct.unpack("<150I", payload)):
                        raise ValueError("calibration trace token is outside vocabulary")
                    logical_words += 150
                    current = None
                else:
                    if source_id >= len(shapes):
                        raise ValueError("calibration trace source id is outside metadata")
                    source_rows, source_columns, source_codec = shapes[source_id]
                    if columns != source_columns:
                        raise ValueError("calibration trace source columns differ")
                    if kind == VALUES:
                        if (codec != source_codec or repeat != 1 or rows == 0
                                or first + rows > source_rows or stored != rows * columns):
                            raise ValueError("calibration trace value frame shape differs")
                        touched = range(first, first + rows)
                    elif kind == HISTOGRAM:
                        if (codec != 4 or first != 0 or rows != 1 or source_rows != 1
                                or repeat != 1 or stored != columns):
                            raise ValueError("calibration trace histogram frame differs")
                        touched = range(1)
                    elif kind == PADDING:
                        if (codec != source_codec or first != 150 or rows != 106 or repeat != 32
                                or stored != 1 or source_rows < 32 * 256):
                            raise ValueError("calibration trace padding frame differs")
                        touched = (block * 256 + row for block in range(32)
                                   for row in range(150, 256))
                    else:
                        raise ValueError("calibration trace frame kind differs")
                    marked = coverage[source_id]
                    for row in touched:
                        if row >= len(marked) or marked[row]:
                            raise ValueError("calibration trace duplicates or misaddresses a row")
                        marked[row] = 1
                    logical_words += rows * columns * repeat

            if expected is not None:
                try:
                    wanted = next(expected)
                except StopIteration as error:
                    raise ValueError("independent comparison omits a trace frame") from error
                if _frame_tuple(frame, payload) != wanted:
                    raise ValueError("independent calibration value comparison differs")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    args = parser.parse_args()
    print(json.dumps(validate(args.trace), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
