#!/usr/bin/env python3
"""Acquire pinned Gemma-31B metadata without downloading complete weight shards."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import math
import os
import re
import struct
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Callable


MODEL = "google/gemma-4-31B"
REVISION = "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89"
SCHEMA = "volta-c7-d126-gemma31b-source-metadata-v1"
SCALAR_SCHEMA = "volta-c7-d126-gemma31b-layer-scalars-v1"
BASE_URL = f"https://huggingface.co/{MODEL}/resolve/{REVISION}"
USER_AGENT = "volta-zk-c7-d126-metadata/1"

SMALL_ARTIFACTS = {
    "config.json": {
        "bytes": 4_181,
        "sha256": "6a81841cad2b6ba06841e23c6afb5f0a27827bc12c64328ffa6338831a21267e",
    },
    "model.safetensors.index.json": {
        "bytes": 120_246,
        "sha256": "d4aff3b976d69c123a29d1c085d7ba4de1ac3f4ca1726a7f81e1b11462a64ea2",
    },
    "tokenizer.json": {
        "bytes": 32_170_070,
        "sha256": "12bac982b793c44b03d52a250a9f0d0b666813da566b910c24a6da0695fd11e6",
    },
}

SHARDS = {
    "model-00001-of-00002.safetensors": {
        "bytes": 49_784_788_364,
        "lfs_sha256": "186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac",
        "xet_hash": "0a57a19d7f8430e9bd73af466cca6032f13677bcee640d0a26234eeff1923473",
        "header_bytes": 136_896,
        "header_sha256": "a58b10bc7e2ec1c7d062896e71f69466c8981440cab7a045510fb997e4b91bc9",
    },
    "model-00002-of-00002.safetensors": {
        "bytes": 12_761_549_884,
        "lfs_sha256": "b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0",
        "xet_hash": "2324e95577e5d990387e6343d68f71675d1885fdba16e94c5d68fbd0b0a68e40",
        "header_bytes": 23_584,
        "header_sha256": "2b82d9b263de66d77efdc15b56743d5d3b1cfb1ee4587acdd836c54c7eadfb42",
    },
}

EXPECTED = {
    "physical_tensors": 1_188,
    "private_text_tensors": 772,
    "public_layer_scalars": 60,
    "forbidden_vision_bridge_tensors": 356,
    "payload_bytes": 62_546_177_752,
    "framing_bytes": 160_496,
    "private_text_scalars": 30_697_345_280,
    "forbidden_vision_bridge_scalars": 575_743_536,
    "ordered_public_layer_scalar_bytes_sha256": (
        "4d4ddd2f27faee67f141f83903c02bc93864a92402fd2cb9896da2628e6dbb70"
    ),
}

CONTENT_RANGE_RE = re.compile(r"bytes ([0-9]+)-([0-9]+)/([0-9]+)\Z")


class MetadataError(ValueError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _exact_keys(value: dict, keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise MetadataError(f"{label} fields differ: {sorted(set(value) ^ keys)}")


def _read_exact(response, expected: int) -> bytes:
    body = response.read(expected + 1)
    if len(body) != expected:
        raise MetadataError(f"HTTP body has {len(body)} bytes, expected {expected}")
    return body


def _download_small(name: str, local: Path | None, timeout: float) -> bytes:
    expected = SMALL_ARTIFACTS[name]
    if local is not None:
        body = local.read_bytes()
    else:
        request = urllib.request.Request(
            f"{BASE_URL}/{name}", headers={"User-Agent": USER_AGENT}
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                raise MetadataError(f"{name}: expected HTTP 200, got {response.status}")
            body = _read_exact(response, expected["bytes"])
    if len(body) != expected["bytes"] or sha256(body) != expected["sha256"]:
        raise MetadataError(f"{name}: pinned size or SHA-256 differs")
    return body


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


def _strip_etag(value: str | None) -> str:
    if value is None:
        return ""
    value = value.removeprefix("W/")
    return value.strip('"')


def _resolve_shard(name: str, timeout: float) -> str:
    spec = SHARDS[name]
    request = urllib.request.Request(
        f"{BASE_URL}/{name}",
        headers={"Range": "bytes=0-7", "User-Agent": USER_AGENT},
    )
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        if error.code not in (301, 302, 303, 307, 308):
            raise MetadataError(f"{name}: resolve failed with HTTP {error.code}") from error
        headers = error.headers
    else:
        raise MetadataError(f"{name}: resolver did not return a pinned redirect")

    checks = {
        "X-Repo-Commit": REVISION,
        "X-Linked-Size": str(spec["bytes"]),
        "X-Xet-Hash": spec["xet_hash"],
        "Accept-Ranges": "bytes",
    }
    for field, expected in checks.items():
        if headers.get(field) != expected:
            raise MetadataError(f"{name}: resolver {field} differs")
    if _strip_etag(headers.get("X-Linked-ETag")) != spec["lfs_sha256"]:
        raise MetadataError(f"{name}: resolver LFS SHA-256 differs")

    location = headers.get("Location")
    parsed = urllib.parse.urlsplit(location or "")
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not (
        host == "huggingface.co"
        or host.endswith(".huggingface.co")
        or host.endswith(".hf.co")
    ):
        raise MetadataError(f"{name}: resolver returned an unexpected HTTPS host")
    return location


def _range_reader(name: str, location: str, timeout: float) -> Callable[[int, int], bytes]:
    spec = SHARDS[name]

    def read(start: int, end_exclusive: int) -> bytes:
        if not 0 <= start < end_exclusive <= spec["bytes"]:
            raise MetadataError(f"{name}: invalid requested range")
        end = end_exclusive - 1
        request = urllib.request.Request(
            location,
            headers={"Range": f"bytes={start}-{end}", "User-Agent": USER_AGENT},
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 206:
                raise MetadataError(f"{name}: expected HTTP 206, got {response.status}")
            match = CONTENT_RANGE_RE.fullmatch(response.headers.get("Content-Range", ""))
            got_range = tuple(map(int, match.groups())) if match else None
            if got_range != (start, end, spec["bytes"]):
                raise MetadataError(f"{name}: Content-Range differs")
            if _strip_etag(response.headers.get("ETag")) != spec["xet_hash"]:
                raise MetadataError(f"{name}: response Xet ETag differs")
            return _read_exact(response, end_exclusive - start)

    return read


def _decode_header(name: str, read_range: Callable[[int, int], bytes]) -> tuple[bytes, dict]:
    spec = SHARDS[name]
    prefix = read_range(0, 8)
    header_bytes = int.from_bytes(prefix, "little")
    if header_bytes != spec["header_bytes"]:
        raise MetadataError(f"{name}: safetensors header length differs")
    raw = read_range(8, 8 + header_bytes)
    if sha256(raw) != spec["header_sha256"]:
        raise MetadataError(f"{name}: safetensors header SHA-256 differs")
    try:
        header = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MetadataError(f"{name}: invalid safetensors JSON header") from error
    if header.pop("__metadata__", None) != {"format": "pt"}:
        raise MetadataError(f"{name}: safetensors metadata differs")
    return raw, header


def _element_count(shape: list[int]) -> int:
    if not isinstance(shape, list) or any(type(dim) is not int or dim < 0 for dim in shape):
        raise MetadataError("invalid tensor shape")
    return math.prod(shape)


def _disposition(name: str) -> str:
    if name.startswith("model.language_model."):
        if name.endswith(".layer_scalar"):
            return "public_layer_scalar"
        return "private_text"
    return "forbidden_vision_bridge"


def _tensor_rows(headers: dict[str, dict], weight_map: dict[str, str]) -> list[dict]:
    header_names = {key for header in headers.values() for key in header}
    if header_names != set(weight_map) or len(header_names) != sum(map(len, headers.values())):
        raise MetadataError("checkpoint index and shard headers have different tensor keys")

    rows = []
    for name in sorted(header_names):
        shard = weight_map[name]
        if shard not in headers or name not in headers[shard]:
            raise MetadataError(f"{name}: checkpoint index points to the wrong shard")
        descriptor = headers[shard][name]
        _exact_keys(descriptor, {"dtype", "shape", "data_offsets"}, name)
        dtype = descriptor["dtype"]
        shape = descriptor["shape"]
        offsets = descriptor["data_offsets"]
        if dtype != "BF16":
            raise MetadataError(f"{name}: only pinned BF16 is accepted")
        if (
            not isinstance(offsets, list)
            or len(offsets) != 2
            or any(type(value) is not int for value in offsets)
            or not 0 <= offsets[0] <= offsets[1]
        ):
            raise MetadataError(f"{name}: invalid data offsets")
        nbytes = _element_count(shape) * 2
        if offsets[1] - offsets[0] != nbytes:
            raise MetadataError(f"{name}: shape and offsets disagree")
        base = 8 + SHARDS[shard]["header_bytes"]
        rows.append(
            {
                "data_offsets": offsets,
                "disposition": _disposition(name),
                "dtype": dtype,
                "file_offsets": [base + offsets[0], base + offsets[1]],
                "name": name,
                "nbytes": nbytes,
                "shape": shape,
                "shard": shard,
            }
        )

    for shard, spec in SHARDS.items():
        shard_rows = sorted(
            (row for row in rows if row["shard"] == shard),
            key=lambda row: row["data_offsets"][0],
        )
        cursor = 0
        for row in shard_rows:
            if row["data_offsets"][0] != cursor:
                raise MetadataError(f"{shard}: tensor data has a gap or overlap")
            cursor = row["data_offsets"][1]
        if cursor != spec["bytes"] - 8 - spec["header_bytes"]:
            raise MetadataError(f"{shard}: tensor data does not cover the shard")
    return rows


def _bf16(raw: bytes) -> tuple[int, str]:
    if len(raw) != 2:
        raise MetadataError("a BF16 scalar must occupy two bytes")
    bits = int.from_bytes(raw, "little")
    value = struct.unpack("<f", struct.pack("<I", bits << 16))[0]
    if not math.isfinite(value):
        raise MetadataError("a public layer scalar is not finite")
    return bits, value.hex()


def _public_scalars(rows: list[dict], readers: dict[str, Callable[[int, int], bytes]]) -> list[dict]:
    by_name = {row["name"]: row for row in rows}
    scalars = []
    for layer in range(60):
        name = f"model.language_model.layers.{layer}.layer_scalar"
        row = by_name.get(name)
        if row is None or row["shape"] != [1] or row["nbytes"] != 2:
            raise MetadataError(f"{name}: missing or not a one-element BF16 tensor")
        start, end = row["file_offsets"]
        raw = readers[row["shard"]](start, end)
        bits, value_hexfloat = _bf16(raw)
        scalars.append(
            {
                **copy.deepcopy(row),
                "bf16_bits": bits,
                "layer": layer,
                "raw_le_hex": raw.hex(),
                "value_hexfloat": value_hexfloat,
            }
        )
    return scalars


def _artifact_record(name: str, body: bytes) -> dict:
    return {
        "bytes": len(body),
        "name": name,
        "sha256": sha256(body),
        "url": f"{BASE_URL}/{name}",
    }


def compile_manifest(
    config: bytes,
    index: bytes,
    tokenizer: bytes,
    raw_headers: dict[str, bytes],
    headers: dict[str, dict],
    readers: dict[str, Callable[[int, int], bytes]],
) -> dict:
    try:
        config_object = json.loads(config)
        index_object = json.loads(index)
        tokenizer_object = json.loads(tokenizer)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MetadataError("a pinned JSON source artifact is invalid") from error
    if config_object.get("model_type") != "gemma4" or config_object.get("dtype") != "bfloat16":
        raise MetadataError("config is not the pinned BF16 Gemma 4 model")
    if tokenizer_object.get("model", {}).get("type") != "BPE":
        raise MetadataError("tokenizer model is not the pinned BPE model")
    weight_map = index_object.get("weight_map")
    if not isinstance(weight_map, dict):
        raise MetadataError("checkpoint index has no weight map")
    rows = _tensor_rows(headers, weight_map)
    scalars = _public_scalars(rows, readers)

    counts = {name: 0 for name in ("private_text", "public_layer_scalar", "forbidden_vision_bridge")}
    scalar_counts = counts.copy()
    for row in rows:
        counts[row["disposition"]] += 1
        scalar_counts[row["disposition"]] += _element_count(row["shape"])
    payload = sum(row["nbytes"] for row in rows)
    framing = sum(8 + spec["header_bytes"] for spec in SHARDS.values())
    ordered_scalar_bytes = b"".join(bytes.fromhex(row["raw_le_hex"]) for row in scalars)
    if sha256(ordered_scalar_bytes) != EXPECTED["ordered_public_layer_scalar_bytes_sha256"]:
        raise MetadataError("ordered public layer-scalar bytes differ")

    summary = {
        "complete_weight_shards_downloaded": 0,
        "forbidden_vision_bridge_scalars": scalar_counts["forbidden_vision_bridge"],
        "forbidden_vision_bridge_tensors": counts["forbidden_vision_bridge"],
        "framing_bytes": framing,
        "payload_bytes": payload,
        "physical_tensors": len(rows),
        "private_text_scalars": scalar_counts["private_text"],
        "private_text_tensors": counts["private_text"],
        "public_layer_scalars": counts["public_layer_scalar"],
        "public_layer_scalar_values_are_runtime_usage_claims": False,
        "ordered_public_layer_scalar_bytes_sha256": EXPECTED[
            "ordered_public_layer_scalar_bytes_sha256"
        ],
        "weight_shard_bytes_requested": framing + len(ordered_scalar_bytes),
        "weight_tensor_value_bytes_requested": len(ordered_scalar_bytes),
    }
    manifest = {
        "admission_credit": {
            "full_source_bodies_verified": False,
            "gemma_quant_v1": False,
            "runtime_tensor_use": False,
            "source_metadata_and_public_scalar_values": True,
            "workload_token_ids": False,
        },
        "config": _artifact_record("config.json", config),
        "index": _artifact_record("model.safetensors.index.json", index),
        "model": MODEL,
        "public_layer_scalars": scalars,
        "revision": REVISION,
        "schema": SCHEMA,
        "shards": [
            {
                "bytes": spec["bytes"],
                "header_bytes": spec["header_bytes"],
                "header_sha256": sha256(raw_headers[name]),
                "lfs_sha256": spec["lfs_sha256"],
                "name": name,
                "tensor_count": len(headers[name]),
                "url": f"{BASE_URL}/{name}",
                "xet_hash": spec["xet_hash"],
            }
            for name, spec in SHARDS.items()
        ],
        "summary": summary,
        "tensors": rows,
        "tokenizer": _artifact_record("tokenizer.json", tokenizer),
    }
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: dict) -> None:
    if manifest.get("schema") != SCHEMA or manifest.get("model") != MODEL:
        raise MetadataError("manifest schema or model differs")
    if manifest.get("revision") != REVISION:
        raise MetadataError("manifest revision differs")
    for field, source_name in (
        ("config", "config.json"),
        ("index", "model.safetensors.index.json"),
        ("tokenizer", "tokenizer.json"),
    ):
        record = manifest.get(field)
        expected = SMALL_ARTIFACTS[source_name]
        if not isinstance(record, dict):
            raise MetadataError(f"manifest {field} is missing")
        if record.get("bytes") != expected["bytes"] or record.get("sha256") != expected["sha256"]:
            raise MetadataError(f"manifest {field} identity differs")

    shard_rows = manifest.get("shards")
    if not isinstance(shard_rows, list) or [row.get("name") for row in shard_rows] != list(SHARDS):
        raise MetadataError("manifest shard order differs")
    for row in shard_rows:
        spec = SHARDS[row["name"]]
        for field in ("bytes", "header_bytes", "header_sha256", "lfs_sha256", "xet_hash"):
            if row.get(field) != spec[field]:
                raise MetadataError(f"{row['name']}: manifest {field} differs")

    rows = manifest.get("tensors")
    if not isinstance(rows, list) or len(rows) != EXPECTED["physical_tensors"]:
        raise MetadataError("manifest tensor count differs")
    if [row.get("name") for row in rows] != sorted(row.get("name") for row in rows):
        raise MetadataError("manifest tensors are not uniquely sorted")
    names = {row["name"] for row in rows}
    if len(names) != len(rows):
        raise MetadataError("manifest tensor names are duplicated")
    for row in rows:
        _exact_keys(
            row,
            {"data_offsets", "disposition", "dtype", "file_offsets", "name", "nbytes", "shape", "shard"},
            row.get("name", "tensor"),
        )
        if row["shard"] not in SHARDS or row["dtype"] != "BF16":
            raise MetadataError(f"{row['name']}: shard or dtype differs")
        if row["disposition"] != _disposition(row["name"]):
            raise MetadataError(f"{row['name']}: disposition differs")
        nbytes = _element_count(row["shape"]) * 2
        data_start, data_end = row["data_offsets"]
        file_start, file_end = row["file_offsets"]
        base = 8 + SHARDS[row["shard"]]["header_bytes"]
        if (
            row["nbytes"] != nbytes
            or data_end - data_start != nbytes
            or [file_start, file_end] != [base + data_start, base + data_end]
        ):
            raise MetadataError(f"{row['name']}: shape or offsets differ")

    for shard, spec in SHARDS.items():
        in_shard = sorted(
            (row for row in rows if row["shard"] == shard), key=lambda row: row["data_offsets"][0]
        )
        cursor = 0
        for row in in_shard:
            if row["data_offsets"][0] != cursor:
                raise MetadataError(f"{shard}: manifest has a tensor gap or overlap")
            cursor = row["data_offsets"][1]
        if cursor != spec["bytes"] - 8 - spec["header_bytes"]:
            raise MetadataError(f"{shard}: manifest payload extent differs")

    summary = manifest.get("summary", {})
    expected_summary = {
        "physical_tensors": EXPECTED["physical_tensors"],
        "private_text_tensors": EXPECTED["private_text_tensors"],
        "public_layer_scalars": EXPECTED["public_layer_scalars"],
        "forbidden_vision_bridge_tensors": EXPECTED["forbidden_vision_bridge_tensors"],
        "payload_bytes": EXPECTED["payload_bytes"],
        "framing_bytes": EXPECTED["framing_bytes"],
        "ordered_public_layer_scalar_bytes_sha256": EXPECTED[
            "ordered_public_layer_scalar_bytes_sha256"
        ],
        "private_text_scalars": EXPECTED["private_text_scalars"],
        "forbidden_vision_bridge_scalars": EXPECTED["forbidden_vision_bridge_scalars"],
        "complete_weight_shards_downloaded": 0,
        "weight_shard_bytes_requested": EXPECTED["framing_bytes"] + 120,
        "weight_tensor_value_bytes_requested": 120,
        "public_layer_scalar_values_are_runtime_usage_claims": False,
    }
    actual_counts = {
        disposition: sum(row["disposition"] == disposition for row in rows)
        for disposition in ("private_text", "public_layer_scalar", "forbidden_vision_bridge")
    }
    actual_scalars = {
        disposition: sum(
            _element_count(row["shape"])
            for row in rows
            if row["disposition"] == disposition
        )
        for disposition in actual_counts
    }
    derived_summary = {
        "physical_tensors": len(rows),
        "private_text_tensors": actual_counts["private_text"],
        "public_layer_scalars": actual_counts["public_layer_scalar"],
        "forbidden_vision_bridge_tensors": actual_counts["forbidden_vision_bridge"],
        "payload_bytes": sum(row["nbytes"] for row in rows),
        "private_text_scalars": actual_scalars["private_text"],
        "forbidden_vision_bridge_scalars": actual_scalars["forbidden_vision_bridge"],
    }
    for field, value in {**expected_summary, **derived_summary}.items():
        if summary.get(field) != value:
            raise MetadataError(f"manifest summary {field} differs")

    scalars = manifest.get("public_layer_scalars")
    if not isinstance(scalars, list) or len(scalars) != 60:
        raise MetadataError("manifest public scalar count differs")
    tensor_by_name = {row["name"]: row for row in rows}
    ordered = bytearray()
    for layer, scalar in enumerate(scalars):
        name = f"model.language_model.layers.{layer}.layer_scalar"
        if scalar.get("layer") != layer or scalar.get("name") != name:
            raise MetadataError("manifest public scalar order differs")
        base = tensor_by_name.get(name)
        if base is None or any(scalar.get(field) != value for field, value in base.items()):
            raise MetadataError(f"{name}: scalar descriptor differs from tensor inventory")
        try:
            raw = bytes.fromhex(scalar["raw_le_hex"])
        except (KeyError, TypeError, ValueError) as error:
            raise MetadataError(f"{name}: scalar bytes are invalid") from error
        bits, value_hexfloat = _bf16(raw)
        if scalar.get("bf16_bits") != bits or scalar.get("value_hexfloat") != value_hexfloat:
            raise MetadataError(f"{name}: scalar decoding differs")
        ordered.extend(raw)
    if summary.get("ordered_public_layer_scalar_bytes_sha256") != sha256(bytes(ordered)):
        raise MetadataError("ordered public scalar digest differs")

    credit = manifest.get("admission_credit")
    if credit != {
        "full_source_bodies_verified": False,
        "gemma_quant_v1": False,
        "runtime_tensor_use": False,
        "source_metadata_and_public_scalar_values": True,
        "workload_token_ids": False,
    }:
        raise MetadataError("manifest admission-credit boundary differs")


def scalar_csv(manifest: dict, source_metadata_sha256: str) -> bytes:
    validate_manifest(manifest)
    lines = [
        f"@schema={SCALAR_SCHEMA}",
        f"@model={MODEL}",
        f"@revision={REVISION}",
        f"@source_metadata_sha256={source_metadata_sha256}",
        "@ordered_raw_sha256="
        + manifest["summary"]["ordered_public_layer_scalar_bytes_sha256"],
        "@count=60",
        "@record_columns=layer|name|raw_le_hex|bf16_bits|value_hexfloat",
    ]
    lines.extend(
        ",".join(
            (
                str(row["layer"]),
                row["name"],
                row["raw_le_hex"],
                str(row["bf16_bits"]),
                row["value_hexfloat"],
            )
        )
        for row in manifest["public_layer_scalars"]
    )
    body = ("\n".join(lines) + "\n").encode("ascii")
    validate_scalar_csv(body, manifest, source_metadata_sha256)
    return body


def validate_scalar_csv(body: bytes, manifest: dict, source_metadata_sha256: str) -> None:
    if not body.endswith(b"\n") or b"\r" in body:
        raise MetadataError("scalar CSV must use canonical LF lines")
    try:
        lines = body.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise MetadataError("scalar CSV must be ASCII") from error
    expected_header = [
        f"@schema={SCALAR_SCHEMA}",
        f"@model={MODEL}",
        f"@revision={REVISION}",
        f"@source_metadata_sha256={source_metadata_sha256}",
        "@ordered_raw_sha256="
        + manifest["summary"]["ordered_public_layer_scalar_bytes_sha256"],
        "@count=60",
        "@record_columns=layer|name|raw_le_hex|bf16_bits|value_hexfloat",
    ]
    if lines[: len(expected_header)] != expected_header:
        raise MetadataError("scalar CSV header differs")
    records = lines[len(expected_header) :]
    if len(records) != 60:
        raise MetadataError("scalar CSV must have 60 records")
    for layer, (line, expected) in enumerate(zip(records, manifest["public_layer_scalars"])):
        fields = line.split(",")
        wanted = [
            str(layer),
            expected["name"],
            expected["raw_le_hex"],
            str(expected["bf16_bits"]),
            expected["value_hexfloat"],
        ]
        if fields != wanted:
            raise MetadataError(f"scalar CSV record {layer} differs")


def _atomic_write(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary.write(body)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)


def acquire(
    output: Path,
    scalar_output: Path,
    config_path: Path | None = None,
    index_path: Path | None = None,
    tokenizer_path: Path | None = None,
    timeout: float = 30.0,
) -> tuple[str, Path, str, Path]:
    config = _download_small("config.json", config_path, timeout)
    index = _download_small("model.safetensors.index.json", index_path, timeout)
    tokenizer = _download_small("tokenizer.json", tokenizer_path, timeout)

    readers = {}
    raw_headers = {}
    headers = {}
    for name in SHARDS:
        location = _resolve_shard(name, timeout)
        reader = _range_reader(name, location, timeout)
        raw_header, header = _decode_header(name, reader)
        readers[name] = reader
        raw_headers[name] = raw_header
        headers[name] = header

    manifest = compile_manifest(config, index, tokenizer, raw_headers, headers, readers)
    body = (json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    digest = sha256(body)
    _atomic_write(output, body)
    sidecar = output.with_suffix(".sha256")
    _atomic_write(sidecar, f"{digest}  {output.name}\n".encode("ascii"))
    scalar_body = scalar_csv(manifest, digest)
    scalar_digest = sha256(scalar_body)
    _atomic_write(scalar_output, scalar_body)
    scalar_sidecar = scalar_output.with_suffix(".sha256")
    _atomic_write(
        scalar_sidecar,
        f"{scalar_digest}  {scalar_output.name}\n".encode("ascii"),
    )
    return digest, sidecar, scalar_digest, scalar_sidecar


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--scalar-output", type=Path, required=True)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--index", type=Path)
    parser.add_argument("--tokenizer", type=Path)
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()
    digest, sidecar, scalar_digest, scalar_sidecar = acquire(
        args.output,
        args.scalar_output,
        args.config,
        args.index,
        args.tokenizer,
        args.timeout,
    )
    print(f"source metadata SHA-256: {digest}")
    print(f"sidecar: {sidecar}")
    print(f"layer scalar CSV SHA-256: {scalar_digest}")
    print(f"layer scalar sidecar: {scalar_sidecar}")
    print("weight shard bytes requested: 160616; complete weight bodies: 0")


if __name__ == "__main__":
    main()
