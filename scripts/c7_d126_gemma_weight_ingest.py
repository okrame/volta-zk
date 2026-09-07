#!/usr/bin/env python3
"""Fail-closed, Gemma-only source verification and reference i16 packing."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
METADATA = ROOT / "manifests" / "c7-d126-gemma31b-source-metadata-v1.json"
METADATA_SHA256 = "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2"
TERMINALS = ROOT / "manifests" / "c7-d126-gemma31b-terminals-v1.csv"
TERMINALS_SHA256 = "a9f4bc9db356c4f40c8f34d1af11367329532ffea53796dfbe2877177c6a9dfa"
MODEL = "google/gemma-4-31B"
REVISION = "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89"
PACKED_BYTES = 61_394_690_560
PACKED_FILENAME = f"gemma-4-31b-{REVISION}.packed.i16"
SOURCE_BYTES = 62_546_338_248
MIN_STORAGE_BYTES = 400_000_000_000
MIN_RAM_BYTES = 256 * 1024**3
RESERVED_FREE_BYTES = 60 * 1024**3
CHUNK_BYTES = 4 * 1024**2

SHARDS = {
    "model-00001-of-00002.safetensors": {
        "bytes": 49_784_788_364,
        "header_bytes": 136_896,
        "header_sha256": "a58b10bc7e2ec1c7d062896e71f69466c8981440cab7a045510fb997e4b91bc9",
        "lfs_sha256": "186fa361e76abbb5f48ffb3d9965181a5da33522e39c25eb75d7241da1637aac",
    },
    "model-00002-of-00002.safetensors": {
        "bytes": 12_761_549_884,
        "header_bytes": 23_584,
        "header_sha256": "2b82d9b263de66d77efdc15b56743d5d3b1cfb1ee4587acdd836c54c7eadfb42",
        "lfs_sha256": "b78ae8294981a6d674c47f2261d34240b7539bbeafb4f7d0525f6167946e6da0",
    },
}


class IngestError(ValueError):
    """An input exists but violates the frozen identity or format."""


class BlockedError(RuntimeError):
    """A required input or host resource is unavailable."""


def _sha256_bytes(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _json_no_duplicates(body: bytes, label: str) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise IngestError(f"{label}: duplicate JSON key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(body, object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise IngestError(f"{label}: invalid UTF-8 JSON") from error
    if type(value) is not dict:
        raise IngestError(f"{label}: top level must be an object")
    return value


def validate_tensor_layout(metadata: dict, shard_specs: dict = SHARDS) -> None:
    """Validate the metadata-to-file offset map without reading tensor bodies."""
    tensors = metadata.get("tensors")
    if type(tensors) is not list:
        raise IngestError("metadata tensors must be a list")

    by_shard = {name: [] for name in shard_specs}
    names = set()
    for index, row in enumerate(tensors):
        if type(row) is not dict:
            raise IngestError(f"metadata tensor {index} must be an object")
        name = row.get("name")
        shard = row.get("shard")
        shape = row.get("shape")
        data_offsets = row.get("data_offsets")
        file_offsets = row.get("file_offsets")
        nbytes = row.get("nbytes")
        if type(name) is not str or not name or name in names:
            raise IngestError(f"metadata tensor {index} has a missing or duplicate name")
        names.add(name)
        if shard not in shard_specs:
            raise IngestError(f"{name}: unknown shard {shard!r}")
        if row.get("dtype") != "BF16":
            raise IngestError(f"{name}: only BF16 tensors are permitted")
        if (
            type(shape) is not list
            or not shape
            or any(type(dimension) is not int or dimension <= 0 for dimension in shape)
        ):
            raise IngestError(f"{name}: shape must contain positive integer dimensions")
        elements = 1
        for dimension in shape:
            elements *= dimension
        if type(nbytes) is not int or nbytes != 2 * elements:
            raise IngestError(f"{name}: nbytes does not equal 2*product(shape)")
        for label, offsets in (("data_offsets", data_offsets), ("file_offsets", file_offsets)):
            if (
                type(offsets) is not list
                or len(offsets) != 2
                or any(type(value) is not int for value in offsets)
                or offsets[0] < 0
                or offsets[0] >= offsets[1]
                or offsets[1] - offsets[0] != nbytes
                or offsets[0] % 2
                or offsets[1] % 2
            ):
                raise IngestError(f"{name}: invalid BF16 {label}")
        data_start = 8 + shard_specs[shard]["header_bytes"]
        if file_offsets != [data_start + data_offsets[0], data_start + data_offsets[1]]:
            raise IngestError(f"{name}: file_offsets do not refine safetensors data_offsets")
        if file_offsets[1] > shard_specs[shard]["bytes"]:
            raise IngestError(f"{name}: tensor extends beyond its shard")
        by_shard[shard].append(row)

    for shard, rows in by_shard.items():
        cursor = 0
        for row in sorted(rows, key=lambda value: value["data_offsets"][0]):
            start, end = row["data_offsets"]
            if start != cursor:
                raise IngestError(
                    f"{shard}: tensor payload is not contiguous at {row['name']!r}"
                )
            cursor = end
        expected = shard_specs[shard]["bytes"] - 8 - shard_specs[shard]["header_bytes"]
        if cursor != expected:
            raise IngestError(
                f"{shard}: tensor payload covers {cursor} bytes, expected {expected}"
            )


def load_metadata(path: Path = METADATA) -> dict:
    try:
        body = path.read_bytes()
    except OSError as error:
        raise BlockedError(f"checked-in metadata unavailable: {path}") from error
    if _sha256_bytes(body) != METADATA_SHA256:
        raise IngestError("checked-in metadata SHA-256 differs")
    metadata = _json_no_duplicates(body, "metadata")
    if (
        metadata.get("schema") != "volta-c7-d126-gemma31b-source-metadata-v1"
        or metadata.get("model") != MODEL
        or metadata.get("revision") != REVISION
    ):
        raise IngestError("metadata model, revision or schema differs")

    rows = metadata.get("shards")
    if (
        type(rows) is not list
        or any(type(row) is not dict for row in rows)
        or [row.get("name") for row in rows] != list(SHARDS)
    ):
        raise IngestError("metadata shard order differs")
    for row in rows:
        expected = SHARDS[row["name"]]
        for field, value in expected.items():
            if row.get(field) != value:
                raise IngestError(f"{row['name']}: metadata {field} differs")

    validate_tensor_layout(metadata)
    private = [row for row in metadata["tensors"] if row.get("disposition") == "private_text"]
    if (
        len(private) != 772
        or [row["name"] for row in private] != sorted(row["name"] for row in private)
        or sum(row.get("nbytes", -1) for row in private) != PACKED_BYTES
        or any(row.get("dtype") != "BF16" for row in private)
    ):
        raise IngestError("metadata private-tensor census differs")
    return metadata


def load_terminal_private_order(metadata: dict, path: Path = TERMINALS) -> list[str]:
    try:
        body = path.read_bytes()
    except OSError as error:
        raise BlockedError(f"terminal manifest unavailable: {path}") from error
    if _sha256_bytes(body) != TERMINALS_SHA256:
        raise IngestError("terminal manifest SHA-256 differs")
    if not body.endswith(b"\n") or b"\r" in body:
        raise IngestError("terminal manifest must use canonical LF lines")
    try:
        lines = body.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise IngestError("terminal manifest must be ASCII") from error
    marker = "@record_columns=ordinal|plane|owner|use_axis_length|private_source_keys|public_source_keys"
    try:
        start = lines.index(marker) + 1
    except ValueError as error:
        raise IngestError("terminal manifest record schema differs") from error
    records = lines[start:]
    if len(records) != 480:
        raise IngestError("terminal manifest must contain exactly 480 records")

    ordered = []
    for ordinal, line in enumerate(records):
        fields = line.split(",")
        if len(fields) != 6 or fields[0] != str(ordinal):
            raise IngestError(f"terminal record {ordinal} is malformed")
        if (ordinal < 472) != (fields[1] == "W"):
            raise IngestError(f"terminal record {ordinal} has the wrong plane")
        sources = [] if fields[4] == "-" else fields[4].split(";")
        if any(not source for source in sources):
            raise IngestError(f"terminal record {ordinal} has an empty private source key")
        ordered.extend(sources)

    metadata_names = {
        row["name"] for row in metadata["tensors"] if row["disposition"] == "private_text"
    }
    if len(ordered) != 772 or len(set(ordered)) != 772 or set(ordered) != metadata_names:
        raise IngestError("terminal private-source order is not a 772-key metadata bijection")
    return ordered


def _required_shards(shard_dir: Path) -> dict[str, Path]:
    paths = {name: shard_dir / name for name in SHARDS}
    missing = [str(path) for path in paths.values() if not path.is_file()]
    if missing:
        # Check all names before opening either shard: a partial checkpoint gets no reads.
        raise BlockedError("missing pinned shard(s); no shard read: " + ", ".join(missing))
    return paths


def _verify_sizes(paths: dict[str, Path]) -> None:
    for name, path in paths.items():
        try:
            size = path.stat().st_size
        except OSError as error:
            raise BlockedError(f"cannot stat shard: {path}") from error
        if size != SHARDS[name]["bytes"]:
            raise IngestError(f"{name}: {size} bytes, expected {SHARDS[name]['bytes']}")


def _validate_safetensors_header(
    label: str, raw: bytes, spec: dict, tensor_rows: list[dict]
) -> None:
    if len(raw) != spec["header_bytes"]:
        raise IngestError(f"{label}: truncated safetensors header")
    if _sha256_bytes(raw) != spec["header_sha256"]:
        raise IngestError(f"{label}: safetensors header SHA-256 differs")

    header = _json_no_duplicates(raw, f"{label} header")
    if header.pop("__metadata__", None) != {"format": "pt"}:
        raise IngestError(f"{label}: safetensors metadata differs")
    expected = {
        row["name"]: {
            "dtype": row["dtype"],
            "shape": row["shape"],
            "data_offsets": row["data_offsets"],
        }
        for row in tensor_rows
    }
    if header != expected:
        raise IngestError(f"{label}: header descriptors differ from checked-in metadata")


def verify_safetensors_header(path: Path, spec: dict, tensor_rows: list[dict]) -> None:
    try:
        with path.open("rb") as source:
            prefix = source.read(8)
            if len(prefix) != 8:
                raise IngestError(f"{path.name}: truncated safetensors prefix")
            header_bytes = int.from_bytes(prefix, "little")
            if header_bytes != spec["header_bytes"]:
                raise IngestError(f"{path.name}: safetensors header length differs")
            raw = source.read(header_bytes)
    except OSError as error:
        raise BlockedError(f"cannot read shard header: {path}") from error
    _validate_safetensors_header(path.name, raw, spec, tensor_rows)


def _verify_headers(paths: dict[str, Path], metadata: dict) -> None:
    rows = metadata["tensors"]
    for name, path in paths.items():
        verify_safetensors_header(
            path,
            SHARDS[name],
            [row for row in rows if row["shard"] == name],
        )


def _host_ram_bytes() -> int | None:
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (OSError, ValueError):
        return None


def check_read_resources(shard_dir: Path) -> dict[str, int]:
    usage = shutil.disk_usage(shard_dir)
    ram = _host_ram_bytes()
    if usage.total < MIN_STORAGE_BYTES:
        raise BlockedError(
            f"shard filesystem has {usage.total} bytes; pod requires at least {MIN_STORAGE_BYTES}"
        )
    if ram is None or ram < MIN_RAM_BYTES:
        raise BlockedError(f"host RAM is {ram!r} bytes; pod requires at least {MIN_RAM_BYTES}")
    return {"filesystem_bytes": usage.total, "free_bytes": usage.free, "ram_bytes": ram}


def require_canonical_output(shard_dir: Path, output: Path) -> None:
    expected = (shard_dir / PACKED_FILENAME).resolve(strict=False)
    actual = output.resolve(strict=False)
    if actual != expected:
        raise BlockedError(f"packed output must be the canonical path: {expected}")


def check_pack_resources(output: Path) -> dict[str, int]:
    parent = output.parent
    partial = output.with_name(output.name + ".partial")
    lock = output.with_name(f".{output.name}.pack.lock")
    if not parent.is_dir():
        raise BlockedError(f"output directory must already exist: {parent}")
    if os.path.lexists(output) or os.path.lexists(partial):
        raise BlockedError("output or its .partial path already exists; refusing overwrite")
    if os.path.lexists(lock):
        raise BlockedError(
            f"pack lock requires operator inspection and removal before retry: {lock.name}"
        )
    orphan_prefix = f".{output.name}."
    try:
        orphan_partials = sorted(
            child.name
            for child in parent.iterdir()
            if child.name.startswith(orphan_prefix) and child.name.endswith(".partial")
        )
    except OSError as error:
        raise BlockedError(f"cannot inspect output directory: {parent}") from error
    if orphan_partials:
        raise BlockedError(
            "orphan pack partial(s) require operator inspection and removal before retry: "
            + ", ".join(orphan_partials)
        )
    usage = shutil.disk_usage(parent)
    ram = _host_ram_bytes()
    if usage.total < MIN_STORAGE_BYTES:
        raise BlockedError(
            f"output filesystem has {usage.total} bytes; pod requires at least {MIN_STORAGE_BYTES}"
        )
    needed_free = PACKED_BYTES + RESERVED_FREE_BYTES
    if usage.free < needed_free:
        raise BlockedError(
            f"output filesystem has {usage.free} free bytes; requires {needed_free} before packing"
        )
    if ram is None or ram < MIN_RAM_BYTES:
        raise BlockedError(f"host RAM is {ram!r} bytes; pod requires at least {MIN_RAM_BYTES}")
    return {"filesystem_bytes": usage.total, "free_bytes": usage.free, "ram_bytes": ram}


def stream_sha256(path: Path, chunk_bytes: int = CHUNK_BYTES) -> tuple[str, int]:
    if type(chunk_bytes) is not int or chunk_bytes <= 0:
        raise ValueError("chunk_bytes must be a positive integer")
    digest = hashlib.sha256()
    count = 0
    try:
        with path.open("rb") as source:
            while chunk := source.read(chunk_bytes):
                digest.update(chunk)
                count += len(chunk)
    except OSError as error:
        raise BlockedError(f"cannot stream shard: {path}") from error
    return digest.hexdigest(), count


def verify_source_hashes(paths: dict[str, Path]) -> dict[str, str]:
    digests = {}
    for name, path in paths.items():
        digest, count = stream_sha256(path)
        if count != SHARDS[name]["bytes"] or digest != SHARDS[name]["lfs_sha256"]:
            raise IngestError(f"{name}: complete size or LFS SHA-256 differs")
        digests[name] = digest
    return digests


def load_weight_exponents(path: Path, private_names: list[str]) -> tuple[dict[str, int], str]:
    try:
        body = path.read_bytes()
    except OSError as error:
        raise BlockedError(f"weight exponent file unavailable: {path}") from error
    document = _json_no_duplicates(body, "weight exponents")
    if set(document) != {"weight_exponents_by_tensor"}:
        raise IngestError("weight exponent file must have exactly weight_exponents_by_tensor")
    values = document["weight_exponents_by_tensor"]
    if type(values) is not dict:
        raise IngestError("weight_exponents_by_tensor must be an object")
    expected = set(private_names)
    actual = set(values)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise IngestError(
            f"weight exponent keys differ: missing={missing[:3]!r}, extra={extra[:3]!r}"
        )
    if any(type(value) is not int for value in values.values()):
        raise IngestError("every weight exponent must be an integer; bool is forbidden")
    return values, _sha256_bytes(body)


def bf16_bits_to_i16(bits: int, exponent: int) -> int:
    """Return RNE(BF16 / 2**exponent), rejecting non-finite and overflow."""
    if type(bits) is not int or not 0 <= bits <= 0xFFFF:
        raise ValueError("bits must be a 16-bit integer")
    if type(exponent) is not int:
        raise ValueError("exponent must be an integer; bool is forbidden")

    sign = -1 if bits & 0x8000 else 1
    encoded_exponent = (bits >> 7) & 0xFF
    fraction = bits & 0x7F
    if encoded_exponent == 0xFF:
        raise IngestError("non-finite BF16 weight")
    if encoded_exponent == 0:
        significand, power = fraction, -133
    else:
        significand, power = 128 + fraction, encoded_exponent - 134
    if significand == 0:
        return 0

    shift = power - exponent
    if shift >= 0:
        if shift >= 15 or significand > (32767 >> shift):
            raise IngestError("BF16 weight overflows symmetric i16")
        magnitude = significand << shift
    else:
        right_shift = -shift
        if right_shift > 9:  # significand <= 255, so the rounded value is exactly zero.
            magnitude = 0
        else:
            divisor = 1 << right_shift
            magnitude, remainder = divmod(significand, divisor)
            twice = remainder << 1
            if twice > divisor or (twice == divisor and magnitude & 1):
                magnitude += 1
    if magnitude > 32767:
        raise IngestError("BF16 weight overflows symmetric i16")
    return sign * magnitude


def _convert_bf16le_chunk_with_max(
    body: bytes, exponent: int, max_abs_bits: int = 0
) -> tuple[bytes, int]:
    if len(body) % 2:
        raise IngestError("BF16 chunk has an odd byte count")
    packed = bytearray(len(body))
    for offset in range(0, len(body), 2):
        bits = body[offset] | body[offset + 1] << 8
        value = bf16_bits_to_i16(bits, exponent)
        max_abs_bits = max(max_abs_bits, bits & 0x7FFF)
        encoded = value & 0xFFFF
        packed[offset] = encoded & 0xFF
        packed[offset + 1] = encoded >> 8
    return bytes(packed), max_abs_bits


def convert_bf16le_chunk(body: bytes, exponent: int) -> bytes:
    return _convert_bf16le_chunk_with_max(body, exponent)[0]


def minimum_weight_exponent(max_abs_bits: int) -> int:
    """Smallest exponent whose RNE output fits, with all-zero tensors fixed at zero."""
    if type(max_abs_bits) is not int or not 0 <= max_abs_bits <= 0x7FFF:
        raise ValueError("max_abs_bits must be an unsigned BF16 bit pattern")
    if max_abs_bits == 0:
        return 0
    if max_abs_bits >= 0x7F80:
        raise IngestError("non-finite BF16 weight")

    # The smallest positive BF16 is 2^-133; exponent -149 scales it to 2^16,
    # so every nonzero BF16 starts outside the symmetric i16 range.
    exponent = -149
    while True:
        try:
            bf16_bits_to_i16(max_abs_bits, exponent)
            return exponent
        except IngestError:
            exponent += 1


def _read_exact(source, length: int, label: str) -> bytes:
    body = bytearray()
    while len(body) < length:
        chunk = source.read(length - len(body))
        if not chunk:
            raise IngestError(f"{label}: truncated source")
        body.extend(chunk)
    return bytes(body)


def _write_all(sink, body: bytes) -> None:
    remaining = memoryview(body)
    while remaining:
        count = sink.write(remaining)
        if count is None or count <= 0:
            raise OSError("packed output made no write progress")
        remaining = remaining[count:]


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _pack_private_weights_source_once(
    paths: dict[str, Path],
    metadata: dict,
    private_names: list[str],
    exponents: dict[str, int],
    output: Path,
    chunk_bytes: int = CHUNK_BYTES,
    shard_specs: dict = SHARDS,
    packed_bytes: int = PACKED_BYTES,
) -> tuple[dict[str, str], str, int]:
    """One-source-pass scalar reference packer; no production throughput credit."""
    if chunk_bytes <= 0 or chunk_bytes % 2:
        raise ValueError("chunk_bytes must be a positive even integer")
    if set(paths) != set(shard_specs):
        raise IngestError("source shard set differs")
    validate_tensor_layout(metadata, shard_specs)
    rows = {row["name"]: row for row in metadata["tensors"]}
    expected_private = {
        row["name"] for row in metadata["tensors"] if row.get("disposition") == "private_text"
    }
    if (
        len(private_names) != len(expected_private)
        or len(set(private_names)) != len(private_names)
        or set(private_names) != expected_private
        or set(exponents) != expected_private
    ):
        raise IngestError("private terminal order or exponent keys differ")

    output_offsets = {}
    output_cursor = 0
    for name in private_names:
        output_offsets[name] = output_cursor
        output_cursor += rows[name]["nbytes"]
    if output_cursor != packed_bytes:
        raise IngestError(
            f"terminal-order output covers {output_cursor} bytes, expected {packed_bytes}"
        )
    if os.path.lexists(output):
        raise BlockedError(f"output already exists; refusing overwrite: {output}")

    lock = output.with_name(f".{output.name}.pack.lock")
    lock_fd = -1
    owned_lock = False
    partial: Path | None = None
    partial_fd = -1
    owned_partial = False
    source_digests = {}
    written = 0
    try:
        try:
            lock_fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as error:
            raise BlockedError(
                f"pack lock already exists; inspect before retry: {lock}"
            ) from error
        owned_lock = True
        os.write(lock_fd, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(lock_fd)
        _fsync_directory(output.parent)

        partial_fd, partial_name = tempfile.mkstemp(
            prefix=f".{output.name}.", suffix=".partial", dir=output.parent
        )
        partial = Path(partial_name)
        owned_partial = True
        with os.fdopen(partial_fd, "r+b", buffering=0) as sink:
            partial_fd = -1
            for shard, spec in shard_specs.items():
                digest = hashlib.sha256()
                shard_rows = [row for row in metadata["tensors"] if row["shard"] == shard]
                private_rows = sorted(
                    (row for row in shard_rows if row["name"] in expected_private),
                    key=lambda row: row["file_offsets"][0],
                )
                try:
                    with paths[shard].open("rb") as source:
                        prefix = _read_exact(source, 8, shard)
                        digest.update(prefix)
                        if int.from_bytes(prefix, "little") != spec["header_bytes"]:
                            raise IngestError(f"{shard}: safetensors header length differs")
                        raw_header = _read_exact(source, spec["header_bytes"], shard)
                        digest.update(raw_header)
                        _validate_safetensors_header(shard, raw_header, spec, shard_rows)
                        source_position = 8 + spec["header_bytes"]

                        for row in private_rows:
                            start, end = row["file_offsets"]
                            while source_position < start:
                                length = min(chunk_bytes, start - source_position)
                                body = _read_exact(source, length, shard)
                                digest.update(body)
                                source_position += length

                            tensor_position = 0
                            max_abs_bits = 0
                            while source_position < end:
                                length = min(chunk_bytes, end - source_position)
                                body = _read_exact(source, length, row["name"])
                                digest.update(body)
                                converted, max_abs_bits = _convert_bf16le_chunk_with_max(
                                    body, exponents[row["name"]], max_abs_bits
                                )
                                sink.seek(output_offsets[row["name"]] + tensor_position)
                                _write_all(sink, converted)
                                tensor_position += len(converted)
                                source_position += length
                                written += len(converted)

                            required = minimum_weight_exponent(max_abs_bits)
                            supplied = exponents[row["name"]]
                            if supplied != required:
                                raise IngestError(
                                    f"{row['name']}: exponent {supplied} is not minimal; "
                                    f"expected {required}"
                                )

                        while source_position < spec["bytes"]:
                            length = min(chunk_bytes, spec["bytes"] - source_position)
                            body = _read_exact(source, length, shard)
                            digest.update(body)
                            source_position += length
                        if source.read(1):
                            raise IngestError(f"{shard}: source is longer than its pinned size")
                except OSError as error:
                    raise BlockedError(f"cannot stream shard: {paths[shard]}") from error

                source_digest = digest.hexdigest()
                if source_digest != spec["lfs_sha256"]:
                    raise IngestError(f"{shard}: complete size or LFS SHA-256 differs")
                source_digests[shard] = source_digest

            sink.flush()
            os.fsync(sink.fileno())
        if written != packed_bytes:
            raise IngestError(f"packed output has {written} bytes, expected {packed_bytes}")

        packed_digest, persisted = stream_sha256(partial)
        if persisted != packed_bytes:
            raise IngestError(
                f"persisted packed output has {persisted} bytes, expected {packed_bytes}"
            )
        try:
            os.link(partial, output)
        except FileExistsError as error:
            raise BlockedError(
                f"output appeared during packing; refusing overwrite: {output}"
            ) from error
        except OSError as error:
            raise BlockedError(f"cannot atomically publish packed output: {output}") from error
        _fsync_directory(output.parent)
        partial.unlink()
        owned_partial = False
        _fsync_directory(output.parent)
    except BaseException as original:
        if partial_fd >= 0:
            os.close(partial_fd)
        if owned_partial and partial is not None:
            try:
                partial.unlink(missing_ok=True)
            except OSError as cleanup_error:
                raise BlockedError(
                    f"packing failed ({original!r}) and owned partial cleanup failed: "
                    f"{partial}: {cleanup_error}"
                ) from cleanup_error
        raise
    finally:
        if lock_fd >= 0:
            os.close(lock_fd)
        if owned_lock:
            try:
                lock.unlink(missing_ok=True)
                _fsync_directory(output.parent)
            except OSError as cleanup_error:
                raise BlockedError(
                    f"pack lock cleanup failed; inspect before retry: {lock}: {cleanup_error}"
                ) from cleanup_error
    return source_digests, packed_digest, written


def _base_report(mode: str, status: str) -> dict:
    return {
        "schema": "volta-c7-d126-gemma31b-weight-ingest-report-v1",
        "mode": mode,
        "status": status,
        "model": MODEL,
        "revision": REVISION,
        "metadata_sha256": METADATA_SHA256,
        "terminal_manifest_sha256": TERMINALS_SHA256,
        "source_bytes": SOURCE_BYTES,
        "packed_bytes": PACKED_BYTES,
        "canonical_packed_filename": PACKED_FILENAME,
        "required_pod_storage_bytes": MIN_STORAGE_BYTES,
        "required_pod_ram_bytes": MIN_RAM_BYTES,
        "stream_chunk_bytes": CHUNK_BYTES,
        "packer_classification": "scalar_python_reference",
        "production_throughput_credit": False,
        "admission_credit": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="mode", required=True)
    for name in ("preflight", "report"):
        command = commands.add_parser(name)
        command.add_argument("--shard-dir", type=Path, required=True)
        if name == "preflight":
            command.add_argument("--output", type=Path, required=True)
    pack = commands.add_parser("pack")
    pack.add_argument("--shard-dir", type=Path, required=True)
    pack.add_argument("--output", type=Path, required=True)
    pack.add_argument("--weight-exponents", type=Path, required=True)
    args = parser.parse_args()

    report = _base_report(args.mode, "INVALID")
    try:
        metadata = load_metadata()
        private_names = load_terminal_private_order(metadata)
        if args.mode != "report":
            require_canonical_output(args.shard_dir, args.output)
        paths = _required_shards(args.shard_dir)
        _verify_sizes(paths)
        if args.mode == "preflight":
            report["host"] = check_pack_resources(args.output)
            _verify_headers(paths, metadata)
            report["status"] = "READY_FOR_FULL_HASH"
        elif args.mode == "report":
            report["host"] = check_read_resources(args.shard_dir)
            _verify_headers(paths, metadata)
            report["source_sha256"] = verify_source_hashes(paths)
            report["status"] = "SOURCE_VERIFIED"
            report["full_source_bodies_verified"] = True
        else:
            exponents, exponent_digest = load_weight_exponents(
                args.weight_exponents, private_names
            )
            report["host"] = check_pack_resources(args.output)
            source_digests, packed_digest, packed_bytes = _pack_private_weights_source_once(
                paths, metadata, private_names, exponents, args.output
            )
            report.update(
                {
                    "status": "PACKED_UNADMITTED",
                    "source_sha256": source_digests,
                    "full_source_bodies_verified": True,
                    "weight_exponents_sha256": exponent_digest,
                    "packed_sha256": packed_digest,
                    "packed_bytes": packed_bytes,
                    "output": str(args.output),
                }
            )
    except BlockedError as error:
        report.update({"status": "BLOCKED", "reason": str(error)})
        print(json.dumps(report, indent=2, sort_keys=True))
        return 2
    except (IngestError, OSError, ValueError) as error:
        report.update({"status": "INVALID", "reason": str(error)})
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
