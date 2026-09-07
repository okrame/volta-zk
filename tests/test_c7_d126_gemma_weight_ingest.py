from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "c7_d126_gemma_weight_ingest.py"


def load_module():
    spec = importlib.util.spec_from_file_location("c7_d126_gemma_weight_ingest", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tiny_shard(tmp_path: Path, tensors: list[tuple[str, bytes]]):
    descriptors = {}
    rows = []
    payload = bytearray()
    for name, body in tensors:
        start = len(payload)
        payload.extend(body)
        descriptors[name] = {
            "dtype": "BF16",
            "shape": [len(body) // 2],
            "data_offsets": [start, len(payload)],
        }
    raw_header = json.dumps(
        {"__metadata__": {"format": "pt"}, **descriptors}, separators=(",", ":")
    ).encode()
    data_start = 8 + len(raw_header)
    for name, _body in tensors:
        descriptor = descriptors[name]
        rows.append(
            {
                "name": name,
                "shard": "tiny.safetensors",
                "dtype": "BF16",
                "shape": descriptor["shape"],
                "data_offsets": descriptor["data_offsets"],
                "file_offsets": [data_start + value for value in descriptor["data_offsets"]],
                "nbytes": descriptor["data_offsets"][1] - descriptor["data_offsets"][0],
                "disposition": "private_text",
            }
        )
    body = len(raw_header).to_bytes(8, "little") + raw_header + payload
    path = tmp_path / "tiny.safetensors"
    path.write_bytes(body)
    specs = {
        path.name: {
            "bytes": len(body),
            "header_bytes": len(raw_header),
            "header_sha256": hashlib.sha256(raw_header).hexdigest(),
            "lfs_sha256": hashlib.sha256(body).hexdigest(),
        }
    }
    return path, {"tensors": rows}, specs


def test_exact_bf16_dyadic_rne_and_symmetric_overflow() -> None:
    module = load_module()
    convert = module.bf16_bits_to_i16

    assert convert(0x0000, -500) == 0
    assert convert(0x8000, -500) == 0
    assert convert(0x3F80, 1) == 0  # +0.5 ties to even 0
    assert convert(0xBF80, 1) == 0  # -0.5 ties to even 0
    assert convert(0x4040, 1) == 2  # +1.5 ties to even 2
    assert convert(0xC040, 1) == -2
    assert convert(0x40A0, 1) == 2  # +2.5 ties to even 2
    assert convert(0xC0A0, 1) == -2
    assert convert(0x46FF, 0) == 32640

    for bits in (0x4700, 0xC700):  # +/-32768 is outside [-32767, 32767].
        with pytest.raises(module.IngestError, match="overflows"):
            convert(bits, 0)
    for bits in (0x7F80, 0xFF80, 0x7FC1):
        with pytest.raises(module.IngestError, match="non-finite"):
            convert(bits, 0)
    with pytest.raises(ValueError, match="bool"):
        convert(0x3F80, True)


def test_tiny_streaming_chunk_and_header_fixture(tmp_path: Path) -> None:
    module = load_module()
    raw_values = bytes.fromhex("803f40400080")  # 1.0, 3.0, -0.0
    assert module.convert_bf16le_chunk(raw_values, 1) == bytes.fromhex("000002000000")
    with pytest.raises(module.IngestError, match="odd"):
        module.convert_bf16le_chunk(b"\x00", 0)

    descriptor = {"dtype": "BF16", "shape": [1], "data_offsets": [0, 2]}
    raw_header = json.dumps(
        {"__metadata__": {"format": "pt"}, "weight": descriptor},
        separators=(",", ":"),
    ).encode()
    shard = tmp_path / "tiny.safetensors"
    shard.write_bytes(len(raw_header).to_bytes(8, "little") + raw_header + b"\x80\x3f")
    module.verify_safetensors_header(
        shard,
        {
            "header_bytes": len(raw_header),
            "header_sha256": hashlib.sha256(raw_header).hexdigest(),
        },
        [{"name": "weight", **descriptor}],
    )
    digest, count = module.stream_sha256(shard, chunk_bytes=3)
    assert count == shard.stat().st_size
    assert digest == hashlib.sha256(shard.read_bytes()).hexdigest()


def test_reference_packer_obeys_terminal_not_metadata_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    source, metadata, specs = tiny_shard(
        tmp_path,
        [("a", bytes.fromhex("803f")), ("b", bytes.fromhex("4040"))],
    )  # physical order: a=1, b=3
    output = tmp_path / "packed.i16"
    real_open = Path.open
    source_opens = 0

    def counted_open(path, *args, **kwargs):
        nonlocal source_opens
        if path == source:
            source_opens += 1
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", counted_open)
    source_digests, digest, count = module._pack_private_weights_source_once(
        {source.name: source},
        metadata,
        ["b", "a"],
        {"a": -14, "b": -13},
        output,
        chunk_bytes=2,
        shard_specs=specs,
        packed_bytes=4,
    )
    assert output.read_bytes() == bytes.fromhex("00600040")
    assert count == 4
    assert digest == hashlib.sha256(output.read_bytes()).hexdigest()
    assert source_digests == {source.name: specs[source.name]["lfs_sha256"]}
    assert source_opens == 1


def test_layout_rejects_offset_shape_and_contiguity_drift(tmp_path: Path) -> None:
    module = load_module()
    _source, metadata, specs = tiny_shard(
        tmp_path,
        [("a", bytes.fromhex("803f")), ("b", bytes.fromhex("4040"))],
    )

    drifted = copy.deepcopy(metadata)
    drifted["tensors"][0]["file_offsets"] = [
        value + 2 for value in drifted["tensors"][0]["file_offsets"]
    ]
    with pytest.raises(module.IngestError, match="do not refine"):
        module.validate_tensor_layout(drifted, specs)

    drifted = copy.deepcopy(metadata)
    drifted["tensors"][0]["shape"] = [2]
    with pytest.raises(module.IngestError, match=r"2\*product"):
        module.validate_tensor_layout(drifted, specs)

    drifted = copy.deepcopy(metadata)
    drifted_specs = copy.deepcopy(specs)
    drifted_specs["tiny.safetensors"]["bytes"] += 2
    data_start = 8 + drifted_specs["tiny.safetensors"]["header_bytes"]
    drifted["tensors"][1]["data_offsets"] = [4, 6]
    drifted["tensors"][1]["file_offsets"] = [data_start + 4, data_start + 6]
    with pytest.raises(module.IngestError, match="not contiguous"):
        module.validate_tensor_layout(drifted, drifted_specs)


def test_packer_rejects_nonminimal_exponent_and_removes_partial(tmp_path: Path) -> None:
    module = load_module()
    source, metadata, specs = tiny_shard(tmp_path, [("a", bytes.fromhex("803f"))])
    output = tmp_path / "packed.i16"
    with pytest.raises(module.IngestError, match="is not minimal; expected -14"):
        module._pack_private_weights_source_once(
            {source.name: source},
            metadata,
            ["a"],
            {"a": -13},
            output,
            chunk_bytes=2,
            shard_specs=specs,
            packed_bytes=2,
        )
    assert not output.exists()
    assert list(tmp_path.glob(".packed.i16.*.partial")) == []
    assert not (tmp_path / ".packed.i16.pack.lock").exists()


def test_publish_race_never_overwrites_winner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    source, metadata, specs = tiny_shard(tmp_path, [("a", bytes.fromhex("803f"))])
    output = tmp_path / "packed.i16"
    real_link = module.os.link

    def concurrent_link(source_path, destination_path):
        Path(destination_path).write_bytes(b"winner")
        return real_link(source_path, destination_path)

    monkeypatch.setattr(module.os, "link", concurrent_link)
    with pytest.raises(module.BlockedError, match="appeared during packing"):
        module._pack_private_weights_source_once(
            {source.name: source},
            metadata,
            ["a"],
            {"a": -14},
            output,
            chunk_bytes=2,
            shard_specs=specs,
            packed_bytes=2,
        )
    assert output.read_bytes() == b"winner"
    assert list(tmp_path.glob(".packed.i16.*.partial")) == []


def test_missing_second_shard_blocks_before_any_shard_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    first = tmp_path / next(iter(module.SHARDS))
    first.write_bytes(b"present but must not be read")

    def forbidden_open(*_args, **_kwargs):
        raise AssertionError("a partial checkpoint must not be opened")

    monkeypatch.setattr(Path, "open", forbidden_open)
    with pytest.raises(module.BlockedError, match="no shard read"):
        module._required_shards(tmp_path)


def test_exponent_map_is_exact_and_rejects_bool(tmp_path: Path) -> None:
    module = load_module()
    path = tmp_path / "exponents.json"
    path.write_text(json.dumps({"weight_exponents_by_tensor": {"a": -7, "b": 3}}))
    values, digest = module.load_weight_exponents(path, ["a", "b"])
    assert values == {"a": -7, "b": 3}
    assert digest == hashlib.sha256(path.read_bytes()).hexdigest()

    path.write_text(json.dumps({"weight_exponents_by_tensor": {"a": True, "b": 3}}))
    with pytest.raises(module.IngestError, match="bool"):
        module.load_weight_exponents(path, ["a", "b"])
    path.write_text(json.dumps({"weight_exponents_by_tensor": {"a": -7, "extra": 3}}))
    with pytest.raises(module.IngestError, match="keys differ"):
        module.load_weight_exponents(path, ["a", "b"])


def test_checked_in_metadata_and_resource_constants_are_frozen() -> None:
    module = load_module()
    metadata = module.load_metadata()
    private = [row for row in metadata["tensors"] if row["disposition"] == "private_text"]
    terminal_order = module.load_terminal_private_order(metadata)
    assert len(private) == 772
    assert len(terminal_order) == 772
    assert terminal_order != sorted(terminal_order)
    assert terminal_order[:8] == [
        "model.language_model.layers.0.self_attn.q_proj.weight",
        "model.language_model.layers.0.self_attn.k_proj.weight",
        "model.language_model.layers.0.self_attn.v_proj.weight",
        "model.language_model.layers.0.self_attn.o_proj.weight",
        "model.language_model.layers.0.mlp.gate_proj.weight",
        "model.language_model.layers.0.mlp.up_proj.weight",
        "model.language_model.layers.0.mlp.down_proj.weight",
        "model.language_model.layers.0.input_layernorm.weight",
    ]
    assert set(terminal_order) == {row["name"] for row in private}
    assert sum(row["nbytes"] for row in private) == 61_394_690_560
    assert sum(row["bytes"] for row in module.SHARDS.values()) == 62_546_338_248
    assert module.MIN_STORAGE_BYTES == 400_000_000_000
    assert module.MIN_RAM_BYTES == 256 * 1024**3


def test_insufficient_disk_blocks_without_creating_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    output = tmp_path / "packed.i16"
    monkeypatch.setattr(
        module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=399_999_999_999, used=0, free=399_999_999_999),
    )
    monkeypatch.setattr(module, "_host_ram_bytes", lambda: module.MIN_RAM_BYTES)
    with pytest.raises(module.BlockedError, match="requires at least 400000000000"):
        module.check_pack_resources(output)
    assert not output.exists()
    assert not output.with_name(output.name + ".partial").exists()


def test_orphan_partial_blocks_retry_before_resource_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    output = tmp_path / "packed.i16"
    orphan = tmp_path / ".packed.i16.interrupted.partial"
    orphan.write_bytes(b"operator-owned recovery evidence")

    def forbidden_disk_usage(_path):
        raise AssertionError("resource checks must not run before orphan disposition")

    monkeypatch.setattr(module.shutil, "disk_usage", forbidden_disk_usage)
    with pytest.raises(module.BlockedError, match="operator inspection and removal"):
        module.check_pack_resources(output)
    assert orphan.read_bytes() == b"operator-owned recovery evidence"


def test_atomic_pack_lock_blocks_concurrent_writer(tmp_path: Path) -> None:
    module = load_module()
    source, metadata, specs = tiny_shard(tmp_path, [("a", bytes.fromhex("803f"))])
    output = tmp_path / "packed.i16"
    lock = tmp_path / ".packed.i16.pack.lock"
    lock.write_text("pid=another-writer\n")

    with pytest.raises(module.BlockedError, match="pack lock already exists"):
        module._pack_private_weights_source_once(
            {source.name: source},
            metadata,
            ["a"],
            {"a": -14},
            output,
            chunk_bytes=2,
            shard_specs=specs,
            packed_bytes=2,
        )
    assert lock.read_text() == "pid=another-writer\n"
    assert not output.exists()
    assert list(tmp_path.glob(".packed.i16.*.partial")) == []


def test_only_one_canonical_packed_path_is_admitted(tmp_path: Path) -> None:
    module = load_module()
    canonical = tmp_path / module.PACKED_FILENAME
    module.require_canonical_output(tmp_path, canonical)

    with pytest.raises(module.BlockedError, match="canonical path"):
        module.require_canonical_output(tmp_path, tmp_path / "second-copy.i16")
