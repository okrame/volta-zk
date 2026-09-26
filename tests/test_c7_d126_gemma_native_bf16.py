"""Small native/Python equality checks. All generated files stay in rust/target."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile

import pytest
from test_c7_d126_gemma_weight_ingest import tiny_shard


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def native():
    rustc = shutil.which("rustc")
    if rustc is None:
        pytest.fail("rustup rustc is required for the Gemma native equality gate")
    target = ROOT / "rust" / "target"
    target.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="gemma31b-bf16-", dir=target) as temporary:
        executable = Path(temporary) / "fixture"
        for name, output in (("fixture", executable), ("pack", executable.with_name("packer"))):
            subprocess.run([
                rustc, "--edition", "2021", "-O",
                str(ROOT / f"rust/volta-pcs/examples/gemma31b_bf16_{name}.rs"),
                "-o", str(output),
            ], check=True, capture_output=True, timeout=60)
        yield executable


def reference():
    spec = importlib.util.spec_from_file_location("gemma_ingest_reference", ROOT / "scripts/c7_d126_gemma_weight_ingest.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_native_tensor_packing_matches_python_across_bf16_ranges(native):
    ref = reference()
    for maximum in (0, 1, 3, 127, 128, 0x1080, 0x3080, 0x3f80, 0x46ff, 0x6080, 0x7f7f):
        # Include both signs and every magnitude up to this maximum.
        body = b"".join(bits.to_bytes(2, "little") for m in range(maximum + 1) for bits in (m, m | 0x8000))
        run = subprocess.run([native], input=body, capture_output=True, timeout=10, check=True)
        exponent = ref.minimum_weight_exponent(maximum)
        assert int.from_bytes(run.stdout[:4], "little", signed=True) == exponent
        assert int.from_bytes(run.stdout[4:6], "little") == maximum
        assert run.stdout[6:] == ref.convert_bf16le_chunk(body, exponent)


def test_native_fixture_rejects_invalid_or_oversized_before_output(native):
    for body in (b"", b"\x00", bytes.fromhex("803f807f"), bytes.fromhex("803fc17f"), b"\0" * 1_048_578):
        run = subprocess.run([native], input=body, capture_output=True, timeout=10)
        assert run.returncode != 0
        assert run.stdout == b""


def test_native_ingester_selects_scales_and_hashes_exact_source(native, tmp_path, monkeypatch):
    ref = reference()
    tensors = [("a", bytes.fromhex("803f0040") * 20000), ("b", bytes.fromhex("000040c0"))]
    source, metadata, specs = tiny_shard(tmp_path, tensors)
    output = tmp_path / "packed.i16"
    opens = []
    original = Path.open

    def opened(path, *args, **kwargs):
        if path == source:
            opens.append(path)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", opened)
    exponents = {}
    digests, packed_digest, count = ref._pack_private_weights_source_once(
        {source.name: source}, metadata, ["b", "a"], exponents, output,
        chunk_bytes=4096, shard_specs=specs, packed_bytes=sum(len(body) for _, body in tensors),
        native_packer=native.with_name("packer"),
    )
    expected = b"".join(ref.convert_bf16le_chunk(body, -13) for _, body in reversed(tensors))
    assert output.read_bytes() == expected
    assert exponents == {"a": -13, "b": -13}
    assert count == len(expected)
    assert packed_digest == ref._sha256_bytes(expected)
    assert digests == {source.name: specs[source.name]["lfs_sha256"]}
    assert opens == [source]
    assert not list(tmp_path.glob(".packed.i16.*"))


def test_native_ingester_discards_failed_or_unverified_results(native, tmp_path):
    ref = reference()
    for fault in ("hash", "nonfinite", "truncated", "existing", "worker"):
        directory = tmp_path / fault
        directory.mkdir()
        raw = bytes.fromhex("803f807f" if fault == "nonfinite" else "803f0040")
        source, metadata, specs = tiny_shard(directory, [("a", raw)])
        output = directory / "packed.i16"
        if fault == "hash":
            specs[source.name]["lfs_sha256"] = "00" * 32
        elif fault == "truncated":
            source.write_bytes(source.read_bytes()[:-1])
        elif fault == "existing":
            output.write_bytes(b"preserve")
        with pytest.raises((ref.IngestError, ref.BlockedError, OSError)):
            ref._pack_private_weights_source_once(
                {source.name: source}, metadata, ["a"], {}, output,
                chunk_bytes=2, shard_specs=specs, packed_bytes=4,
                native_packer=native.with_name("absent" if fault == "worker" else "packer"),
            )
        assert output.read_bytes() == b"preserve" if fault == "existing" else not output.exists()
        assert not list(directory.glob(".packed.i16.*"))


def test_native_worker_rejects_invalid_frames_before_emitting(native):
    worker = native.with_name("packer")
    for frame in (b"\x04", (0).to_bytes(8, "little"), (3).to_bytes(8, "little"),
                  (10).to_bytes(8, "little"), (4).to_bytes(8, "little") + b"\x00\x00"):
        run = subprocess.run([worker, "8"], input=frame, capture_output=True, timeout=10)
        assert run.returncode != 0
        assert run.stdout == b""
