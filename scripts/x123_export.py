#!/usr/bin/env python3
"""Model-agnostic synthetic exporter/calibration framework for X1--X3.

This is deliberately a toy architecture adapter.  It exercises the two
onboarding interfaces pinned by D2/D4 and emits small committed fixtures; it
does not parse, download, or claim to export a real gpt-oss checkpoint.

The shared framework owns:

* canonical BF16 -> symmetric i16 calibration with explicit power-of-two
  shifts (D4);
* canonical per-block MXFP4-code dequantization followed by i16 calibration
  and one recorded shift per source block (D2);
* deterministic artifact/config manifests and architecture goldens.

Run from the repository root with the checked-in numpy environment:

    .venv/bin/python scripts/x123_export.py
    .venv/bin/python scripts/x123_export.py --check
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import math
import struct
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Final

import numpy as np


REPO: Final = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT: Final = REPO / "tests" / "fixtures" / "x123"
SCHEMA: Final = 1
I16_MIN: Final = -32768
I16_MAX: Final = 32767

X1_T: Final = 31
X1_LAYERS: Final = 4
X1_D: Final = 48
X1_EXPERTS: Final = 32
X1_TOP_K: Final = 4
X1_ROUTER_REQUANT: Final = 8
X1_ROUTER_NORM: Final = 12
EXP_IN_LOG2: Final = 10
EXP_OUT_LOG2: Final = 12
RECIP_DEN_SHIFT: Final = 6
RECIP_LOG2: Final = 26


def sha256(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")


def round_half_away(values: np.ndarray) -> np.ndarray:
    """Rust/spec f64 round: nearest, with halves away from zero."""

    values = np.asarray(values, dtype=np.float64)
    return np.where(values >= 0, np.floor(values + 0.5), np.ceil(values - 0.5))


def bf16_roundtrip(values: np.ndarray) -> np.ndarray:
    """Canonical RNE float32 -> BF16 bits -> float32 source values."""

    source = np.asarray(values, dtype=np.float32)
    bits = source.view(np.uint32)
    rounded = bits + np.uint32(0x7FFF) + ((bits >> np.uint32(16)) & np.uint32(1))
    bf16 = (rounded >> np.uint32(16)).astype(np.uint16)
    return (bf16.astype(np.uint32) << np.uint32(16)).view(np.float32)


def choose_symmetric_shift(values: np.ndarray, headroom_bits: int = 0) -> int:
    """Largest power-of-two shift that fits a symmetric zero-point-0 i16."""

    maximum = float(np.max(np.abs(np.asarray(values, dtype=np.float64))))
    if not math.isfinite(maximum):
        raise ValueError("calibration source contains a non-finite value")
    if maximum == 0.0:
        return 0
    shift = math.floor(math.log2(I16_MAX / maximum)) - headroom_bits
    if not -31 <= shift <= 31:
        raise ValueError("calibration shift exceeds the signed 31-bit contract")
    return shift


@dataclasses.dataclass(frozen=True)
class CalibratedTensor:
    name: str
    source_kind: str
    values: np.ndarray
    shifts: tuple[int, ...]
    block_elems: int

    def __post_init__(self) -> None:
        if self.source_kind not in {"bf16", "mxfp4"}:
            raise ValueError("unknown source kind")
        if self.values.dtype != np.dtype("int16"):
            raise ValueError("proof artifact values must be i16")
        if self.values.size == 0 or self.block_elems <= 0:
            raise ValueError("empty tensor or invalid block size")
        expected = math.ceil(self.values.size / self.block_elems)
        if len(self.shifts) != expected:
            raise ValueError("one i16 shift is required per emitted block")


def calibrate_bf16(
    name: str,
    values: np.ndarray,
    *,
    shift: int | None = None,
    headroom_bits: int = 0,
) -> CalibratedTensor:
    """D4: BF16 source -> private i16 with an explicit tensor shift."""

    source = bf16_roundtrip(values).astype(np.float64)
    chosen = choose_symmetric_shift(source, headroom_bits) if shift is None else shift
    if not -31 <= chosen <= 31:
        raise ValueError("BF16 calibration shift is outside [-31,31]")
    quantized = round_half_away(source * (2.0**chosen))
    if np.any(quantized < I16_MIN) or np.any(quantized > I16_MAX):
        raise ValueError("BF16 calibration would clamp")
    out = np.ascontiguousarray(quantized.astype(np.int16))
    return CalibratedTensor(name, "bf16", out, (chosen,), out.size)


def dequantize_mxfp4(
    codes: np.ndarray,
    source_log2_shifts: tuple[int, ...],
    block_elems: int,
) -> np.ndarray:
    """Canonical toy MXFP4 interface: signed nibble code times 2^block shift."""

    codes = np.ascontiguousarray(codes, dtype=np.int8).reshape(-1)
    if block_elems <= 0 or len(source_log2_shifts) != math.ceil(codes.size / block_elems):
        raise ValueError("MXFP4 block geometry does not match its shift vector")
    if np.any(codes < -8) or np.any(codes > 7):
        raise ValueError("MXFP4 code lies outside the signed nibble domain")
    out = np.empty(codes.size, dtype=np.float64)
    for block, source_shift in enumerate(source_log2_shifts):
        begin = block * block_elems
        end = min(begin + block_elems, codes.size)
        out[begin:end] = codes[begin:end].astype(np.float64) * (2.0**source_shift)
    return out


def calibrate_mxfp4(
    name: str,
    codes: np.ndarray,
    source_log2_shifts: tuple[int, ...],
    block_elems: int,
    *,
    i16_shifts: tuple[int, ...] | None = None,
) -> CalibratedTensor:
    """D2: per-block dequantization, then per-block symmetric i16 shifts."""

    flat_codes = np.ascontiguousarray(codes, dtype=np.int8).reshape(-1)
    source = dequantize_mxfp4(flat_codes, source_log2_shifts, block_elems)
    n_blocks = len(source_log2_shifts)
    if i16_shifts is None:
        chosen = tuple(
            choose_symmetric_shift(source[b * block_elems : min((b + 1) * block_elems, source.size)])
            for b in range(n_blocks)
        )
    else:
        chosen = i16_shifts
    if len(chosen) != n_blocks or any(not -31 <= shift <= 31 for shift in chosen):
        raise ValueError("MXFP4 i16 shift vector does not match its source blocks")
    quantized = np.empty(source.size, dtype=np.int16)
    for block, shift in enumerate(chosen):
        begin = block * block_elems
        end = min(begin + block_elems, source.size)
        values = round_half_away(source[begin:end] * (2.0**shift))
        if np.any(values < I16_MIN) or np.any(values > I16_MAX):
            raise ValueError("MXFP4 calibration would clamp")
        quantized[begin:end] = values.astype(np.int16)
    return CalibratedTensor(
        name,
        "mxfp4",
        np.ascontiguousarray(quantized.reshape(np.asarray(codes).shape)),
        tuple(chosen),
        block_elems,
    )


class ArchitectureExporter(ABC):
    """Per-architecture adapter over shared calibration/artifact machinery."""

    architecture: str

    @abstractmethod
    def calibrated_tensors(self) -> list[CalibratedTensor]:
        raise NotImplementedError

    @abstractmethod
    def config(self) -> dict[str, object]:
        raise NotImplementedError

    @abstractmethod
    def goldens(self) -> dict[str, bytes]:
        raise NotImplementedError


def x1_router_arrays(layer: int, all_equal: bool = False) -> dict[str, np.ndarray]:
    """Independent numpy reference for the Rust X1 native witness."""

    x = np.zeros((X1_T, X1_D), dtype=np.int16)
    for row in range(X1_T):
        x[row, 0] = 256 + 16 * (row % 5)
        x[row, X1_D - 1] = (row % 9) - 4
    weights = np.zeros((X1_D, X1_EXPERTS), dtype=np.int16)
    if not all_equal:
        step = 28 + 2 * layer
        weights[0, :] = (np.arange(X1_EXPERTS, dtype=np.int16) - (X1_EXPERTS - 1)) * step
    raw = x.astype(np.int64) @ weights.astype(np.int64)
    requant = ((raw + (1 << (X1_ROUTER_REQUANT - 1))) >> X1_ROUTER_REQUANT).astype(np.int16)
    exp = np.empty_like(requant)
    for index, value in np.ndenumerate(requant):
        ev = round_half_away(
            np.asarray((1 << EXP_OUT_LOG2) * (2.0 ** (int(value) / float(1 << EXP_IN_LOG2))))
        ).item()
        exp[index] = min(int(ev), I16_MAX)
    denoms = exp.astype(np.int64).sum(axis=1)
    recip_in = (denoms >> RECIP_DEN_SHIFT).astype(np.int16)
    recips = np.empty(X1_T, dtype=np.int16)
    for row, value in enumerate(recip_in):
        den_back = (int(value) << RECIP_DEN_SHIFT) + (1 << (RECIP_DEN_SHIFT - 1))
        recips[row] = min(((1 << RECIP_LOG2) + den_back // 2) // den_back, I16_MAX)
    norm_acc = exp.astype(np.int64) * recips.astype(np.int64)[:, None]
    scores = ((norm_acc + (1 << (X1_ROUTER_NORM - 1))) >> X1_ROUTER_NORM).astype(np.int16)
    routes = np.empty((X1_T, X1_TOP_K), dtype=np.uint8)
    theta = np.empty(X1_T, dtype=np.int16)
    comparisons = np.empty((X1_T, X1_EXPERTS), dtype=np.uint16)
    for row in range(X1_T):
        ranked = sorted(range(X1_EXPERTS), key=lambda expert: (int(scores[row, expert]), expert), reverse=True)
        cutoff = ranked[X1_TOP_K - 1]
        rest = sorted(ranked[: X1_TOP_K - 1])
        route = [cutoff, *rest]
        routes[row, :] = route
        threshold = int(scores[row, cutoff])
        theta[row] = threshold
        selected_ids = set(route)
        for expert in range(X1_EXPERTS):
            score = int(scores[row, expert])
            if expert in selected_ids:
                value = score - threshold - int(expert < cutoff)
            else:
                value = threshold - score - int(expert > cutoff)
            if not 0 <= value < 1 << 16:
                raise AssertionError("honest X1 comparison escaped its one-limb bound")
            comparisons[row, expert] = value
    return {
        "x": x,
        "weights": weights,
        "raw_acc": raw,
        "requant": requant,
        "exp": exp,
        "denoms": denoms,
        "recip_in": recip_in,
        "recips": recips,
        "norm_acc": norm_acc,
        "scores": scores,
        "routes": routes,
        "theta": theta,
        "comparisons": comparisons,
    }


def x1_golden_bytes() -> bytes:
    out = bytearray(b"VOLTA-X1-GOLD-V1")
    out += struct.pack(
        "<9I",
        X1_T,
        X1_LAYERS,
        X1_D,
        X1_EXPERTS,
        X1_TOP_K,
        X1_ROUTER_REQUANT,
        X1_ROUTER_NORM,
        RECIP_DEN_SHIFT,
        EXP_OUT_LOG2,
    )
    order = (
        ("x", "<i2"),
        ("weights", "<i2"),
        ("raw_acc", "<i8"),
        ("requant", "<i2"),
        ("exp", "<i2"),
        ("denoms", "<i8"),
        ("recip_in", "<i2"),
        ("recips", "<i2"),
        ("norm_acc", "<i8"),
        ("scores", "<i2"),
        ("routes", "u1"),
        ("theta", "<i2"),
        ("comparisons", "<u2"),
    )
    for layer in range(X1_LAYERS):
        arrays = x1_router_arrays(layer)
        for name, dtype in order:
            out += np.ascontiguousarray(arrays[name], dtype=dtype).tobytes(order="C")
    tie = x1_router_arrays(0, all_equal=True)
    out += np.ascontiguousarray(tie["routes"][0], dtype="u1").tobytes()
    out += np.ascontiguousarray(tie["comparisons"][0], dtype="<u2").tobytes()
    return bytes(out)


class ToyMoeExporter(ArchitectureExporter):
    architecture = "volta-x123-toy-moe-v1"

    def calibrated_tensors(self) -> list[CalibratedTensor]:
        tensors: list[CalibratedTensor] = []
        for layer in range(X1_LAYERS):
            weights = x1_router_arrays(layer)["weights"].astype(np.float32)
            # Explicit shift zero keeps the emitted block byte-identical to
            # the Rust fixture; it still exercises D4's recorded power-of-two
            # calibration contract and leaves ample range headroom.
            tensors.append(calibrate_bf16(f"x1.router.{layer}.weight", weights, shift=0))
        attention = ((np.arange(X1_D * X1_D, dtype=np.int32) * 17 + 5) % 257 - 128).reshape(
            X1_D, X1_D
        )
        tensors.append(calibrate_bf16("x2.attention.0.weight", attention, shift=0))
        codes = ((np.arange(8 * 16, dtype=np.int16) * 5 + 3) % 16 - 8).astype(np.int8)
        tensors.append(
            calibrate_mxfp4(
                "x2.expert.0.gelu_up",
                codes.reshape(8, 16),
                source_log2_shifts=(-2, -1, 0, 1, -2, -1, 0, 1),
                block_elems=16,
                i16_shifts=(8, 7, 6, 5, 8, 7, 6, 5),
            )
        )
        return tensors

    def config(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "architecture": self.architecture,
            "contract": {
                "bf16": "D4 symmetric zero-point-0 BF16-to-i16 with explicit power-of-two shift",
                "mxfp4": "D2 per-block dequantize then symmetric i16; no 4-bit proof credit",
                "real_gpt_oss_export": False,
            },
            "x1": {
                "t": X1_T,
                "layers": X1_LAYERS,
                "d_model": X1_D,
                "experts": X1_EXPERTS,
                "top_k": X1_TOP_K,
                "router_requant": X1_ROUTER_REQUANT,
                "router_norm": X1_ROUTER_NORM,
                "tie_rule": "descending(score,expert_id); higher expert id wins",
                "d1_encoding": "[cutoff,remaining-selected-ascending]",
            },
            "x2": {
                "t": 7,
                "layers": 2,
                "d_model": 48,
                "d_ff": 80,
                "q_heads": 6,
                "kv_heads": 2,
                "head_dim": 8,
                "experts": 8,
                "top_k": 2,
                "vocab": 97,
                "thin_k": [1, 2],
            },
        }

    def goldens(self) -> dict[str, bytes]:
        return {"x1-router-v1.golden.bin": x1_golden_bytes()}


def artifact_bytes(tensors: list[CalibratedTensor]) -> tuple[bytes, list[dict[str, object]]]:
    out = bytearray(b"VOLTA-X123-ART1\0")
    ordered = sorted(tensors, key=lambda tensor: tensor.name)
    out += struct.pack("<II", SCHEMA, len(ordered))
    manifest: list[dict[str, object]] = []
    for tensor in ordered:
        name = tensor.name.encode("utf-8")
        values = np.ascontiguousarray(tensor.values, dtype="<i2")
        kind = 0 if tensor.source_kind == "bf16" else 1
        out += struct.pack("<HBB", len(name), kind, values.ndim)
        out += name
        out += struct.pack(f"<{values.ndim}I", *values.shape)
        out += struct.pack("<II", tensor.block_elems, len(tensor.shifts))
        out += struct.pack(f"<{len(tensor.shifts)}i", *tensor.shifts)
        out += struct.pack("<Q", values.size)
        offset = len(out)
        payload = values.tobytes(order="C")
        out += payload
        manifest.append(
            {
                "name": tensor.name,
                "source_kind": tensor.source_kind,
                "shape": list(values.shape),
                "block_elems": tensor.block_elems,
                "i16_shifts": list(tensor.shifts),
                "payload_offset_bytes": offset,
                "payload_bytes": len(payload),
                "payload_sha256": sha256(payload),
            }
        )
    return bytes(out), manifest


def generated_files(exporter: ArchitectureExporter | None = None) -> dict[str, bytes]:
    adapter = exporter or ToyMoeExporter()
    config = json_bytes(adapter.config())
    artifact, tensor_manifest = artifact_bytes(adapter.calibrated_tensors())
    goldens = adapter.goldens()
    script_hash = sha256(Path(__file__).read_bytes())
    files: dict[str, bytes] = {
        "toy-moe-v1.config.json": config,
        "toy-moe-v1.artifact.bin": artifact,
        **goldens,
    }
    manifest = {
        "schema": SCHEMA,
        "architecture": adapter.architecture,
        "framework": "per-architecture adapter + shared D2/D4 calibration/golden machinery",
        "exporter_sha256": script_hash,
        "real_gpt_oss_export": False,
        "tensors": tensor_manifest,
        "files": {
            name: {"bytes": len(blob), "sha256": sha256(blob)} for name, blob in sorted(files.items())
        },
    }
    files["toy-moe-v1.manifest.json"] = json_bytes(manifest)
    return files


def write_or_check(output: Path, check: bool) -> None:
    files = generated_files()
    if check:
        mismatches = [
            name for name, expected in files.items() if not (output / name).is_file() or (output / name).read_bytes() != expected
        ]
        if mismatches:
            raise SystemExit(f"x123 fixtures differ: {', '.join(mismatches)}")
        print(f"x123 fixtures OK: {len(files)} files")
        return
    output.mkdir(parents=True, exist_ok=True)
    for name, blob in files.items():
        (output / name).write_bytes(blob)
    print(f"wrote {len(files)} deterministic X1--X3 toy fixtures to {output}")


def self_test() -> None:
    bf16 = calibrate_bf16(
        "bf16",
        np.asarray([-2.5, -0.5, 0.0, 0.5, 2.5], dtype=np.float32),
        shift=3,
    )
    assert bf16.shifts == (3,)
    assert bf16.values.tolist() == [-20, -4, 0, 4, 20]
    try:
        calibrate_bf16("overflow", np.asarray([32767.0], dtype=np.float32), shift=1)
    except ValueError as error:
        assert "clamp" in str(error)
    else:
        raise AssertionError("D4 clamp smoke accepted")

    mxfp4 = calibrate_mxfp4(
        "mxfp4",
        np.asarray([1, -2, 3, -4, 1, -2, 3, -4], dtype=np.int8),
        source_log2_shifts=(-1, 1),
        block_elems=4,
        i16_shifts=(2, 0),
    )
    assert mxfp4.shifts == (2, 0)
    assert mxfp4.values.tolist() == [2, -4, 6, -8, 2, -4, 6, -8]
    try:
        dequantize_mxfp4(np.asarray([8], dtype=np.int8), (0,), 1)
    except ValueError as error:
        assert "signed nibble" in str(error)
    else:
        raise AssertionError("D2 invalid-code smoke accepted")

    normal = x1_router_arrays(0)
    tied = x1_router_arrays(0, all_equal=True)
    expected = np.asarray([28, 29, 30, 31], dtype=np.uint8)
    assert np.all(normal["routes"] == expected)
    assert tied["routes"][0].tolist() == expected.tolist()
    assert np.all(tied["comparisons"] == 0)
    assert int(normal["comparisons"].max()) <= 65535
    print("x123 exporter self-test OK")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    write_or_check(args.output_dir, args.check)


if __name__ == "__main__":
    main()
