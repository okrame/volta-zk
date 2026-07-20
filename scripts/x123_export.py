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
X2_T: Final = 7
X2_LAYERS: Final = 2
X2_D: Final = 48
X2_DFF: Final = 80
X2_Q_HEADS: Final = 6
X2_KV_HEADS: Final = 2
X2_HEAD_DIM: Final = 8
X2_QKV: Final = 80
X2_EXPERTS: Final = 8
X2_TOP_K: Final = 2
X2_VOCAB: Final = 97
X2_SHIFT: Final = 8
EXP_IN_LOG2: Final = 10
EXP_OUT_LOG2: Final = 12
RECIP_DEN_SHIFT: Final = 6
RECIP_LOG2: Final = 26
X2_RECIP_LOG2: Final = 22
X3_T: Final = 7
X3_T_PAD: Final = 8
X3_LAYERS: Final = 2
X3_D: Final = 48
X3_D_PAD: Final = 64
X3_DFF: Final = 80
X3_DFF_PAD: Final = 128
X3_Q_HEADS: Final = 6
X3_KV_HEADS: Final = 2
X3_GQA_GROUP: Final = 3
X3_HEAD_DIM: Final = 8
X3_QKV: Final = 80
X3_EXPERTS: Final = 8
X3_TOP_K: Final = 2
X3_VOCAB: Final = 97
X3_VOCAB_PAD: Final = 128
X3_SHIFT: Final = 8
X3_SILU_SHIFT: Final = 10
X3_ROPE_FRAC: Final = 14
X3_SCORE_SHIFT: Final = 22
X3_CLAMP_MIN: Final = -1024
X3_CLAMP_MAX: Final = 1024
X3_SINKS: Final = 2


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


def _requant(values: np.ndarray, shift: int, label: str) -> np.ndarray:
    values = np.asarray(values, dtype=np.int64)
    if shift > 16:
        stage1_shift = shift - 16
        stage1 = (values + (1 << (stage1_shift - 1))) >> stage1_shift
        rounded = (stage1 + (1 << 15)) >> 16
    else:
        rounded = (values + (1 << (shift - 1))) >> shift
    if np.any(rounded < I16_MIN) or np.any(rounded > I16_MAX):
        raise AssertionError(f"X2 {label} requant overflow")
    return rounded.astype(np.int16)


def _x2_luts() -> dict[str, np.ndarray]:
    signed = np.arange(1 << 16, dtype=np.uint16).view(np.int16).astype(np.float64)
    exp = round_half_away((1 << EXP_OUT_LOG2) * np.exp2(signed / float(1 << EXP_IN_LOG2)))
    exp = np.minimum(exp, I16_MAX).astype(np.int16)
    xr = signed / float(1 << 10)
    gelu = round_half_away(
        0.5
        * xr
        * (1.0 + np.tanh(0.797_884_560_802_865_4 * (xr + 0.044715 * xr * xr * xr)))
        * (1 << 10)
    )
    gelu = np.clip(gelu, I16_MIN, I16_MAX).astype(np.int16)
    ln_rsqrt = np.empty(1 << 16, dtype=np.int16)
    recip = np.empty(1 << 16, dtype=np.int16)
    for index in range(1 << 16):
        root = math.isqrt((index + 1) << 7)
        ln_rsqrt[index] = min(((1 << 18) + root // 2) // root, I16_MAX)
        den = (index << RECIP_DEN_SHIFT) + (1 << (RECIP_DEN_SHIFT - 1))
        recip[index] = min(((1 << X2_RECIP_LOG2) + den // 2) // den, I16_MAX)
    return {"exp": exp, "gelu": gelu, "ln_rsqrt": ln_rsqrt, "recip": recip}


def _x2_routes(layer: int) -> np.ndarray:
    base = np.asarray([[0, 1], [2, 3], [4, 5], [6, 7], [0, 2], [1, 4], [3, 5]], dtype=np.uint8)
    return ((base.astype(np.uint16) + layer) % X2_EXPERTS).astype(np.uint8)


def _x2_embedding() -> np.ndarray:
    out = np.zeros((X2_VOCAB, X2_D), dtype=np.int16)
    for token in range(X2_VOCAB):
        out[token, -1] = (token * 3 + 1) % 7 - 3
    for token in range(X2_T):
        out[token, token] = 1024
    # Canonical pad row for the seven-token low subcube used by the single
    # synthetic embedding PCS claim; it must not alias a live token-7 row.
    out[X2_T, :] = 0
    return out


def _x2_pattern(shape: tuple[int, ...], salt: int, modulus: int = 5) -> np.ndarray:
    size = math.prod(shape)
    if modulus == 5:
        values = [((index * (salt * 2 + 3) + 5 * salt + 1) % 5) - 2 for index in range(size)]
    else:
        values = [((index * (salt + 1) + 3 * salt + 1) % 3) - 1 for index in range(size)]
    return np.asarray(values, dtype=np.int16).reshape(shape)


def _x2_dense_weights(layer: int) -> dict[str, np.ndarray]:
    return {
        "qkv": _x2_pattern((X2_D, X2_QKV), 3 + layer),
        "attention": _x2_pattern((X2_D, X2_D), 7 + layer),
    }


def _x2_router_weights(layer: int) -> np.ndarray:
    out = np.full((X2_D, X2_EXPERTS), -1, dtype=np.int16)
    for token, route in enumerate(_x2_routes(layer)):
        out[token, :] = -64
        out[token, int(route[0])] = 160
        out[token, int(route[1])] = 192
    return out


def _x2_expert_weights(layer: int, expert: int) -> tuple[np.ndarray, np.ndarray]:
    return (
        _x2_pattern((X2_D, X2_DFF), 1 + 2 * layer + expert, 3),
        _x2_pattern((X2_DFF, X2_D), 5 + 3 * layer + expert, 3),
    )


def _x2_layer_norm(values: np.ndarray, luts: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
    values = np.asarray(values, dtype=np.int16)
    means = np.empty(X2_T, dtype=np.int64)
    variances = np.empty(X2_T, dtype=np.int64)
    rin = np.empty(X2_T, dtype=np.int64)
    rout = np.empty(X2_T, dtype=np.int16)
    acc = np.empty((X2_T, X2_D), dtype=np.int64)
    for row in range(X2_T):
        source = values[row].astype(np.int64)
        mean = (int(source.sum()) + X2_D // 2) // X2_D
        variance = (int(np.square(source - mean, dtype=np.int64).sum()) + X2_D // 2) // X2_D
        table_in = variance >> 7
        means[row] = mean
        variances[row] = variance
        rin[row] = table_in
        rout[row] = luts["ln_rsqrt"][table_in]
        acc[row] = (source - mean) * int(rout[row])
    return {
        "mean": means,
        "var": variances,
        "rin": rin,
        "rout": rout,
        "acc": acc,
        "out": _requant(acc, X2_SHIFT, "layer norm"),
    }


def _x2_dense_attention(
    source: np.ndarray,
    weights: dict[str, np.ndarray],
    luts: dict[str, np.ndarray],
) -> dict[str, np.ndarray]:
    ln1 = _x2_layer_norm(source, luts)
    qkv_acc = ln1["out"].astype(np.int64) @ weights["qkv"].astype(np.int64)
    qkv = _requant(qkv_acc, X2_SHIFT, "qkv")
    q = np.ascontiguousarray(qkv[:, :X2_D])
    k = np.ascontiguousarray(qkv[:, X2_D : X2_D + X2_KV_HEADS * X2_HEAD_DIM])
    v = np.ascontiguousarray(qkv[:, X2_D + X2_KV_HEADS * X2_HEAD_DIM :])
    score_acc: list[int] = []
    score_q: list[int] = []
    exp_out: list[int] = []
    denoms: list[int] = []
    recips: list[int] = []
    softmax: list[int] = []
    av_acc = np.zeros((X2_T, X2_D), dtype=np.int64)
    av_q = np.zeros((X2_T, X2_D), dtype=np.int16)
    for head in range(X2_Q_HEADS):
        kv_head = head // (X2_Q_HEADS // X2_KV_HEADS)
        qh = q[:, head * X2_HEAD_DIM : (head + 1) * X2_HEAD_DIM]
        kh = k[:, kv_head * X2_HEAD_DIM : (kv_head + 1) * X2_HEAD_DIM]
        full_scores = qh.astype(np.int64) @ kh.astype(np.int64).T
        w = np.zeros((X2_T, X2_T), dtype=np.int16)
        for row in range(X2_T):
            row_scores = _requant(full_scores[row, : row + 1], X2_SHIFT, "scores")
            score_acc.extend(int(value) for value in full_scores[row, : row + 1])
            score_q.extend(int(value) for value in row_scores)
            row_exp = luts["exp"][row_scores.astype(np.uint16)]
            exp_out.extend(int(value) for value in row_exp)
            denom = int(row_exp.astype(np.int64).sum())
            reciprocal = int(luts["recip"][denom >> RECIP_DEN_SHIFT])
            denoms.append(denom)
            recips.append(reciprocal)
            row_w = _requant(row_exp.astype(np.int64) * reciprocal, X2_SHIFT, "softmax norm")
            softmax.extend(int(value) for value in row_w)
            w[row, : row + 1] = row_w
        vh = v[:, kv_head * X2_HEAD_DIM : (kv_head + 1) * X2_HEAD_DIM]
        head_acc = w.astype(np.int64) @ vh.astype(np.int64)
        av_acc[:, head * X2_HEAD_DIM : (head + 1) * X2_HEAD_DIM] = head_acc
        av_q[:, head * X2_HEAD_DIM : (head + 1) * X2_HEAD_DIM] = _requant(
            head_acc, X2_SHIFT, "av"
        )
    projection_acc = av_q.astype(np.int64) @ weights["attention"].astype(np.int64)
    projection = _requant(projection_acc, X2_SHIFT, "attention projection")
    residual = source.astype(np.int32) + projection.astype(np.int32)
    if np.any(residual < I16_MIN) or np.any(residual > I16_MAX):
        raise AssertionError("X2 attention residual overflow")
    attention_out = residual.astype(np.int16)
    ln2 = _x2_layer_norm(attention_out, luts)
    return {
        "x": np.ascontiguousarray(source),
        "ln1": ln1,
        "qkv_acc": qkv_acc,
        "q": q,
        "k": k,
        "v": v,
        "score_acc": np.asarray(score_acc, dtype=np.int64),
        "score_q": np.asarray(score_q, dtype=np.int16),
        "exp": np.asarray(exp_out, dtype=np.int16),
        "denoms": np.asarray(denoms, dtype=np.int64),
        "recips": np.asarray(recips, dtype=np.int16),
        "softmax": np.asarray(softmax, dtype=np.int16),
        "av_acc": av_acc,
        "av_q": av_q,
        "projection_acc": projection_acc,
        "projection": projection,
        "attention_out": attention_out,
        "ln2": ln2,
    }


def _x2_router(
    source: np.ndarray,
    weights: np.ndarray,
    expected: np.ndarray,
    luts: dict[str, np.ndarray],
) -> dict[str, np.ndarray]:
    acc = source.astype(np.int64) @ weights.astype(np.int64)
    scores = _requant(acc, X2_SHIFT, "router")
    exp = luts["exp"][scores.astype(np.uint16)]
    denoms = exp.astype(np.int64).sum(axis=1)
    rin = (denoms >> RECIP_DEN_SHIFT).astype(np.int16)
    recips = luts["recip"][rin.astype(np.uint16)]
    routes = np.empty((X2_T, X2_TOP_K), dtype=np.uint8)
    theta = np.empty(X2_T, dtype=np.int16)
    comparisons = np.empty((X2_T, X2_EXPERTS), dtype=np.uint16)
    route_weights = np.empty((X2_T, X2_TOP_K), dtype=np.int16)
    for row in range(X2_T):
        ranked = sorted(
            range(X2_EXPERTS), key=lambda expert: (int(scores[row, expert]), expert), reverse=True
        )
        route = [ranked[1], ranked[0]]
        routes[row] = route
        cutoff = route[0]
        threshold = int(scores[row, cutoff])
        theta[row] = threshold
        for expert in range(X2_EXPERTS):
            if expert in route:
                value = int(scores[row, expert]) - threshold - int(expert < cutoff)
            else:
                value = threshold - int(scores[row, expert]) - int(expert > cutoff)
            if not 0 <= value < 1 << 16:
                raise AssertionError("X2 top-k comparison escaped u16")
            comparisons[row, expert] = value
        for slot, expert in enumerate(route):
            route_weights[row, slot] = _requant(
                np.asarray(int(exp[row, expert]) * int(recips[row]), dtype=np.int64),
                X2_SHIFT,
                "router weight",
            )
    if not np.array_equal(routes, expected):
        raise AssertionError("numpy router missed the pinned X2 route fixture")
    return {
        "acc": acc,
        "scores": scores,
        "exp": exp,
        "denoms": denoms,
        "rin": rin,
        "recips": recips,
        "routes": routes,
        "theta": theta,
        "comparisons": comparisons,
        "route_weights": route_weights,
    }


def _x2_experts(
    source: np.ndarray,
    routes: np.ndarray,
    layer: int,
    luts: dict[str, np.ndarray],
) -> tuple[list[dict[str, np.ndarray]], np.ndarray]:
    jobs: list[list[tuple[int, int]]] = [[] for _ in range(X2_EXPERTS)]
    for token in range(X2_T):
        for slot in range(X2_TOP_K):
            jobs[int(routes[token, slot])].append((token, slot))
    route_values = np.empty((X2_T, X2_TOP_K, X2_D), dtype=np.int16)
    experts: list[dict[str, np.ndarray]] = []
    for expert, rows in enumerate(jobs):
        up_weight, down_weight = _x2_expert_weights(layer, expert)
        gathered = np.ascontiguousarray(np.stack([source[token] for token, _ in rows]))
        up_acc = gathered.astype(np.int64) @ up_weight.astype(np.int64)
        up_q = _requant(up_acc, X2_SHIFT, "expert up")
        gelu = luts["gelu"][up_q.astype(np.uint16)]
        down_acc = gelu.astype(np.int64) @ down_weight.astype(np.int64)
        down_q = _requant(down_acc, X2_SHIFT, "expert down")
        for job_row, (token, slot) in enumerate(rows):
            route_values[token, slot] = down_q[job_row]
        experts.append(
            {
                "rows": np.asarray(rows, dtype=np.uint8),
                "up_weight": up_weight,
                "down_weight": down_weight,
                "gathered": gathered,
                "up_acc": up_acc,
                "up_q": up_q,
                "gelu": gelu,
                "down_acc": down_acc,
                "down_q": down_q,
            }
        )
    return experts, route_values


def x2_moe_arrays() -> dict[str, object]:
    luts = _x2_luts()
    tokens = np.arange(X2_T, dtype=np.uint16)
    embedding = _x2_embedding()
    embedding_acc = embedding[tokens].astype(np.int64) << X2_SHIFT
    current = _requant(embedding_acc, X2_SHIFT, "embedding")
    layers: list[dict[str, object]] = []
    seam_acc = np.empty(0, dtype=np.int64)
    seam_out = np.empty(0, dtype=np.int16)
    for layer in range(X2_LAYERS):
        dense_weight = _x2_dense_weights(layer)
        dense = _x2_dense_attention(current, dense_weight, luts)
        router_weight = _x2_router_weights(layer)
        router = _x2_router(current, router_weight, _x2_routes(layer), luts)
        experts, route_values = _x2_experts(dense["ln2"]["out"], router["routes"], layer, luts)
        combine_acc = (dense["projection"].astype(np.int64) << X2_SHIFT).copy()
        for slot in range(X2_TOP_K):
            combine_acc += (
                router["route_weights"][:, slot].astype(np.int64)[:, None]
                * route_values[:, slot].astype(np.int64)
            )
        combine_q = _requant(combine_acc, X2_SHIFT, "MoE combine")
        output_wide = current.astype(np.int32) + combine_q.astype(np.int32)
        if np.any(output_wide < I16_MIN) or np.any(output_wide > I16_MAX):
            raise AssertionError("X2 layer residual overflow")
        output = output_wide.astype(np.int16)
        layers.append(
            {
                "dense_weight": dense_weight,
                "router_weight": router_weight,
                "dense": dense,
                "router": router,
                "experts": experts,
                "route_values": route_values,
                "combine_acc": combine_acc,
                "combine_q": combine_q,
                "output": output,
            }
        )
        if layer + 1 < X2_LAYERS:
            seam_acc = output.astype(np.int64) << X2_SHIFT
            seam_out = _requant(seam_acc, X2_SHIFT, "residual seam")
            current = seam_out
        else:
            current = output
    output_weight = np.asarray(
        [((index * 7 + 3) % 5) - 2 for index in range(X2_D * X2_VOCAB)], dtype=np.int16
    ).reshape(X2_D, X2_VOCAB)
    final_input = current[-1].copy()
    final_ln = _x2_layer_norm(np.repeat(final_input[None, :], X2_T, axis=0), luts)
    # Rust's final norm computes only one row; take the identical first row.
    final = {
        "input": final_input,
        "mean": int(final_ln["mean"][0]),
        "var": int(final_ln["var"][0]),
        "rin": int(final_ln["rin"][0]),
        "rout": int(final_ln["rout"][0]),
        "acc": final_ln["acc"][0],
        "out": final_ln["out"][0],
    }
    final["logits"] = final["out"].astype(np.int64) @ output_weight.astype(np.int64)
    return {
        "tokens": tokens,
        "embedding": embedding,
        "embedding_acc": embedding_acc,
        "embedding_out": _requant(embedding_acc, X2_SHIFT, "embedding"),
        "layers": layers,
        "seam_acc": seam_acc,
        "seam_out": seam_out,
        "output_weight": output_weight,
        "final": final,
    }


def _append_array(out: bytearray, values: np.ndarray, dtype: str) -> None:
    out += np.ascontiguousarray(values, dtype=dtype).tobytes(order="C")


def x2_golden_bytes() -> bytes:
    fixture = x2_moe_arrays()
    out = bytearray(b"VOLTA-X2-GOLD-V1")
    out += struct.pack(
        "<11I",
        X2_T,
        X2_LAYERS,
        X2_D,
        X2_DFF,
        X2_Q_HEADS,
        X2_KV_HEADS,
        X2_HEAD_DIM,
        X2_EXPERTS,
        X2_TOP_K,
        X2_VOCAB,
        X2_SHIFT,
    )
    _append_array(out, fixture["tokens"], "<u2")
    _append_array(out, fixture["embedding"], "<i2")
    _append_array(out, fixture["embedding_acc"], "<i8")
    _append_array(out, fixture["embedding_out"], "<i2")
    for layer in fixture["layers"]:
        dense = layer["dense"]
        router = layer["router"]
        _append_array(out, layer["dense_weight"]["qkv"], "<i2")
        _append_array(out, layer["dense_weight"]["attention"], "<i2")
        _append_array(out, layer["router_weight"], "<i2")
        _append_array(out, dense["x"], "<i2")
        for name, dtype in (
            ("mean", "<i8"), ("var", "<i8"), ("rin", "<i8"), ("rout", "<i2"),
            ("acc", "<i8"), ("out", "<i2")
        ):
            _append_array(out, dense["ln1"][name], dtype)
        for name, dtype in (
            ("qkv_acc", "<i8"), ("q", "<i2"), ("k", "<i2"), ("v", "<i2"),
            ("score_acc", "<i8"), ("score_q", "<i2"), ("exp", "<i2"),
            ("denoms", "<i8"), ("recips", "<i2"), ("softmax", "<i2"),
            ("av_acc", "<i8"), ("av_q", "<i2"), ("projection_acc", "<i8"),
            ("projection", "<i2"), ("attention_out", "<i2"),
        ):
            _append_array(out, dense[name], dtype)
        for name, dtype in (
            ("mean", "<i8"), ("var", "<i8"), ("rin", "<i8"), ("rout", "<i2"),
            ("acc", "<i8"), ("out", "<i2")
        ):
            _append_array(out, dense["ln2"][name], dtype)
        for name, dtype in (
            ("acc", "<i8"), ("scores", "<i2"), ("exp", "<i2"),
            ("denoms", "<i8"), ("rin", "<i2"), ("recips", "<i2"),
            ("routes", "u1"), ("theta", "<i2"), ("comparisons", "<u2"),
            ("route_weights", "<i2"),
        ):
            _append_array(out, router[name], dtype)
        for expert in layer["experts"]:
            out += struct.pack("<I", expert["rows"].shape[0])
            _append_array(out, expert["rows"], "u1")
            for name, dtype in (
                ("up_weight", "<i2"), ("down_weight", "<i2"), ("gathered", "<i2"),
                ("up_acc", "<i8"), ("up_q", "<i2"), ("gelu", "<i2"),
                ("down_acc", "<i8"), ("down_q", "<i2"),
            ):
                _append_array(out, expert[name], dtype)
        for name, dtype in (
            ("route_values", "<i2"), ("combine_acc", "<i8"),
            ("combine_q", "<i2"), ("output", "<i2"),
        ):
            _append_array(out, layer[name], dtype)
    _append_array(out, fixture["seam_acc"], "<i8")
    _append_array(out, fixture["seam_out"], "<i2")
    _append_array(out, fixture["output_weight"], "<i2")
    final = fixture["final"]
    _append_array(out, final["input"], "<i2")
    out += struct.pack("<qq", final["mean"], final["var"])
    out += struct.pack("<hh", final["rin"], final["rout"])
    _append_array(out, final["acc"], "<i8")
    _append_array(out, final["out"], "<i2")
    _append_array(out, final["logits"], "<i8")
    _append_array(out, fixture["layers"][-1]["output"], "<i2")
    _append_array(out, fixture["layers"][-1]["output"], "<i2")
    return bytes(out)


def _x3_luts() -> dict[str, np.ndarray]:
    """Independent table contents for the X3 op pack."""

    out = _x2_luts()
    silu = np.empty(1 << 16, dtype=np.int16)
    clamp = np.empty(1 << 16, dtype=np.int16)
    for bits in range(1 << 16):
        value = int(np.asarray(bits, dtype=np.uint16).view(np.int16))
        x = value / float(1 << X3_SILU_SHIFT)
        rounded = math.floor(x / (1.0 + math.exp(-x)) * (1 << X3_SILU_SHIFT) + 0.5)
        if x < 0:
            raw = x / (1.0 + math.exp(-x)) * (1 << X3_SILU_SHIFT)
            rounded = math.ceil(raw - 0.5)
        silu[bits] = min(max(rounded, I16_MIN), I16_MAX)
        clamp[bits] = min(max(value, X3_CLAMP_MIN), X3_CLAMP_MAX)
    out["silu"] = silu
    out["clamp"] = clamp
    return out


def _x3_routes(layer: int) -> np.ndarray:
    base = np.asarray([[0, 1], [2, 3], [4, 5], [6, 7], [0, 2], [1, 4], [3, 5]], dtype=np.uint8)
    return ((base.astype(np.uint16) + layer) % X3_EXPERTS).astype(np.uint8)


def _x3_sparse_projection(rows: int, cols: int, salt: int, magnitude: int) -> np.ndarray:
    out = np.zeros((rows, cols), dtype=np.int16)
    for col in range(cols):
        row = (col * (salt * 2 + 1) + salt) % rows
        sign = 1 if (col + salt) % 2 == 0 else -1
        out[row, col] = sign * magnitude
        row2 = (row + 7 + salt) % rows
        out[row2, col] = -sign
    return out


def _x3_layer_weights(layer: int) -> dict[str, object]:
    experts: list[dict[str, np.ndarray]] = []
    for expert in range(X3_EXPERTS):
        salt = 1 + 3 * layer + expert
        experts.append(
            {
                "gate": _x3_sparse_projection(X3_D, X3_DFF, salt, 96),
                "up": _x3_sparse_projection(X3_D, X3_DFF, salt + 5, 112),
                "down": _x3_sparse_projection(X3_DFF, X3_D, salt + 11, 2),
            }
        )
    return {
        "qkv": _x3_sparse_projection(X3_D, X3_QKV, 3 + layer, 2),
        "attention": _x3_sparse_projection(X3_D, X3_D, 7 + layer, 2),
        "experts": experts,
    }


def _x3_embedding_weights() -> tuple[np.ndarray, np.ndarray]:
    wte = np.zeros((X3_VOCAB, X3_D), dtype=np.int16)
    for token in range(X3_VOCAB):
        wte[token, -1] = (token * 3 + 1) % 7 - 3
    for token in range(X3_T):
        wte[token, token] = 1024
    wpe = np.asarray(
        [((index * 5 + 3) % 9) - 4 for index in range(X3_T * X3_D)], dtype=np.int16
    ).reshape(X3_T, X3_D)
    return wte, wpe


def _x3_source_padding() -> np.ndarray:
    count = (
        X3_D_PAD
        + X3_D_PAD
        + X3_T_PAD * (X3_D_PAD - X3_D)
        + X3_T_PAD * (X3_DFF_PAD - X3_DFF)
        + (X3_VOCAB_PAD - X3_VOCAB) * X3_D_PAD
    )
    return np.arange(1001, 1001 + count, dtype=np.int16)


def _x3_rmsnorm(values: np.ndarray, luts: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
    source = np.ascontiguousarray(values, dtype=np.int16).reshape(-1, X3_D)
    rows = source.shape[0]
    sums = np.empty(rows, dtype=np.int64)
    means = np.empty(rows, dtype=np.int64)
    rin = np.empty(rows, dtype=np.int16)
    rout = np.empty(rows, dtype=np.int16)
    acc = np.empty_like(source, dtype=np.int64)
    for row in range(rows):
        wide = source[row].astype(np.int64)
        total = int(np.square(wide, dtype=np.int64).sum())
        mean = (total + X3_D // 2) // X3_D
        table_in = mean >> 7
        if not 0 <= table_in < 1 << 16:
            raise AssertionError("X3 RMS rsqrt input overflow")
        sums[row] = total
        means[row] = mean
        rin[row] = table_in
        rout[row] = luts["ln_rsqrt"][table_in]
        acc[row] = wide * int(rout[row])
    return {
        "input": source,
        "sum_squares": sums,
        "mean_square": means,
        "rsqrt_in": rin,
        "rsqrt_out": rout,
        "acc": acc,
        "output": _requant(acc, X3_SHIFT, "RMSNorm"),
    }


def _x3_rope_coefficients() -> np.ndarray:
    values: list[int] = []
    for delta in range(-6, 7):
        for pair in range(X3_HEAD_DIM // 2):
            frequency = 10000.0 ** (-(2 * pair) / X3_HEAD_DIM)
            angle = delta * frequency
            for coefficient in (math.cos(angle), math.sin(angle)):
                scaled = coefficient * (1 << X3_ROPE_FRAC)
                rounded = math.floor(scaled + 0.5) if scaled >= 0 else math.ceil(scaled - 0.5)
                values.append(rounded)
    return np.asarray(values, dtype=np.int16)


def _x3_rope_coeff(coefficients: np.ndarray, delta: int, pair: int) -> tuple[int, int]:
    index = ((delta + 6) * (X3_HEAD_DIM // 2) + pair) * 2
    return int(coefficients[index]), int(coefficients[index + 1])


def _x3_attention(
    source: np.ndarray,
    layer: int,
    weights: dict[str, object],
    luts: dict[str, np.ndarray],
    rope_coefficients: np.ndarray,
) -> dict[str, object]:
    rms1 = _x3_rmsnorm(source, luts)
    qkv_acc = rms1["output"].astype(np.int64) @ weights["qkv"].astype(np.int64)
    qkv = _requant(qkv_acc, X3_SHIFT, "QKV")
    q = np.ascontiguousarray(qkv[:, :X3_D])
    k = np.ascontiguousarray(qkv[:, X3_D : X3_D + X3_KV_HEADS * X3_HEAD_DIM])
    v = np.ascontiguousarray(qkv[:, X3_D + X3_KV_HEADS * X3_HEAD_DIM :])
    lo = np.asarray(
        [0 if layer == 0 else max(0, row + 1 - 4) for row in range(X3_T)], dtype=np.uint32
    )
    hi = np.arange(1, X3_T + 1, dtype=np.uint32)
    rect_shape = (X3_Q_HEADS, X3_T_PAD, X3_T_PAD)
    real_mask = np.zeros(rect_shape, dtype=np.uint8)
    score_acc_rect = np.zeros(rect_shape, dtype=np.int64)
    zero_indices = np.flatnonzero(luts["exp"] == 0)
    if zero_indices.size == 0:
        raise AssertionError("X3 Exp table lacks a zero padding input")
    pad_score = int(np.asarray(int(zero_indices[0]), dtype=np.uint16).view(np.int16))
    score_q_rect = np.full(rect_shape, pad_score, dtype=np.int16)
    exp_rect = np.zeros(rect_shape, dtype=np.int16)
    grouped_k_reads: list[int] = []
    grouped_v_reads: list[int] = []
    rope_folded_k: list[int] = []
    rope_pair_terms: list[int] = []
    score_acc_real: list[int] = []
    score_q_real: list[int] = []
    for head in range(X3_Q_HEADS):
        kv_head = head // X3_GQA_GROUP
        for row in range(X3_T):
            for key_row in range(int(lo[row]), int(hi[row])):
                real_mask[head, row, key_row] = 1
                delta = key_row - row
                score = 0
                for pair in range(X3_HEAD_DIM // 2):
                    cos, sin = _x3_rope_coeff(rope_coefficients, delta, pair)
                    q_base = head * X3_HEAD_DIM + 2 * pair
                    kv_base = kv_head * X3_HEAD_DIM + 2 * pair
                    qe, qo = int(q[row, q_base]), int(q[row, q_base + 1])
                    ke, ko = int(k[key_row, kv_base]), int(k[key_row, kv_base + 1])
                    kfe = ke * cos - ko * sin
                    kfo = ke * sin + ko * cos
                    te, to = qe * kfe, qo * kfo
                    grouped_k_reads.extend((ke, ko))
                    grouped_v_reads.extend((int(v[key_row, kv_base]), int(v[key_row, kv_base + 1])))
                    rope_folded_k.extend((kfe, kfo))
                    rope_pair_terms.extend((te, to))
                    score += te + to
                quantized = int(_requant(np.asarray([score]), X3_SCORE_SHIFT, "RoPE score")[0])
                score_acc_rect[head, row, key_row] = score
                score_q_rect[head, row, key_row] = quantized
                exp_rect[head, row, key_row] = luts["exp"][quantized & 0xFFFF]
                score_acc_real.append(score)
                score_q_real.append(quantized)
    sink_scores: list[int] = []
    sink_exp: list[int] = []
    denoms = np.zeros((X3_Q_HEADS, X3_T), dtype=np.int64)
    recip_in = np.zeros((X3_Q_HEADS, X3_T), dtype=np.int16)
    recips = np.zeros((X3_Q_HEADS, X3_T), dtype=np.int16)
    for head in range(X3_Q_HEADS):
        for row in range(X3_T):
            denom = int(exp_rect[head, row, int(lo[row]) : int(hi[row])].astype(np.int64).sum())
            for sink in range(X3_SINKS):
                score = (3 * layer + 2 * head + sink - 6) * 16
                exponent = int(luts["exp"][score & 0xFFFF])
                sink_scores.append(score)
                sink_exp.append(exponent)
                denom += exponent
            denoms[head, row] = denom
            table_in = denom >> RECIP_DEN_SHIFT
            recip_in[head, row] = table_in
            recips[head, row] = luts["recip"][table_in]
    norm_acc_rect = np.zeros(rect_shape, dtype=np.int64)
    weights_rect = np.zeros(rect_shape, dtype=np.int16)
    for head in range(X3_Q_HEADS):
        for row in range(X3_T):
            reciprocal = int(recips[head, row])
            for key_row in range(int(lo[row]), int(hi[row])):
                acc = int(exp_rect[head, row, key_row]) * reciprocal
                norm_acc_rect[head, row, key_row] = acc
                weights_rect[head, row, key_row] = _requant(
                    np.asarray([acc]), X3_SHIFT, "softmax weight"
                )[0]
    av_acc = np.zeros((X3_T, X3_D), dtype=np.int64)
    av_q = np.zeros((X3_T, X3_D), dtype=np.int16)
    for head in range(X3_Q_HEADS):
        kv_head = head // X3_GQA_GROUP
        for row in range(X3_T):
            for dim in range(X3_HEAD_DIM):
                acc = 0
                for key_row in range(int(lo[row]), int(hi[row])):
                    acc += int(weights_rect[head, row, key_row]) * int(
                        v[key_row, kv_head * X3_HEAD_DIM + dim]
                    )
                index = head * X3_HEAD_DIM + dim
                av_acc[row, index] = acc
                av_q[row, index] = _requant(np.asarray([acc]), X3_SHIFT, "AV")[0]
    projection_acc = av_q.astype(np.int64) @ weights["attention"].astype(np.int64)
    projection_q = _requant(projection_acc, X3_SHIFT, "attention projection")
    output_wide = np.asarray(source, dtype=np.int32) + projection_q.astype(np.int32)
    if np.any(output_wide < I16_MIN) or np.any(output_wide > I16_MAX):
        raise AssertionError("X3 attention residual overflow")
    return {
        "rms1": rms1,
        "qkv_acc": qkv_acc,
        "qkv": qkv,
        "q": q,
        "k": k,
        "v": v,
        "lo": lo,
        "hi": hi,
        "real_mask": real_mask,
        "grouped_k_reads": np.asarray(grouped_k_reads, dtype=np.int16),
        "grouped_v_reads": np.asarray(grouped_v_reads, dtype=np.int16),
        "rope_folded_k": np.asarray(rope_folded_k, dtype=np.int64),
        "rope_pair_terms": np.asarray(rope_pair_terms, dtype=np.int64),
        "score_acc_rect": score_acc_rect,
        "score_acc_real": np.asarray(score_acc_real, dtype=np.int64),
        "score_q_rect": score_q_rect,
        "score_q_real": np.asarray(score_q_real, dtype=np.int16),
        "exp_rect": exp_rect,
        "sink_scores": np.asarray(sink_scores, dtype=np.int16),
        "sink_exp": np.asarray(sink_exp, dtype=np.int16),
        "denoms": denoms,
        "recip_in": recip_in,
        "recips": recips,
        "norm_acc_rect": norm_acc_rect,
        "weights_rect": weights_rect,
        "av_acc": av_acc,
        "av_q": av_q,
        "projection_acc": projection_acc,
        "projection_q": projection_q,
        "output": output_wide.astype(np.int16),
    }


def _x3_experts(
    source: np.ndarray,
    routes: np.ndarray,
    weights: list[dict[str, np.ndarray]],
    luts: dict[str, np.ndarray],
) -> tuple[list[dict[str, np.ndarray]], np.ndarray]:
    jobs: list[list[tuple[int, int]]] = [[] for _ in range(X3_EXPERTS)]
    for token in range(X3_T):
        for slot in range(X3_TOP_K):
            jobs[int(routes[token, slot])].append((token, slot))
    route_values = np.zeros((X3_T, X3_TOP_K, X3_D), dtype=np.int16)
    witnesses: list[dict[str, np.ndarray]] = []
    for expert, rows in enumerate(jobs):
        if not rows:
            raise AssertionError("X3 synthetic routes must exercise every expert")
        gathered = np.ascontiguousarray(np.stack([source[token] for token, _ in rows]))
        gate_acc = gathered.astype(np.int64) @ weights[expert]["gate"].astype(np.int64)
        gate_q = _requant(gate_acc, X3_SHIFT, "expert gate")
        up_acc = gathered.astype(np.int64) @ weights[expert]["up"].astype(np.int64)
        up_q = _requant(up_acc, X3_SHIFT, "expert up")
        gate_clamped = luts["clamp"][gate_q.astype(np.uint16)]
        up_clamped = luts["clamp"][up_q.astype(np.uint16)]
        silu = luts["silu"][gate_clamped.astype(np.uint16)]
        product_acc = silu.astype(np.int64) * up_clamped.astype(np.int64)
        product_q = _requant(product_acc, X3_SILU_SHIFT, "SwiGLU product")
        down_acc = product_q.astype(np.int64) @ weights[expert]["down"].astype(np.int64)
        down_q = _requant(down_acc, X3_SHIFT, "expert down")
        for job_row, (token, slot) in enumerate(rows):
            route_values[token, slot] = down_q[job_row]
        witnesses.append(
            {
                "rows": np.asarray(rows, dtype=np.uint8),
                "gathered": gathered,
                "gate_acc": gate_acc,
                "gate_q": gate_q,
                "gate_clamped": gate_clamped,
                "up_acc": up_acc,
                "up_q": up_q,
                "up_clamped": up_clamped,
                "silu": silu,
                "product_acc": product_acc,
                "product_q": product_q,
                "down_acc": down_acc,
                "down_q": down_q,
            }
        )
    return witnesses, route_values


def _x3_clamp_probe(luts: dict[str, np.ndarray]) -> dict[str, np.ndarray]:
    gate_in = np.asarray([-2048, -1025, -1024, -17, 0, 23, 1024, 1025, 2048], dtype=np.int16)
    up_in = np.asarray([2048, 1025, 1024, 23, 0, -17, -1024, -1025, -2048], dtype=np.int16)
    gate_clamped = luts["clamp"][gate_in.astype(np.uint16)]
    up_clamped = luts["clamp"][up_in.astype(np.uint16)]
    silu = luts["silu"][gate_clamped.astype(np.uint16)]
    product_acc = silu.astype(np.int64) * up_clamped.astype(np.int64)
    return {
        "gate_in": gate_in,
        "up_in": up_in,
        "gate_clamped": gate_clamped,
        "up_clamped": up_clamped,
        "silu": silu,
        "product_acc": product_acc,
        "product_q": _requant(product_acc, X3_SILU_SHIFT, "clamp probe product"),
    }


def x3_ops_arrays(*, admit_poison: bool = False) -> dict[str, object]:
    luts = _x3_luts()
    rope_coefficients = _x3_rope_coefficients()
    tokens = np.arange(X3_T, dtype=np.uint16)
    wte, wpe = _x3_embedding_weights()
    source_padding = _x3_source_padding()
    canonical_padding = source_padding.copy() if admit_poison else np.zeros_like(source_padding)
    embedding_acc = (wte[tokens].astype(np.int64) + wpe.astype(np.int64)) << X3_SHIFT
    embedding_out = _requant(embedding_acc, X3_SHIFT, "embedding")
    weights = [_x3_layer_weights(layer) for layer in range(X3_LAYERS)]
    layers: list[dict[str, object]] = []
    current = embedding_out
    seam_acc = np.empty(0, dtype=np.int64)
    seam_out = np.empty(0, dtype=np.int16)
    for layer in range(X3_LAYERS):
        attention = _x3_attention(current, layer, weights[layer], luts, rope_coefficients)
        rms2 = _x3_rmsnorm(attention["output"], luts)
        routes = _x3_routes(layer)
        route_weights = np.full((X3_T, X3_TOP_K), 128, dtype=np.int16)
        experts, route_values = _x3_experts(
            rms2["output"], routes, weights[layer]["experts"], luts
        )
        combine_acc = attention["projection_q"].astype(np.int64) << X3_SHIFT
        for slot in range(X3_TOP_K):
            combine_acc += route_weights[:, slot].astype(np.int64)[:, None] * route_values[:, slot].astype(
                np.int64
            )
        combine_q = _requant(combine_acc, X3_SHIFT, "MoE combine")
        output_wide = current.astype(np.int32) + combine_q.astype(np.int32)
        if np.any(output_wide < I16_MIN) or np.any(output_wide > I16_MAX):
            raise AssertionError("X3 layer residual overflow")
        output = output_wide.astype(np.int16)
        layers.append(
            {
                "input": current.copy(),
                "attention": attention,
                "rms2": rms2,
                "routes": routes,
                "route_weights": route_weights,
                "experts": experts,
                "route_values": route_values,
                "combine_acc": combine_acc,
                "combine_q": combine_q,
                "output": output,
            }
        )
        if layer + 1 < X3_LAYERS:
            seam_acc = output.astype(np.int64) << X3_SHIFT
            seam_out = _requant(seam_acc, X3_SHIFT, "residual seam")
            current = seam_out
        else:
            current = output
    output_weight = _x3_sparse_projection(X3_D, X3_VOCAB, 19, 2)
    final_rms = _x3_rmsnorm(current[-1:], luts)
    final_witness = {
        "rms": final_rms,
        "logits": final_rms["output"].astype(np.int64) @ output_weight.astype(np.int64),
    }
    return {
        "rope_coefficients": rope_coefficients,
        "tokens": tokens,
        "wte": wte,
        "wpe": wpe,
        "source_padding": source_padding,
        "canonical_padding": canonical_padding,
        "embedding_acc": embedding_acc,
        "embedding_out": embedding_out,
        "weights": weights,
        "layers": layers,
        "seam_acc": seam_acc,
        "seam_out": seam_out,
        "output_weight": output_weight,
        "final_witness": final_witness,
        "clamp_probe": _x3_clamp_probe(luts),
    }


def _append_x3_rms(out: bytearray, rms: dict[str, np.ndarray]) -> None:
    for name, dtype in (
        ("input", "<i2"),
        ("sum_squares", "<i8"),
        ("mean_square", "<i8"),
        ("rsqrt_in", "<i2"),
        ("rsqrt_out", "<i2"),
        ("acc", "<i8"),
        ("output", "<i2"),
    ):
        _append_array(out, rms[name], dtype)


def x3_golden_bytes(*, admit_poison: bool = False) -> bytes:
    fixture = x3_ops_arrays(admit_poison=admit_poison)
    out = bytearray(b"VOLTA-X3-GOLD-V1")
    out += struct.pack(
        "<19I",
        X3_T,
        X3_T_PAD,
        X3_LAYERS,
        X3_D,
        X3_D_PAD,
        X3_DFF,
        X3_DFF_PAD,
        X3_Q_HEADS,
        X3_KV_HEADS,
        X3_HEAD_DIM,
        X3_EXPERTS,
        X3_TOP_K,
        X3_VOCAB,
        X3_VOCAB_PAD,
        X3_SHIFT,
        X3_SILU_SHIFT,
        X3_ROPE_FRAC,
        X3_SCORE_SHIFT,
        X3_SINKS,
    )
    _append_array(out, fixture["rope_coefficients"], "<i2")
    out += struct.pack("<I", fixture["source_padding"].size)
    for name, dtype in (
        ("source_padding", "<i2"),
        ("canonical_padding", "<i2"),
        ("tokens", "<u2"),
        ("wte", "<i2"),
        ("wpe", "<i2"),
        ("embedding_acc", "<i8"),
        ("embedding_out", "<i2"),
    ):
        _append_array(out, fixture[name], dtype)
    for weights, layer in zip(fixture["weights"], fixture["layers"], strict=True):
        _append_array(out, weights["qkv"], "<i2")
        _append_array(out, weights["attention"], "<i2")
        for expert_weights in weights["experts"]:
            for name in ("gate", "up", "down"):
                _append_array(out, expert_weights[name], "<i2")
        _append_array(out, layer["input"], "<i2")
        attention = layer["attention"]
        _append_x3_rms(out, attention["rms1"])
        for name, dtype in (
            ("qkv_acc", "<i8"),
            ("qkv", "<i2"),
            ("q", "<i2"),
            ("k", "<i2"),
            ("v", "<i2"),
            ("lo", "<u4"),
            ("hi", "<u4"),
            ("real_mask", "u1"),
            ("grouped_k_reads", "<i2"),
            ("grouped_v_reads", "<i2"),
            ("rope_folded_k", "<i8"),
            ("rope_pair_terms", "<i8"),
            ("score_acc_rect", "<i8"),
            ("score_acc_real", "<i8"),
            ("score_q_rect", "<i2"),
            ("score_q_real", "<i2"),
            ("exp_rect", "<i2"),
            ("sink_scores", "<i2"),
            ("sink_exp", "<i2"),
            ("denoms", "<i8"),
            ("recip_in", "<i2"),
            ("recips", "<i2"),
            ("norm_acc_rect", "<i8"),
            ("weights_rect", "<i2"),
            ("av_acc", "<i8"),
            ("av_q", "<i2"),
            ("projection_acc", "<i8"),
            ("projection_q", "<i2"),
            ("output", "<i2"),
        ):
            _append_array(out, attention[name], dtype)
        _append_x3_rms(out, layer["rms2"])
        _append_array(out, layer["routes"], "u1")
        _append_array(out, layer["route_weights"], "<i2")
        for expert in layer["experts"]:
            out += struct.pack("<I", expert["rows"].shape[0])
            for name, dtype in (
                ("rows", "u1"),
                ("gathered", "<i2"),
                ("gate_acc", "<i8"),
                ("gate_q", "<i2"),
                ("gate_clamped", "<i2"),
                ("up_acc", "<i8"),
                ("up_q", "<i2"),
                ("up_clamped", "<i2"),
                ("silu", "<i2"),
                ("product_acc", "<i8"),
                ("product_q", "<i2"),
                ("down_acc", "<i8"),
                ("down_q", "<i2"),
            ):
                _append_array(out, expert[name], dtype)
        for name, dtype in (
            ("route_values", "<i2"),
            ("combine_acc", "<i8"),
            ("combine_q", "<i2"),
            ("output", "<i2"),
        ):
            _append_array(out, layer[name], dtype)
    _append_array(out, fixture["seam_acc"], "<i8")
    _append_array(out, fixture["seam_out"], "<i2")
    _append_array(out, fixture["output_weight"], "<i2")
    _append_x3_rms(out, fixture["final_witness"]["rms"])
    _append_array(out, fixture["final_witness"]["logits"], "<i8")
    for name, dtype in (
        ("gate_in", "<i2"),
        ("up_in", "<i2"),
        ("gate_clamped", "<i2"),
        ("up_clamped", "<i2"),
        ("silu", "<i2"),
        ("product_acc", "<i8"),
        ("product_q", "<i2"),
    ):
        _append_array(out, fixture["clamp_probe"][name], dtype)
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
            "x3": {
                "t": X3_T,
                "t_pad": X3_T_PAD,
                "layers": X3_LAYERS,
                "d_model": X3_D,
                "d_model_pad": X3_D_PAD,
                "d_ff": X3_DFF,
                "d_ff_pad": X3_DFF_PAD,
                "q_heads": X3_Q_HEADS,
                "kv_heads": X3_KV_HEADS,
                "head_dim": X3_HEAD_DIM,
                "gqa_group": X3_GQA_GROUP,
                "experts": X3_EXPERTS,
                "top_k": X3_TOP_K,
                "vocab": X3_VOCAB,
                "vocab_pad": X3_VOCAB_PAD,
                "norm": "rmsnorm",
                "activation": "swiglu",
                "clamp": [X3_CLAMP_MIN, X3_CLAMP_MAX],
                "attention": ["full_causal", {"sliding": 4}],
                "attention_sinks_per_q_head": X3_SINKS,
                "rope": {"base": 10000, "fraction_bits": X3_ROPE_FRAC},
                "score_shift": X3_SCORE_SHIFT,
                "thin_k": 2,
            },
        }

    def goldens(self) -> dict[str, bytes]:
        return {
            "x1-router-v1.golden.bin": x1_golden_bytes(),
            "x2-moe-v1.golden.bin": x2_golden_bytes(),
            "x3-ops-v1.golden.bin": x3_golden_bytes(),
        }


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
    x2 = x2_moe_arrays()
    assert np.array_equal(x2["layers"][0]["router"]["routes"], _x2_routes(0))
    assert np.array_equal(x2["layers"][1]["router"]["routes"], _x2_routes(1))
    final_layer = np.ascontiguousarray(x2["layers"][-1]["output"], dtype="<i2").tobytes()
    assert x2_golden_bytes().endswith(final_layer + final_layer)
    x3 = x3_ops_arrays()
    poisoned = x3_ops_arrays(admit_poison=True)
    assert np.all(x3["source_padding"] != 0)
    assert np.all(x3["canonical_padding"] == 0)
    assert np.array_equal(poisoned["canonical_padding"], poisoned["source_padding"])
    assert np.array_equal(x3["layers"][-1]["output"], poisoned["layers"][-1]["output"])
    assert x3["layers"][0]["attention"]["lo"].tolist() == [0, 0, 0, 0, 0, 0, 0]
    assert x3["layers"][1]["attention"]["lo"].tolist() == [0, 0, 0, 0, 1, 2, 3]
    probe = x3["clamp_probe"]
    assert probe["gate_clamped"].tolist() == [-1024, -1024, -1024, -17, 0, 23, 1024, 1024, 1024]
    assert x3_golden_bytes() != x3_golden_bytes(admit_poison=True)
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
