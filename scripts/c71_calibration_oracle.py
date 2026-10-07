#!/usr/bin/env python3
"""Independent exact integer operators for the C7.1 calibration oracle.

This module contains no Rust replay or trace-decoding logic.  It is the
numeric side of a future full-model producer; callers still have to supply
the canonical operation plan, weights, tables, liveness and frame order.
"""
from __future__ import annotations

import ctypes
from fractions import Fraction
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile

import numpy as np

import c7_1_gemma_plan as reference


I16_MIN, I16_MAX = -32767, 32767
RMS_SOURCE = Path(__file__).with_name("c71_oracle_rms.c")


def _symmetric_i16(values, label: str) -> np.ndarray:
    result = np.asarray(values)
    if not np.issubdtype(result.dtype, np.integer):
        raise ValueError(f"{label} must contain integers")
    if np.any(result < I16_MIN) or np.any(result > I16_MAX):
        raise ValueError(f"{label} is outside symmetric i16")
    return result


def matrix(weight, values) -> np.ndarray:
    """Exact W@x via binary64 BLAS after proving every partial sum <2^53."""
    weight = _symmetric_i16(weight, "matrix weight")
    values = _symmetric_i16(values, "matrix input")
    if weight.ndim != 2 or values.ndim != 1 or weight.shape[1] != values.size:
        raise ValueError("matrix shape differs")
    absolute_bound = int(weight.shape[1]) * I16_MAX**2
    if absolute_bound >= 1 << 53:
        raise ValueError("matrix exact-binary64 bound exceeded")
    output = weight.astype(np.float64) @ values.astype(np.float64)
    if not np.isfinite(output).all() or not np.equal(output, np.rint(output)).all():
        raise ArithmeticError("matrix binary64 result is not an exact integer")
    return output.astype(np.int64)


def rne(values, shift: int) -> list[int]:
    return [reference.rne_i48_to_i16(int(value), shift) for value in values]


def affine(left, right, coefficients) -> list[int]:
    left = _symmetric_i16(left, "affine left")
    right = _symmetric_i16(right, "affine right")
    if left.shape != right.shape or left.ndim != 1 or len(coefficients) != 2:
        raise ValueError("affine shape differs")
    if any(type(value) is not int or abs(value) > 1 << 30 for value in coefficients):
        raise ValueError("affine coefficient differs")
    return [coefficients[0] * int(x) + coefficients[1] * int(y)
            for x, y in zip(left, right)]


def rms(values, weights, exponents) -> tuple[list[int], list[int], list[int]]:
    values = _symmetric_i16(values, "RMS input").reshape(-1)
    if len(exponents) != 3 or any(type(value) is not int for value in exponents):
        raise ValueError("RMS exponents differ")
    if weights is None:
        if exponents[1] != 0:
            raise ValueError("unweighted RMS scale exponent differs")
        products = [int(value) for value in values]
        scale = 0
    else:
        weights = _symmetric_i16(weights, "RMS weight").reshape(-1)
        if weights.shape != values.shape:
            raise ValueError("RMS weight shape differs")
        products = [int(x) * int(w) for x, w in zip(values, weights)]
        scale = exponents[1]
    statistic = sum(int(value) ** 2 for value in values)
    output = [reference.rms_rne_i16(product, statistic, len(values),
                                    exponents[0], scale, exponents[2])
              for product in products]
    return [statistic], products, output


def rope(values, coefficients, shift: int) -> list[int]:
    raw = reference.rope_raw_row([int(value) for value in _symmetric_i16(values, "RoPE input")],
                                 coefficients)
    return rne(raw, shift)


def softmax(scores, live: int, score_exponent: int) -> dict:
    scores = [int(value) for value in _symmetric_i16(scores, "softmax score")]
    if not 1 <= live <= len(scores):
        raise ValueError("softmax live prefix differs")
    return reference.softmax_exp30_row(scores, [index < live for index in range(len(scores))],
                                       score_exponent)


def ratio_rne(numerator: int, denominator: int) -> int:
    if denominator <= 0:
        raise ValueError("ratio denominator must be positive")
    result = round(Fraction(numerator, denominator))
    if not I16_MIN <= result <= I16_MAX:
        raise ValueError("ratio output is outside symmetric i16")
    return result


def argmax(values) -> tuple[int, list[int]]:
    values = [int(value) for value in _symmetric_i16(values, "argmax input")]
    if not values:
        raise ValueError("argmax input is empty")
    token = values.index(max(values))
    slack = [values[token] - value - int(index < token) - 32768
             for index, value in enumerate(values)]
    if any(not -(1 << 15) <= value < 1 << 15 for value in slack):
        raise ValueError("argmax unsigned slack overflows u16")
    return token, slack


def encode_signed(values, width: int) -> bytes:
    if not 1 <= width <= 8:
        raise ValueError("oracle codec width differs")
    result = bytearray()
    bound = 1 << (8 * width - 1)
    for value in values:
        value = int(value)
        if not -bound <= value < bound:
            raise ValueError("oracle value exceeds codec")
        result.extend(value.to_bytes(8, "little", signed=True)[:width])
    return bytes(result)


def encode_u32(values) -> bytes:
    if any(type(value) is not int or not 0 <= value < 1 << 32 for value in values):
        raise ValueError("oracle u32 value differs")
    return struct.pack(f"<{len(values)}I", *values)


def _rms_library():
    source = RMS_SOURCE.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    directory = tempfile.TemporaryDirectory(prefix="volta-c71-oracle-rms-")
    output = Path(directory.name) / f"{digest}.so"
    subprocess.run(["cc", "-O3", "-march=native", "-shared", "-fPIC", "-std=c11",
                    "-Wall", "-Wextra", "-Werror", str(RMS_SOURCE),
                    "-o", str(output)], timeout=60, check=True, capture_output=True)
    library = ctypes.CDLL(str(output))
    function = library.c71_rms_batch
    function.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.c_size_t,
                         ctypes.c_uint64, ctypes.c_uint64, ctypes.c_uint64,
                         ctypes.c_uint64, ctypes.c_uint64,
                         ctypes.POINTER(ctypes.c_int16)]
    function.restype = ctypes.c_size_t
    library.c71_matrix_i16.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_size_t, ctypes.c_size_t]
    library.c71_matrix_i16.restype = ctypes.c_int
    binary_digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return directory, library, function, digest, binary_digest


_RMS = None


def matrix_i16(weight, values) -> np.ndarray:
    """Independent C11 exact integer dot without a dequantized weight copy."""
    global _RMS
    weight = np.asarray(weight)
    values = _symmetric_i16(values, "matrix input")
    if (weight.dtype != np.dtype("int16") or weight.ndim != 2
            or not weight.flags.c_contiguous or values.ndim != 1
            or weight.shape[1] != values.size or not weight.size):
        raise ValueError("native oracle matrix shape/dtype differs")
    if weight.shape[1] * 32767**2 >= 1 << 63:
        raise ValueError("native oracle matrix i64 bound exceeded")
    values = np.ascontiguousarray(values, dtype=np.int16)
    output = np.empty(weight.shape[0], dtype=np.int64)
    if _RMS is None:
        _RMS = _rms_library()
    if _RMS[1].c71_matrix_i16(weight.ctypes.data, values.ctypes.data, output.ctypes.data,
                             *weight.shape):
        raise ValueError("native oracle matrix outside symmetric i16")
    return output


def rms_batch(products, statistic: int, columns: int, exponents) -> np.ndarray:
    """Exact batched RMS RNE through the independent 192-bit C kernel."""
    global _RMS
    products = np.ascontiguousarray(products, dtype=np.int64).reshape(-1)
    if len(exponents) != 3 or any(type(value) is not int for value in exponents):
        raise ValueError("RMS exponents differ")
    a, b, c = reference.rms_integer_coefficients(columns, *exponents)
    denominator = b + c * int(statistic)
    multiplier = reference.rms_row_multiplier(a, denominator)
    if any(value < 0 or value >= 1 << 128 for value in (a, denominator)):
        raise ValueError("RMS coefficient exceeds independent kernel")
    if _RMS is None:
        _RMS = _rms_library()
    output = np.empty(products.size, dtype=np.int16)
    failure = _RMS[2](products.ctypes.data_as(ctypes.POINTER(ctypes.c_int64)), products.size,
                      a & ((1 << 64) - 1), a >> 64,
                      denominator & ((1 << 64) - 1), denominator >> 64, multiplier,
                      output.ctypes.data_as(ctypes.POINTER(ctypes.c_int16)))
    if failure:
        raise ValueError(f"RMS output lane {failure - 1} differs")
    return output


def rms_kernel_digests() -> dict:
    return {
        "source_sha256": hashlib.sha256(RMS_SOURCE.read_bytes()).hexdigest(),
        "shared_object_sha256": None if _RMS is None else _RMS[4],
    }
