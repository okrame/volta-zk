"""Independent exact numeric building blocks for calibration comparison."""
from pathlib import Path
import sys

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import c71_calibration_oracle as oracle


def test_matrix_uses_exact_binary64_envelope_and_matches_scalar_integer_dot():
    weight = np.array([[32767, -32767, 17], [-3, 5, 7]], dtype=np.int16)
    values = np.array([-32767, 32767, 19], dtype=np.int16)
    expected = [sum(int(a) * int(b) for a, b in zip(row, values)) for row in weight]
    assert oracle.matrix(weight, values).tolist() == expected
    with pytest.raises(ValueError, match="integers"):
        oracle.matrix(weight.astype(np.float64), values)


def test_rne_affine_and_rms_are_exact_at_signs_and_ties():
    assert oracle.rne([3, 5, -3, -5], 1) == [2, 2, -2, -2]
    assert oracle.affine([1, -2], [3, 4], (5, -2)) == [-1, -18]
    statistic, products, output = oracle.rms([3, 4], None, (0, 0, 0))
    assert statistic == [25] and products == [3, 4]
    assert output == [1, 1]
    weighted = oracle.rms([3, 4], [-2, 5], (0, 0, 0))
    assert weighted[1] == [-6, 20] and weighted[2] == [-2, 6]
    products = np.array([-32767**2, -17, 0, 19, 32767**2], dtype=np.int64)
    statistic = 3 * 32767**2
    assert oracle.rms_batch(products, statistic, 3, [0, 0, 0]).tolist() == [
        oracle.reference.rms_rne_i16(int(value), statistic, 3, 0, 0, 0)
        for value in products
    ]
    rng = np.random.default_rng(71)
    products = rng.integers(-32767**2, 32767**2 + 1, size=1000, dtype=np.int64)
    statistic = 5376 * 32767**2
    assert oracle.rms_batch(products, statistic, 5376, [0, 0, 0]).tolist() == [
        oracle.reference.rms_rne_i16(int(value), statistic, 5376, 0, 0, 0)
        for value in products
    ]


def test_integer_matrix_kernel_matches_python_and_blas_at_canonical_widths():
    rng = np.random.default_rng(71)
    for columns in (1, 3, 129, 5376, 21504):
        weight = rng.integers(-32767, 32768, size=(3, columns), dtype=np.int16)
        values = rng.integers(-32767, 32768, size=columns, dtype=np.int16)
        weight[0] = 32767
        values[::2] = -32767
        expected = [sum(int(a) * int(b) for a, b in zip(row, values)) for row in weight]
        actual = oracle.matrix_i16(weight, values)
        assert actual.tolist() == expected == oracle.matrix(weight, values).tolist()
    for target in (weight, values):
        saved = target.flat[-1]
        target.flat[-1] = -32768
        with pytest.raises(ValueError, match="symmetric i16"):
            oracle.matrix_i16(weight, values)
        target.flat[-1] = saved
    with pytest.raises(ValueError, match="shape/dtype"):
        oracle.matrix_i16(weight[:, ::2], values[::2])
    with pytest.raises(ValueError, match="shape/dtype"):
        oracle.matrix_i16(weight.astype(np.float64), values)


def test_rope_softmax_ratio_and_argmax_match_public_integer_recipes():
    assert oracle.rope([3, 4], [(1 << 30, 0)], 30) == [3, 4]
    row = oracle.softmax([7, 7, 0], 2, 0)
    assert row["maximum"] == 7 and row["probabilities"] == [8192, 8192, 0]
    assert oracle.ratio_rne(3, 2) == 2 and oracle.ratio_rne(-3, 2) == -2
    token, slack = oracle.argmax([7, 7, -3, 6])
    assert token == 0 and slack == [-32768, -32768, -32758, -32767]


def test_original_codec_encoding_preserves_signed_values_and_rejects_overflow():
    assert oracle.encode_signed([-32768, -1, 0, 32767], 2).hex() == "0080ffff0000ff7f"
    assert oracle.encode_u32([0, 262143]).hex() == "00000000ffff0300"
    with pytest.raises(ValueError, match="exceeds codec"):
        oracle.encode_signed([128], 1)


def test_rms_batch_matches_scalar_across_wide_public_coefficients():
    rng = np.random.default_rng(7101)
    checked = 0
    for _ in range(80):
        columns = int(rng.choice([64, 128, 256, 4096, 5376, 11008]))
        exponents = [int(value) for value in rng.integers(-20, 21, size=3)]
        try:
            coefficients = oracle.reference.rms_integer_coefficients(columns, *exponents)
        except ValueError:
            continue
        statistic = int(rng.integers(0, columns * 32767**2 + 1))
        if max((*coefficients, coefficients[1] + coefficients[2] * statistic)) >= 1 << 128:
            continue
        products, expected = [], []
        for value in rng.integers(-32767**2, 32767**2 + 1, size=32, dtype=np.int64):
            try:
                result = oracle.reference.rms_rne_i16(
                    int(value), statistic, columns, *exponents)
            except ValueError:
                continue
            products.append(int(value))
            expected.append(result)
        if products:
            assert oracle.rms_batch(products, statistic, columns, exponents).tolist() == expected
            checked += len(products)
    assert checked >= 100
