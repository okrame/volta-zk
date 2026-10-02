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
