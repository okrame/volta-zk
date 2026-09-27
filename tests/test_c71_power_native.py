import copy
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MODULUS = 18_446_744_069_414_584_321


def encode(vector):
    values = ["C71_POWER_P3_V1", vector["side"]]
    for name in ("numerator", "inverse", "expected"):
        values.extend(vector[name])
    return " ".join(map(str, values)) + "\n"


def test_native_rational_power_blocks_cross_the_fft_boundary(tmp_path):
    native = os.environ.get("C71_PCS_TEST_BINARY")
    assert native, "build volta-pcs tests and set C71_PCS_TEST_BINARY"
    output = subprocess.check_output(
        [native, "c71_b12_native_power_fft_vectors", "--test-threads=1", "--nocapture"],
        text=True, timeout=60,
    )
    assert "test result: ok. 1 passed" in output
    marker = "C71_NATIVE_POWER "
    vectors = [json.loads(line.split(marker, 1)[1]) for line in output.splitlines() if marker in line]
    assert {(vector["side"], vector["block"]) for vector in vectors} == {
        (side, block) for side in (2, 4, 8, 16) for block in range(3)
    }
    assert len(vectors) == 12
    binary = tmp_path / "fft"
    subprocess.run(
        ["g++", "-O2", "-std=c++17", "-x", "c++", str(ROOT / "cuda/c71_fft_microbench.cu"), "-o", str(binary)],
        check=True, timeout=30,
    )
    for vector in vectors:
        assert vector["basis"] == "v^3-v-1"
        length = vector["side"] ** 2
        result = subprocess.run(
            [str(binary), "--host-power-native"], input=encode(vector),
            capture_output=True, text=True, check=True, timeout=30,
        )
        assert json.loads(result.stdout) == {
            "schema": "volta-c71-native-power-v1", "basis": "v^3-v-1",
            "gpu_execution": False, "credit": False, "cap": length // 2,
            "native_power_block": True, "pointwise_fp3_products": length,
            "pointwise_base_products": 6 * length,
            "inverse_normalization_base_products": 3 * length,
            "planned_device_bytes": 8 * length * 8,
        }
        for name, offset in (("numerator", 0), ("inverse", 1), ("expected", 0)):
            changed = copy.deepcopy(vector)
            changed[name][offset] = (changed[name][offset] + 1) % MODULUS
            rejected = subprocess.run(
                [str(binary), "--host-power-native"], input=encode(changed),
                capture_output=True, text=True, timeout=30,
            )
            assert rejected.returncode == 1, (vector["side"], vector["block"], name, rejected.stdout)
    valid = encode(vectors[-1])
    for malformed in (
        "", valid + "extra", " ".join(valid.split()[:-1]),
        valid.replace("C71_POWER_P3_V1", "C71_POWER_U3_V1", 1),
        valid.replace("C71_POWER_P3_V1 16", "C71_POWER_P3_V1 32", 1),
        valid.replace("C71_POWER_P3_V1 16", "C71_POWER_P3_V1 -16", 1),
        " ".join(valid.split()[:2] + [str(MODULUS)] + valid.split()[3:]),
    ):
        rejected = subprocess.run(
            [str(binary), "--host-power-native"], input=malformed,
            capture_output=True, text=True, timeout=30,
        )
        assert rejected.returncode == 2
