import copy
import json
import os
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
MODULUS = 18_446_744_069_414_584_321


def encode(vector):
    values = ["C71_REMAINDER_V1"]
    values.extend(vector[name] for name in ("side", "columns", "coefficients", "queries"))
    for name in ("inverse", "modulus", "source", "points", "expected", "rows"):
        values.extend(vector[name])
    return " ".join(map(str, values)) + "\n"


def test_native_base_and_extension_remainders_cross_the_fft_boundary(tmp_path):
    native = os.environ.get("C71_PCS_TEST_BINARY")
    assert native, "build volta-pcs tests and set C71_PCS_TEST_BINARY"
    output = subprocess.check_output(
        [native, "c71_b12_native_remainder_fft_vectors", "--test-threads=1", "--nocapture"],
        text=True, timeout=60,
    )
    assert "test result: ok. 1 passed" in output
    marker = "C71_NATIVE_REMAINDER "
    vectors = [json.loads(line.split(marker, 1)[1]) for line in output.splitlines() if marker in line]
    assert len(vectors) == 8
    binary = tmp_path / "fft"
    subprocess.run(
        ["g++", "-O2", "-std=c++17", "-x", "c++", str(ROOT / "cuda/c71_fft_microbench.cu"), "-o", str(binary)],
        check=True, timeout=30,
    )
    for vector in vectors:
        result = subprocess.run(
            [str(binary), "--host-remainder-native"], input=encode(vector),
            capture_output=True, text=True, check=True, timeout=30,
        )
        report = json.loads(result.stdout)
        assert report == {
            "schema": "volta-c71-native-remainder-v1", "gpu_execution": False,
            "cap": vector["side"] ** 2 // 2, "columns": vector["columns"],
            "coefficients_per_column": vector["coefficients"], "queries": vector["queries"],
            "native_remainder_and_rows": True,
        }
        assert vector["columns"] == (6 if vector["extension"] else 2)
        assert vector["source"][61:64] == [0, 0, 0]
        assert all(vector["source"][64:67])
        for name, offset in (("source", 64), ("inverse", 0), ("modulus", 0), ("expected", 0), ("rows", 0)):
            if name in ("inverse", "modulus") and vector["coefficients"] <= report["cap"]:
                continue
            changed = copy.deepcopy(vector)
            changed[name][offset] = (changed[name][offset] + 1) % MODULUS
            rejected = subprocess.run(
                [str(binary), "--host-remainder-native"], input=encode(changed),
                capture_output=True, text=True, timeout=30,
            )
            assert rejected.returncode == 1, (vector["side"], name, rejected.stdout)
    valid = encode(vectors[-1])
    for malformed in (
        "", valid + "0", " ".join(valid.split()[:-1]),
        valid.replace("C71_REMAINDER_V1 16", "C71_REMAINDER_V1 32", 1),
        valid.replace("C71_REMAINDER_V1 16", "C71_REMAINDER_V1 -16", 1),
        valid.replace("C71_REMAINDER_V1 16 6", "C71_REMAINDER_V1 16 1000000000", 1),
        " ".join(valid.split()[:5] + [str(MODULUS)] + valid.split()[6:]),
    ):
        rejected = subprocess.run(
            [str(binary), "--host-remainder-native"], input=malformed,
            capture_output=True, text=True, timeout=30,
        )
        assert rejected.returncode == 2
