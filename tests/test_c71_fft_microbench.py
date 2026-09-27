import copy
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_c71_fft_microbench as fft


def test_host_square_and_odd_reports_match_the_existing_kernel(tmp_path):
    compiler = shutil.which("g++")
    if compiler is None:
        pytest.skip("g++ is required for the host reference check")
    binary = tmp_path / "fft"
    subprocess.run(
        [compiler, "-O2", "-std=c++17", "-x", "c++", str(fft.SOURCE), "-o", str(binary)],
        check=True, timeout=30,
    )
    for log2_m in range(1, 5):
        for mode in ("host-check", "host-check-odd", "host-check-inverse", "host-check-odd-inverse"):
            report = json.loads(subprocess.check_output(
                [str(binary), f"--{mode}", str(log2_m)], text=True, timeout=30,
            ))
            fft.validate(report, mode, log2_m, 1)
            corrupted = copy.deepcopy(report)
            corrupted["input"]["length"] += 1
            with pytest.raises(SystemExit):
                fft.validate(corrupted, mode, log2_m, 1)
            for field in ("scale", "field_multiplications", "extra_global_passes"):
                corrupted = copy.deepcopy(report)
                corrupted["normalization"][field] += 1
                with pytest.raises(SystemExit):
                    fft.validate(corrupted, mode, log2_m, 1)
            corrupted = copy.deepcopy(report)
            corrupted["roundtrip"] = False
            with pytest.raises(SystemExit):
                fft.validate(corrupted, mode, log2_m, 1)
            if "-odd" in mode:
                for section, field in (
                    ("merge", "twiddle_table_bytes"),
                    ("whole_fft", "value_read_write_bytes"),
                    ("correctness", "odd_adapter_vs_dft"),
                ):
                    corrupted = copy.deepcopy(report)
                    corrupted[section][field] = 0
                    with pytest.raises(SystemExit):
                        fft.validate(corrupted, mode, log2_m, 1)
            else:
                corrupted = copy.deepcopy(report)
                corrupted["correctness"]["tile_pair_normalized_m64"] = False
                with pytest.raises(SystemExit):
                    fft.validate(corrupted, mode, log2_m, 1)


@pytest.mark.parametrize("odd", [False, True])
@pytest.mark.parametrize("inverse", [False, True])
def test_simulated_gpu_reports_require_matching_mode_counts_and_timings(odd, inverse):
    log2_m, batch = 2, 3
    length = 32 if odd else 16
    count = length * batch
    mode = ("cuda-odd" if odd else "cuda") + ("-inverse" if inverse else "")
    report = {
        "schema": fft.SCHEMA,
        "mode": mode,
        "normalization": {
            "inverse": inverse,
            "scale": pow(length, 18_446_744_069_414_584_319, 18_446_744_069_414_584_321) if inverse else 1,
            "field_multiplications": count if inverse else 0,
            "extra_global_passes": 0,
        },
        "field": {"base_modulus": 18_446_744_069_414_584_321, "generator": 7, "element_bytes": 8},
        "input": {
            "generator": "splitmix64-v1", "seed": fft.SEED, "log2_m": log2_m,
            "m": 4, "length": length, "batch": batch,
        },
        "algorithm": {
            "passes": 6 if odd else 5,
            "layout": "parity-scattered-input/natural-order-output" if odd else "natural-order",
            "steps": ["transpose", "row-fft", "twiddle-transpose", "row-fft", "transpose"]
            + (["radix2-merge"] if odd else []),
        },
        "correctness": {"small_cpu_gpu_natural_order": True},
        "allocation": {
            "requested_peak_bytes": 1024 if odd else 512,
            "values_bytes": 8 * count, "twiddle_bytes": 8 * length,
            "transpose_static_shared_bytes_per_block": 16_896,
            "row_fft_dynamic_shared_bytes_per_block": 32,
            "allocation_ms": 1.0,
        },
        "timing_ms": {
            "initialize": 1.0, "twiddle_initialize": 1.0,
            "fft" if odd else "five_pass_fft": 1.0,
        },
        "logical_global_traffic_bytes": 9216 if odd else 3840,
        "odd_merge": {
            "value_read_bytes": 768 if odd else 0,
            "value_write_bytes": 768 if odd else 0,
            "twiddle_read_bytes": 384 if odd else 0,
            "field_multiplications": 48 if odd else 0,
            "field_additions": 48 if odd else 0,
            "field_subtractions": 48 if odd else 0,
        },
        "work": {
            "twiddle_read_bytes": 2688 if odd else 1152,
            "butterflies": 240 if odd else 96,
            "square_cross_multiplications": count,
            "twiddle_table_bytes": 8 * length,
            "additional_twiddle_table_bytes_vs_square": 128 if odd else 0,
            "additional_twiddle_initialization_write_bytes_vs_square": 128 if odd else 0,
        },
    }
    fft.validate(report, mode, log2_m, batch)
    if inverse:
        corrupted = copy.deepcopy(report)
        del corrupted["normalization"]
        with pytest.raises(SystemExit):
            fft.validate(corrupted, mode, log2_m, batch)
    with pytest.raises(SystemExit):
        fft.validate(report, "cuda" if odd else "cuda-odd", log2_m, batch)
    for section, field in (
        ("allocation", "values_bytes"),
        ("allocation", "twiddle_bytes"),
        ("odd_merge", "field_multiplications"),
        ("work", "butterflies"),
        ("normalization", "scale"),
        ("normalization", "field_multiplications"),
        ("normalization", "extra_global_passes"),
    ):
        corrupted = copy.deepcopy(report)
        corrupted[section][field] += 1
        with pytest.raises(SystemExit):
            fft.validate(corrupted, mode, log2_m, batch)
    corrupted = copy.deepcopy(report)
    corrupted["timing_ms"]["initialize"] = float("nan")
    with pytest.raises(SystemExit):
        fft.validate(corrupted, mode, log2_m, batch)


@pytest.mark.parametrize("inverse", [False, True])
def test_host_only_odd_cli_and_distinct_immutable_result_names(tmp_path, monkeypatch, inverse):
    compiler = shutil.which("g++")
    if compiler is None:
        pytest.skip("g++ is required for the host reference check")
    output = subprocess.check_output(
        [
            sys.executable, str(ROOT / "scripts/run_c71_fft_microbench.py"),
            "--host-only", "--odd", "--host-log2-m", "2",
            "--timeout-seconds", "30", "--cxx", compiler,
        ] + (["--inverse"] if inverse else []),
        text=True, timeout=40,
    )
    report = json.loads(output[output.index("{"):])
    assert report["kernel"]["mode"] == "host-check-odd" + ("-inverse" if inverse else "")
    assert report["provenance"]["source_sha256"] == fft.source_sha256()
    assert fft.device_bytes(10, 128, odd=True) == 2_164_260_864
    assert fft.device_bytes(10, 128, odd=True) + (256 << 20) < fft.ARENA
    monkeypatch.setattr(fft, "RESULTS", tmp_path)
    even = fft.unique_result_path("2026-09-27", "test", False)
    odd = fft.unique_result_path("2026-09-27", "test", False, odd=True, inverse=inverse)
    assert even != odd
    assert odd != fft.unique_result_path("2026-09-27", "test", False, odd=True, inverse=not inverse)
    odd.write_text("preserved")
    assert fft.unique_result_path("2026-09-27", "test", False, odd=True, inverse=inverse) != odd
    assert odd.read_text() == "preserved"
