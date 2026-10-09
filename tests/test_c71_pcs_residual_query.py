"""Independent PCS E query-loader parity; host component, no CUDA credit."""
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_pcs_residual_query_three_limbs_single_pass_and_msb_folds(tmp_path):
    binary = tmp_path / "pcs-residual-query-host"
    shared_cuda = Path(os.environ.get("C71_PCS_SHARED_CUDA", ROOT / "cuda"))
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=undefined", "-fno-sanitize-recover=all",
         "-I", str(ROOT / "cuda"), "-I", str(shared_cuda),
         str(ROOT / "tests/c71_pcs_residual_query_host.cpp"), "-o", str(binary)],
        check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True, timeout=20)
    print(result.stdout.strip())
    report = json.loads(result.stdout.splitlines()[-1].removeprefix("C71_PCS_RESIDUAL_QUERY_HOST "))
    assert report["cases"] == 190
    assert report["logical_passes"] == 189
    assert report["horner_checks"] == 189 * 16
    assert report["coefficient_outputs"] > 0
    assert report["pad_outputs"] > 0 and report["zero_outputs"] > 0
    assert report["rejections"] >= 32
    assert report["expected_W_original_reads"] > 0
    assert report["emulated_W_reads"] == report["expected_W_original_reads"]
    assert report["emulated_CTA_tasks"] > 0 and report["emulated_EQ_cache_entries"] > 0
    assert report["emulated_field_updates"] > 0
    assert report["expected_A_retained_word_reads"] == 3 * report["expected_A_retained_E_reads"]
    assert report["named_fixture_heap_upper_bytes"] < 2 * 1024**2
    assert report["max_low_payload_bytes"] == 3 * 2**20 * 8
    assert report["W_shared_bytes"] == 12288 and report["resident_shared_bytes"] == 0
    assert report["host_component_s"] > 0
    assert report["PCS_basis_v3_v1"]
    assert not report["gpu_execution"] and not report["integrated"] and not report["credit"]
