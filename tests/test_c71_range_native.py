"""Native range arithmetic/geometry only; does not execute CUDA."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_native_range_host_algebra_and_bounded_groups(tmp_path):
    binary = tmp_path / "native-range-host"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         str(ROOT / "cuda/c71_range_native_host.cpp"), "-o", str(binary)],
        check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout.removeprefix("C71_NATIVE_RANGE_HOST "))
    assert report == {"cases": 37, "max_original_words": 2048,
                      "max_shared_payload_bytes": 52224, "gpu_execution": False, "credit": False}


def test_native_range_owner_with_deferred_fake_driver(tmp_path):
    binary = tmp_path / "native-range-owner"
    subprocess.run(
        ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Werror",
         "-fsanitize=undefined", "-fno-sanitize-recover=all",
         "-I", str(ROOT / "tests/cuda_stub"), "-I", str(ROOT / "cuda"),
         str(ROOT / "cuda/c71_range_runtime.cpp"), str(ROOT / "tests/c71_range_runtime_host.cpp"),
         "-o", str(binary)], check=True, timeout=30,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stdout + result.stderr
    reports = {}
    for line in result.stdout.splitlines():
        marker, payload = line.split(" ", 1)
        assert marker not in reports
        reports[marker] = json.loads(payload)
    print(result.stdout.strip())
    report = reports.pop("C71_RANGE_OWNER_HOST")
    assert report == {"rejections": 13, "dense_rejections": 23, "byte_rejections": 19, "pointwise_rejections": 14, "embedding_rejections": 17, "dense_batches": 2, "dense_row_views": 1, "max_arena_bytes": 262144,
                      "gpu_execution": False, "credit": False}

    reuse = reports.pop("C71_SYNC_ERROR_FLAG_REUSE")
    assert reuse.pop("host_owner_bytes") == 42096
    assert reuse == {
        "retained_device_capacity_bytes": 256, "flag_count": 1,
        "sync_flag_reuse": True, "numeric_operations": 32,
        "numeric_flag_allocations": 1, "numeric_flag_allocations_before": 32,
        "numeric_completion_fences": 32, "numeric_flag_download_bytes": 128,
        "numeric_reset_terminal_rejections": 1, "pool_free_terminal_rejections": 1,
        "gpu_execution": False, "credit": False,
    }

    assert reports.pop("C71_POINTWISE_PUBLIC_ZERO") == {
        "ragged_cases": 7, "output_zeroed_bytes": 134288,
        "flag_zeroed_bytes": 28, "application_kernel_launches": 0,
        "completion_fences": 7, "flag_download_bytes": 28,
        "retained_device_capacity_bytes": 256, "terminal_fault_rejections": 5,
        "unused_input_rejections": 4, "sticky_byte_flag_preserved": True,
        "gpu_execution": False, "credit": False,
    }

    expected_components = {
        "C71_RUNTIME_STACK_LIMIT": {
            "requested_bytes": 256, "terminal_rejections": 3,
            "gpu_execution": False, "credit": False,
        },
        "C71_PCS_RESIDUAL_OWNER_COMPONENT": {
            "singleton": 1, "original_retention": 1, "ood_original": 1,
            "ood_resident": 3, "paired_folds": 2, "bounded_consuming_reads": 3,
            "gpu_execution": False, "credit": False,
        },
        "C71_PCS_RESIDUAL_CONTRACT_OWNER": {
            "cases": 8, "W_bands_one_scan": True, "resident_virtual_bits": 2,
            "consumer_d2h_bytes": 52, "public_tail_reads": 0,
            "gpu_execution": False, "credit": False,
        },
        "C71_PCS_RESIDUAL_OWNER_FAILURE": {
            "terminal_rejections": 45, "private_read_d2h_bytes": 0,
            "publication_after_free": True, "gpu_execution": False, "credit": False,
        },
        "C71_PCS_RESIDUAL_CONTRACT_FAILURE": {
            "terminal_rejections": 19, "gpu_execution": False, "credit": False,
        },
        "C71_PCS_SHORT_OWNER": {
            "two_coset_groups": 16, "private_salts": 1024,
            "ring_words_checked": 3072, "odd_fft_log_rows": 3,
            "input_d2h_bytes": 0, "gpu_execution": False, "credit": False,
        },
        "C71_PCS_SHORT_OWNER_FAILURE": {
            "terminal_rejections": 13, "old_groups_large_rows_rejected": 2,
            "gpu_execution": False, "credit": False,
        },
    }
    expected_components["C71_PCS_QUERY_E_OWNER"] = {
        "column_cases": 80, "query_rows": 448, "original_or_plane_visits": 400,
        "root_blocks": 204, "private_limb_loads": 3, "fences_per_column": 2,
        "input_d2h_bytes": 0, "W_scans_per_batch": 1,
        "gpu_execution": False, "credit": False,
    }
    expected_components["C71_PCS_QUERY_E_FAILURE"] = {
        "terminal_rejections": 56, "forbidden_read_d2h_bytes": 0,
        "publication_after_free": True, "root_columns_are_not_queries": True,
        "gpu_execution": False, "credit": False,
    }
    expected_components["C71_PCS_QUERY_E_WEIGHT_FAILURE"] = {
        "terminal_rejections": 2, "pad_only_launches": 1, "real_work_launches": 2,
        "accepted_init_drained": True, "gpu_execution": False, "credit": False,
    }
    expected_components["C71_PCS_TRUSTED_SOURCE_PARTITION"] = {
        "reversed_ragged_cases": 1, "trusted_row_coverage": True,
        "standalone_byte_count_proves_uniqueness": False,
        "gpu_execution": False, "credit": False,
    }
    expected_components["C71_PCS_QUERY_W_INITIAL_OWNER"] = {
        "column_cases": 160, "query_rows": 896, "root_blocks": 0,
        "original_visits": 640, "W_scans_per_batch": 1,
        "loader_launches_per_block": 1, "loader_extra_temp_bytes": 0,
        "block_input_transfer_bytes": 0, "fences_per_column": 1,
        "D35_sparse_geometry": True, "None_zero_unchanged": True,
        "gpu_execution": False, "credit": False,
    }
    # Count comes from the public source_rows/capacity loop, not an FFT claim.
    expected_components["C71_PCS_QUERY_W_INITIAL_OWNER"]["root_blocks"] = sum(
        8 * ((n + 3 + cap - 1) // cap)
        for cap in (1, 2, 4, 8, 16) for n in (4, 8, 16, 64)
    )
    expected_components["C71_PCS_QUERY_W_INITIAL_FAILURE"] = {
        "terminal_rejections": 34, "input_d2h_bytes": 0,
        "unavailable_GPU_fail_closed": True, "gpu_execution": False, "credit": False,
    }
    assert reports == expected_components
