import importlib.util
from pathlib import Path


def load_sweep_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "p7_shape_memory_sweep.py"
    spec = importlib.util.spec_from_file_location("p7_shape_memory_sweep", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_shape_memory_sweep_is_analytic_and_grounded_in_resident_record():
    sweep = load_sweep_module()
    resident = (
        Path(__file__).resolve().parents[1]
        / "benchmarks/results/p7-integrated-resident-2026-07-13-1fd5195.json"
    )
    report = sweep.build_report(resident)

    assert all(report["validation"].values())
    assert report["scope"]["non_gpt2_end_to_end"] is False
    assert report["scope"]["proof_peak_memory_projected"] is False
    assert report["source_resident_peak_device_bytes"] == 5_405_147_708
    profiles = {row["name"]: row for row in report["profiles"]}
    gpt2 = profiles["gpt2-small"]
    assert gpt2["total_parameters"] == 124_701_952
    assert gpt2["committed_weight_bytes_i16"] == 249_403_904
    llama = profiles["llama-class-8b-dense-gqa"]
    assert llama["status"] == "analytic-projection-only"
    assert llama["gqa_kv_fraction_vs_mha"] == 0.25
    assert 8_000_000_000 < llama["total_parameters"] < 8_100_000_000
    moe = profiles["gpt-oss-20b-moe-active"]
    assert moe["active_parameter_fraction"] == 3.6 / 20.9
    assert moe["active_weight_bytes_i16"] == 7_200_000_000
    assert moe["committed_weight_bytes_i16"] == 41_800_000_000
    assert [row["sequence_length"] for row in moe["sequence_sweep"]] == [150, 512, 2048, 8192]
