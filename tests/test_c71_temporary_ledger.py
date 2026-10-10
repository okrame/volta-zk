"""Retained CUDA capacity is charged across phases, including when idle."""
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("temporary_ledger", ROOT / "scripts/c71_temporary_ledger.py")
LEDGER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(LEDGER)
INPUTS = ROOT / "benchmarks/results/c71-preh100-operational-local-2026-10-09-24b54d414421/ledger-inputs"


def compute(directory):
    return LEDGER.ledger(directory, "s1-prepared",
        ROOT / "benchmarks/results/c71-crypto-query-local-2026-10-09-46d295ef4ea6.json",
        ROOT / "benchmarks/results/c71-crypto-linear-local-2026-10-09-31280382f681.json",
        ROOT / "benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1.json")


def test_retained_sync_flag_is_charged_until_native_cleanup(tmp_path):
    for path in INPUTS.glob("*.log"):
        (tmp_path / path.name).symlink_to(path)
    before = compute(tmp_path)
    marker = dict(sync_flag_reuse=True, flag_count=1, retained_device_capacity_bytes=256,
                  host_owner_bytes=max(x["bytes"] for x in before["current_owner_host_byte_observations"])+8)
    (tmp_path / "sync.log").write_text("C71_SYNC_ERROR_FLAG_REUSE " + json.dumps(marker) + "\n")
    after = compute(tmp_path)
    assert len(after["named_phase_crosschecks"]) == len(before["named_phase_crosschecks"]) == 653
    for old, new in zip(before["named_phase_crosschecks"], after["named_phase_crosschecks"]):
        assert old["phase"] == new["phase"]
        owner_live = "native_common_owner_host" in old["parts"]
        retired = old["phase"] == "after_crypto_cleanup_report"
        assert new["named_allocation_subtotal_bytes"]-old["named_allocation_subtotal_bytes"] == (
            (8 if retired else 264) if owner_live else 0)
        assert ("native_retained_sync_error_flag_upper" in new["parts"]) == (owner_live and not retired)
    assert after["joint_admitted"] is False
    assert after["allowance_physically_verified"] is False
    assert after["credit"] is False


def test_AES_setup_keeps_the_already_installed_W_cache_and_owner():
    phases = {r["phase"]: r for r in compute(INPUTS)["named_phase_crosschecks"]}
    parts = phases["real_AES_seed6_setup"]["parts"]
    installed = phases["native_initial_W_install"]["parts"]
    for key in ("initial_W_and_A_root_offset_caches", "retained_initial_private_host_pads",
                "native_common_owner_host"):
        assert parts[key] == installed[key] > 0
    assert parts["two_public_table_host_payloads"] == 2*24414870
    assert "full_calibration_table_serialization_difference_upper" not in parts
    assert "native_common_owner_host" not in phases["public_profile_construction"]["parts"]


@pytest.mark.parametrize("change", [dict(retained_device_capacity_bytes=0), dict(flag_count=2),
                                  dict(host_owner_bytes=1), dict(sync_flag_reuse=False)])
def test_invalid_retention_receipt_is_rejected(tmp_path, change):
    for path in INPUTS.glob("*.log"):
        (tmp_path / path.name).symlink_to(path)
    marker = dict(sync_flag_reuse=True, flag_count=1, retained_device_capacity_bytes=256,
                  host_owner_bytes=42104) | change
    (tmp_path / "sync.log").write_text("C71_SYNC_ERROR_FLAG_REUSE " + json.dumps(marker) + "\n")
    with pytest.raises(ValueError, match="flag retention"):
        compute(tmp_path)
