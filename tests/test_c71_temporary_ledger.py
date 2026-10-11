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


def prepare_inputs(directory, *, export=True):
    # Upgrade copies of the historical fixture; immutable receipts stay intact.
    prefix = "C71_PUBLIC_METADATA_TELEMETRY "
    for path in INPUTS.glob("*.log"):
        lines = path.read_text().splitlines()
        for i, line in enumerate(lines):
            if export and prefix in line:
                before, payload = line.split(prefix, 1)
                marker = json.loads(payload)
                marker["certificate_export_heap_upper_bytes"] = 32768
                marker["crypto_live_metadata_heap_upper_bytes"] += 32768
                lines[i] = before + prefix + json.dumps(marker)
        (directory / path.name).write_text("\n".join(lines) + "\n")


def compute(directory, *, rms_candidates=False):
    return LEDGER.ledger(directory, "s1-prepared",
        ROOT / "benchmarks/results/c71-crypto-query-local-2026-10-09-46d295ef4ea6.json",
        ROOT / "benchmarks/results/c71-crypto-linear-local-2026-10-09-31280382f681.json",
        ROOT / "benchmarks/results/c71-crypto-retirement-local-2026-10-09-96b69ded52c1.json",
        rms_candidates=rms_candidates)


def test_retained_sync_flag_is_charged_until_native_cleanup(tmp_path):
    prepare_inputs(tmp_path)
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


def test_AES_setup_keeps_the_already_installed_W_cache_and_owner(tmp_path):
    prepare_inputs(tmp_path)
    phases = {r["phase"]: r for r in compute(tmp_path)["named_phase_crosschecks"]}
    parts = phases["real_AES_seed6_setup"]["parts"]
    installed = phases["native_initial_W_install"]["parts"]
    for key in ("initial_W_and_A_root_offset_caches", "retained_initial_private_host_pads",
                "native_common_owner_host"):
        assert parts[key] == installed[key] > 0
    assert parts["two_public_table_host_payloads"] == 2*24414870
    assert "full_calibration_table_serialization_difference_upper" not in parts
    assert "native_common_owner_host" not in phases["public_profile_construction"]["parts"]


def test_source_pool_reserve_is_released_before_proof_phases(tmp_path):
    prepare_inputs(tmp_path)
    before = compute(tmp_path)
    marker = dict(reserve_bytes=128 << 20, host_owner_bytes=42168,
                  initial_commitment_only=True, end_requires_empty_pool=True)
    (tmp_path / "pool.log").write_text("C71_SOURCE_POOL_PHASE " + json.dumps(marker) + "\n")
    after = compute(tmp_path)
    charged = []
    for old, new in zip(before['named_phase_crosschecks'], after['named_phase_crosschecks']):
        extra = new['parts'].get('initial_A_stream_ordered_pool_reserve', 0)
        if extra:
            charged.append(new['phase'])
            assert extra == 128 << 20
        owner_delta = 42168-old['parts']['native_common_owner_host'] if 'native_common_owner_host' in old['parts'] else 0
        assert new['named_allocation_subtotal_bytes']-old['named_allocation_subtotal_bytes'] == extra+owner_delta
    assert charged == [f'native_initial_A{i}_{phase}' for i in (1, 2, 3) for phase in ('accumulate', 'hash')]
    assert after['joint_admitted'] is False
    marker['end_requires_empty_pool'] = False
    (tmp_path / "pool.log").write_text("C71_SOURCE_POOL_PHASE " + json.dumps(marker) + "\n")
    with pytest.raises(ValueError, match='source pool lifetime'):
        compute(tmp_path)


@pytest.mark.parametrize("change", [dict(retained_device_capacity_bytes=0), dict(flag_count=2),
                                  dict(host_owner_bytes=1), dict(sync_flag_reuse=False)])
def test_invalid_retention_receipt_is_rejected(tmp_path, change):
    prepare_inputs(tmp_path)
    marker = dict(sync_flag_reuse=True, flag_count=1, retained_device_capacity_bytes=256,
                  host_owner_bytes=42104) | change
    (tmp_path / "sync.log").write_text("C71_SYNC_ERROR_FLAG_REUSE " + json.dumps(marker) + "\n")
    with pytest.raises(ValueError, match="flag retention"):
        compute(tmp_path)


def test_current_ledger_rejects_receipt_without_certificate_export(tmp_path):
    prepare_inputs(tmp_path, export=False)
    with pytest.raises(ValueError, match="certificate export"):
        compute(tmp_path)


@pytest.mark.parametrize("granularity", [65536, 2097152])
def test_source_vmm_accounts_rounding_and_only_public_lifetimes(tmp_path, granularity):
    prepare_inputs(tmp_path)
    before = compute(tmp_path)
    marker = dict(host_owner_bytes=50848, granularity_bytes=granularity,
                  kv_columns=[2048]*20+[4096]*100, live_columns=[99, 107, 116],
                  preserves_shared_handles=True)
    (tmp_path / "vmm.log").write_text("C71_SOURCE_VMM " + json.dumps(marker) + "\n")
    after = compute(tmp_path)
    rounded = lambda n: (n+granularity-1)//granularity*granularity
    full = sum(rounded(450*c*2) for c in marker['kv_columns'])
    prefix = sum(rounded(150*c*2) for c in marker['kv_columns'])
    changed = []
    for old, new in zip(before['named_phase_crosschecks'], after['named_phase_crosschecks']):
        parts = new['parts']
        delta = 50848-old['parts']['native_common_owner_host'] if 'native_common_owner_host' in old['parts'] else 0
        if 'device_persistent_or_single_replay_envelope' in parts:
            delta += full-405504000
            if new['phase'] in ('native_initial_A1_accumulate', 'native_initial_A1_hash'):
                delta -= full-prefix
        if new['phase'].startswith('native_initial_A') and new['phase'].endswith('_accumulate'):
            changed.append(new['phase'])
            columns = marker['live_columns'][int(new['phase'][16])-1]
            delta -= (128-columns)*4*(1 << 20)*8
        assert new['named_allocation_subtotal_bytes']-old['named_allocation_subtotal_bytes'] == delta
    assert changed == [f'native_initial_A{i}_accumulate' for i in (1, 2, 3)]
    assert after['credit'] is False and after['allowance_physically_verified'] is False


def test_source_vmm_pool_requires_combined_lifetime_receipt(tmp_path):
    prepare_inputs(tmp_path)
    marker = dict(host_owner_bytes=50880, granularity_bytes=2097152,
                  kv_columns=[2048]*20+[4096]*100, live_columns=[99, 107, 116],
                  preserves_shared_handles=True)
    pool = dict(reserve_bytes=128 << 20, host_owner_bytes=50880,
                initial_commitment_only=True, end_requires_empty_pool=True)
    (tmp_path / "pool.log").write_text("C71_SOURCE_POOL_PHASE " + json.dumps(pool) + "\n")
    (tmp_path / "vmm.log").write_text("C71_SOURCE_VMM " + json.dumps(marker) + "\n")
    with pytest.raises(ValueError, match="deferred source backing"):
        compute(tmp_path)
    marker['pool_lifetime_parity'] = True
    (tmp_path / "vmm.log").write_text("C71_SOURCE_VMM " + json.dumps(marker) + "\n")
    after = compute(tmp_path)
    phases = {r['phase']: r for r in after['named_phase_crosschecks']}
    for caches in (1, 2, 3):
        for suffix in ('accumulate', 'hash'):
            row = phases[f'native_initial_A{caches}_{suffix}']
            assert row['parts']['initial_A_stream_ordered_pool_reserve'] == 128 << 20
            assert not row['named_subtotal_exceeds_payload']
    assert 'initial_A_stream_ordered_pool_reserve' not in phases['proof_A1_RMS_GKR_steady']['parts']


def test_rms_candidates_have_separate_lifetimes_and_keep_joint_owners(tmp_path):
    prepare_inputs(tmp_path)
    # Reuse the frozen combined lifetime receipt, including measured 2 MiB pages.
    frozen = ROOT / 'benchmarks/results/c71-certificates-vmm-pool-local-2026-10-11-6ccb54a1'
    for name in ('inputs-pool.log', 'inputs-vmm.log'):
        (tmp_path / name).write_bytes((frozen / name).read_bytes())
    before = compute(tmp_path)
    after = compute(tmp_path, rms_candidates=True)
    baseline = {r['phase']: r for r in before['named_phase_crosschecks']}
    phases = {r['phase']: r for r in after['named_phase_crosschecks']}
    assert len(phases) == len(baseline)+6
    for name, row in baseline.items():
        assert phases[name] == row
    for i in (1, 2, 3):
        original = baseline[f'proof_A{i}_RMS_GKR_steady']
        cell = phases[f'proof_A{i}_RMS_GKR_candidate_cell']
        byte = phases[f'proof_A{i}_RMS_GKR_candidate_byte']
        for row in (cell, byte):
            # Includes caller CompactFrames, claims, W/KV, Writer, PCG and VMM.
            for key, value in original['parts'].items():
                assert row['parts'][key] == value
            assert 'initial_A_stream_ordered_pool_reserve' not in row['parts']
            assert row['named_allocation_subtotal_bytes'] == sum(row['parts'].values())
            assert row['remaining_shared_payload_capacity_bytes'] == (
                after['enforced_joint_allocation_limit_bytes']-sum(row['parts'].values()))
            assert row['is_complete_phase_peak'] is False
        assert cell['named_allocation_subtotal_bytes']-original['named_allocation_subtotal_bytes'] == 48 << 20
        assert not any('_byte_' in key for key in cell['parts'])
        assert not any('_folded_cache_' in key or '_shared_gate_' in key for key in byte['parts'])
        assert byte['parts']['class6_RMS_byte_LUT_nodes'] == 100466688
        assert byte['parts']['class6_RMS_byte_contraction_evaluator_capacity_upper'] == 32 << 20
        assert byte['parts']['class6_RMS_byte_tree_proof_and_triples_upper'] == 43584
        assert byte['parts']['class6_RMS_retained_proof_and_triples_moving_upper'] > 128*64*8*24
    # Adding an RMS candidate must not hide the existing O300 PCS excess.
    maximum = max(phases.values(), key=lambda r: r['named_allocation_subtotal_bytes'])
    assert maximum['phase'] == 'native_E_D34_A3_S2_predecessor_E_query_publication'
    assert maximum['named_subtotal_exceeds_payload'] is True
    assert after['rms_candidates_modeled'] is True
    assert after['rms_candidates_selected_in_canonical_runner'] is False
    assert after['credit'] is False and after['joint_admitted'] is False
    assert after['allowance_physically_verified'] is False


@pytest.mark.parametrize('backend', ['legacy', 'native-2026-10-09', 'unknown'])
def test_rms_candidates_reject_incomplete_backend(tmp_path, backend):
    with pytest.raises(ValueError, match='prepared complete-capacity ledger'):
        LEDGER.ledger(tmp_path, backend, rms_candidates=True)
