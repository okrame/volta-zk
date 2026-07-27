import copy
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


def load_report_module():
    path = Path(__file__).resolve().parents[1] / "scripts" / "report.py"
    spec = importlib.util.spec_from_file_location("p7_report", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def test_pcs_formula_matches_p6_opening_bytes():
    report = load_report_module()

    layer = report.multi_open_breakdown(report.LAYER_PARAMS, 8)
    embed = report.multi_open_breakdown(report.EMBED_PARAMS, 6)

    assert layer["total"] == 4_293_216
    assert embed["total"] == 15_214_912
    assert 12 * layer["total"] + embed["total"] == 66_733_504


def test_query_error_threshold_for_same_rate_q60():
    report = load_report_module()

    assert 80.0 <= report.query_error_bits(report.LAYER_PARAMS) <= 81.0
    assert report.queries_for_bits(report.LAYER_PARAMS, 60.0) == 150


def test_p7_report_selects_record_and_packed_sources():
    report = load_report_module()

    data = report.p7_report(report.DEFAULT_RESULTS)

    assert data["pcs_formula_check"]["matches_p6_measured_bytes"] is True
    assert data["baseline"]["source"].endswith("p6-2026-07-11-f72e4dd.json")
    assert data["baseline"]["cloud"]["provider"] == "Thunder Compute"
    assert data["report_schema_version"] == 4
    assert data["cloud"]["instance_id"] == "tc-machineid-sha256-42069fd5fa86"
    assert data["cloud"] != data["baseline"]["cloud"]
    assert data["communication"]["packed_logits_source"].endswith("p6-2026-07-11-f72e4dd.json")
    c1 = data["c1_communication_reference"]
    assert c1["source"].endswith("c1-2026-07-15-2a3d731.json")
    assert c1["response_transcript_bytes"] == 129_119_408
    assert c1["packed_response_bytes"] == 136_526_530
    assert c1["identity_seam_alias_values"] == 1_036_800
    assert c1["historical_runpod_a100_v1_packed_response_bytes"] == 144_820_930
    required = data["gpu_budget_model"]["required_relative_prover_vs_native_speedup"]
    assert 2.051 < required["prefill"] < 2.052
    assert 4.146 < required["decode"] < 4.147
    assert data["gpu_budget_model"]["targets"] == {"prefill": 10.0, "decode": 2.0}
    roofline = data["gpu_roofline"]["run_of_record"]
    assert roofline["source"].endswith("p7-gpu-roofline-2026-07-11-a43d105.json")
    assert roofline["correctness"] is True
    assert roofline["timing_sane"] is True
    assert roofline["stream_gpu_cpu_speedup"] == 55.4816444611
    assert roofline["chain_gpu_cpu_speedup"] == 300.94133017
    assert all("5ead965" not in row["source"] for row in data["gpu_roofline"]["profiles"])
    fused = data["gpu_fused_epilogue"]["run_of_record"]
    assert fused["source"].endswith("p7-gpu-fused-epilogue-2026-07-11-bde5d7d.json")
    assert fused["correctness"] is True
    assert fused["gate_weighted_rho_le_1_30"] is True
    assert fused["weighted_rho_kernel"] == 1.003056933
    logup = data["gpu_logup_tree"]["run_of_record"]
    assert logup["source"].endswith("p7-gpu-logup-tree-2026-07-11-5f7b443.json")
    assert logup["correctness"] is True
    assert logup["gate_speedup_ge_5_48"] is True
    assert logup["gpu_cpu_speedup"] == 66.1188534508
    assert any(
        row["milestone"] == "P7-gpu-logup-tree-quick"
        and row["gate_speedup_ge_5_48"] is False
        for row in data["gpu_logup_tree"]["profiles"]
    )
    rounds = data["gpu_logup_rounds"]["run_of_record"]
    assert rounds["source"].endswith("p7-gpu-logup-rounds-2026-07-11-f7f54a2.json")
    assert rounds["correctness"] is True
    assert rounds["gate_speedup_ge_5_48"] is True
    assert rounds["gpu_cpu_speedup"] == 8.92029391681
    assert any(
        row["milestone"] == "P7-gpu-logup-rounds-quick"
        and row["gate_speedup_ge_5_48"] is False
        for row in data["gpu_logup_rounds"]["profiles"]
    )
    assert any(
        row["milestone"] == "P7-gpu-logup-rounds"
        and row["gate_speedup_ge_5_48"] is False
        for row in data["gpu_logup_rounds"]["profiles"]
    )
    pcs = data["gpu_pcs_arithmetic"]["run_of_record"]
    assert pcs["source"].endswith("p7-gpu-pcs-arithmetic-2026-07-11-366ec4a.json")
    assert pcs["correctness"] is True
    assert pcs["gate_each_speedup_ge_5_48"] is True
    assert pcs["ntt"]["gpu_cpu_speedup"] == 80.3253115046
    assert pcs["combine_rows"]["gpu_cpu_speedup"] == 76.0996903402
    blake3 = data["gpu_blake3_merkle"]["run_of_record"]
    assert blake3["source"].endswith("p7-gpu-blake3-merkle-2026-07-11-3b0a916.json")
    assert blake3["host_device_correctness"] is True
    assert blake3["root_matches_rust_blake3"] is True
    assert blake3["gate_gpu_s_le_0_075"] is True
    assert blake3["gpu_s"] == 0.001407478
    assert blake3["gpu_cpu_speedup"] == 31.10442294657536
    blind = data["gpu_logup_blind_rounds"]["run_of_record"]
    assert blind["source"].endswith("p7-gpu-logup-blind-rounds-2026-07-11-534dcad.json")
    assert blind["blind_corrections_correct"] is True
    assert blind["parameters"]["correction_bytes_total"] == 848
    assert blind["parameters"]["extra_transcript_rounds"] == 0
    assert blind["parameters"]["pinned_host_barriers"] is True
    assert blind["gpu_cpu_speedup"] == 6.4232076889
    assert blind["blind_over_clear"] == 0.903391144688
    assert blind["gate_speedup_ge_5_48_and_overhead_le_1_05"] is True
    assert any(
        row["milestone"] == "P7-gpu-logup-blind-rounds"
        and row["gate_speedup_ge_5_48_and_overhead_le_1_05"] is False
        for row in data["gpu_logup_blind_rounds"]["profiles"]
    )
    native = data["gpu_native_inference"]["run_of_record"]
    assert native["source"].endswith("p7-gpu-native-inference-2026-07-13-1fd5195.json")
    assert native["correctness"] is True
    assert native["golden_match"] is True
    assert native["prefill_s"] == 0.017341642
    assert native["decode_50_s"] == 0.599345878
    assert native["prefill_timing"]["mad_s"] == 0.000062169
    assert native["decode_50_timing"]["mad_s"] == 0.000989627
    assert native["memory"]["peak_device_bytes"] == 258_181_700
    assert native["native_gpu_speedup"]["prefill"] == 57.2201883189608
    assert native["native_gpu_speedup"]["decode"] == 3.6205070138148177
    prover_targets = data["gpu_native_inference"]["required_prover_gpu_speedup_vs_cpu"]
    assert prover_targets is None  # aggregate P6 baseline is a different instance
    proof_budget = data["gpu_native_inference"]["proof_only_budget"]
    assert abs(proof_budget["prefill_s"] - 0.17341642) < 1e-15
    assert abs(proof_budget["decode_50_s"] - 1.198691756) < 1e-15
    hybrid = data["integrated_hybrid"]["run_of_record"]
    assert hybrid["source"].endswith("p7-integrated-hybrid-2026-07-12-706d067.json")
    assert hybrid["golden_decode_match"] is True
    assert hybrid["flat_cost_gate"] is True
    assert hybrid["packed_response_bytes"] == 144_820_930
    same_host = data["integrated_hybrid"]["same_host_result"]
    assert same_host["same_instance"] is True
    assert abs(same_host["proof_rho"]["prefill"] - 2008.58387043107) < 1e-9
    assert abs(same_host["proof_rho"]["decode"] - 28.53693406240955) < 1e-9
    assert same_host["target_met"] == {"prefill": False, "decode": False}
    resident = data["integrated_resident"]["run_of_record"]
    assert resident["source"].endswith("p7-integrated-resident-2026-07-13-1fd5195.json")
    assert resident["golden_decode_match"] is True
    assert resident["flat_cost_gate"] is True
    assert resident["packed_response_bytes"] == 144_820_930
    assert resident["accelerator_resident_device_bytes_after_cleanup"] == 0
    assert resident["accelerator_workspace_device_bytes_after_cleanup"] == 104_988_720
    # Schema-3 historical records predate resident-arena cache accounting.
    assert resident["accelerator_cached_resident_device_bytes_after_cleanup"] is None
    assert resident["accelerator_cleanup_memory_accounting_ok"] is None
    assert resident["accelerator_cached_resident_device_bytes_after_cache_trim"] is None
    assert resident["accelerator_cache_trim_memory_accounting_ok"] is None
    resident_same_host = data["integrated_resident"]["same_host_result"]
    assert abs(resident_same_host["proof_rho"]["prefill"] - 3707.595455551441) < 1e-9
    assert abs(resident_same_host["proof_rho"]["decode"] - 95.59733125585956) < 1e-9
    assert resident_same_host["target_met"] == {"prefill": False, "decode": False}
    assert resident_same_host["online_accounted"]["decode_rho"] == 96.64629855684099
    assert resident_same_host["measured_resident_pipeline_s"] == {
        "prefill_inference_plus_protocol_core": 64.40694849100001,
        "response_inference_plus_online_accounted": 122.02173956600001,
        "response_inference_plus_full_session_wall": 124.175154845,
    }
    assert data["integrated_resident"]["status"] == "measured_same_host_targets_fail"
    shape_sweep = data["shape_memory_sweep"]["run_of_record"]
    assert shape_sweep["source"].endswith(
        "p7-shape-memory-sweep-2026-07-13-797f499.json"
    )
    assert all(shape_sweep["validation"].values())
    assert shape_sweep["scope"]["non_gpt2_end_to_end"] is False
    assert [row["name"] for row in shape_sweep["profiles"]] == [
        "gpt2-small",
        "llama-class-8b-dense-gqa",
        "gpt-oss-20b-moe-active",
    ]
    assert data["go_no_go"]["local_recommendation"] == (
        "resident-gates-fail-report-result-without-production-claim"
    )
    q150 = [
        row
        for row in data["measured_pcs_profiles"]
        if row["source"].endswith("p6-quick-q150-2026-07-07-fa40a1d.json")
    ]
    assert len(q150) == 1
    assert q150[0]["pcs_n_queries"] == 150
    assert q150[0]["pcs_opening_bytes_total"] == 57_822_904
    pcg = [
        row
        for row in data["real_pcg_spike"]["mock_pcg_lower_bounds"]
        if row["source"].endswith("p7-mock-pcg-2026-07-07-d16a69c.json")
    ]
    assert len(pcg) == 1
    assert pcg[0]["is_real_pcg"] is False
    assert pcg[0]["corr_sub_corrs"] == 8_479_926
    for row in data["real_pcg_spike"]["real_pcg_phase_a"]:
        assert row["is_real_pcg"] is True
        assert row["base_vole"] == "mock-stub"
        assert row["setup_comm_bytes"] == 0
        assert row["lpn_parameters"]["security_bits"] == 128
        assert row["consistency"]["ok"] is True
    for row in data["real_pcg_spike"]["real_pcg_phase_b"]:
        assert row["is_real_pcg"] is True
        # "real" is the label of the two 2026-07-07 pre-fix JSONs; the honest
        # label after the GGM-accounting fix is "setup-cost-model".
        assert row["base_vole"] in {
            "real",
            "setup-cost-model",
            "real-COPEe-WYKW-checked",
        }
        assert row["setup_comm_bytes"] > 0
        assert row["production_ready"] is False
        assert row["consistency"]["ok"] is True
    decode = [
        row
        for row in data["decode_marginal_profiles"]
        if row["source"].endswith("p6-2026-07-07-382bb56.json")
    ]
    assert len(decode) == 1
    assert decode[0]["label_sum_bytes"] == decode[0]["comm_decode_marginal_bytes"]
    assert decode[0]["top_labels"][0] == {"label": "auth_corrections", "bytes": 20_902_016}


def test_c1_record_closes_exact_reference_without_mutating_p7b():
    report = load_report_module()
    path = report.DEFAULT_RESULTS / "c1-2026-07-15-2a3d731.json"
    row = report.load_json(path)

    assert report._c1_record_valid(row) is True
    assert report.C1_PACKED_RESPONSE_REFERENCE_BYTES == 136_526_530
    assert report.P7B_PACKED_RESPONSE_REFERENCE_BYTES == 144_820_930


def test_x4_v4_validators_pin_profile_bytes_events_and_incomplete_pod_scope():
    report = load_report_module()
    cpu = {
        "schema": 2,
        "milestone": "X4-v4-CPU-synthetic",
        "git_dirty": False,
        "git_sha": "a" * 40,
        "profile": report.X4_V4_PROFILE,
        "design_sha256": report.X4_V4_DESIGN_SHA256,
        "query_count": 111,
        "soundness_expression": report.X4_V4_SOUNDNESS_EXPRESSION,
        "soundness_bits": report.X4_V4_SOUNDNESS_BITS,
        "required_soundness_bits": report.X4_V4_SOUNDNESS_FLOOR_BITS,
        "soundness_resummed_new_terms": 0,
        "security_counter_inventory": report.X4_V4_COUNTER_FAMILIES,
        "touched_family": [
            {
                "touched_blocks": touched,
                "accepted": True,
                "bytes": {"closed_formula_total": 10 + touched, "serialized_total": 10 + touched},
            }
            for touched in (1, 2, 4, 8, 16)
        ],
        "recompute_case": {
            "policy": "RecomputeOracleAndMerkle",
            "traffic": {
                "recomputed_source_bytes_read": 1,
                "recomputed_oracle_bytes": 1,
                "recomputed_merkle_bytes": 1,
            },
        },
        "recompute_matches_persisted_response": True,
        "abba": {"order": "A/B/B/A", "ceiling": 1.05, "pass": True},
        "gate": {
            "g5_verdict": "PASS",
            "g6_verdict": "PASS",
            "overall_x4_verdict": "NOT_EVALUATED_UNTIL_GPT2_MIGRATION_AND_A100_RECORDS",
        },
    }
    assert report._x4_v4_cpu_result_valid(cpu) is True
    bad_cpu = copy.deepcopy(cpu)
    bad_cpu["security_counter_inventory"].remove("beta_collision_witness")
    assert report._x4_v4_cpu_result_valid(bad_cpu) is False

    migration = {
        "schema": 1,
        "milestone": "X4-v4-GPT2-migration",
        "git_dirty": False,
        "git_sha": "b" * 40,
        "profile": report.X4_V4_PROFILE,
        "design_sha256": report.X4_V4_DESIGN_SHA256,
        "query_count": 111,
        "rate": "1/8",
        "maximum_claim_union": 3320,
        "soundness_expression": report.X4_V4_SOUNDNESS_EXPRESSION,
        "soundness_bits": report.X4_V4_SOUNDNESS_BITS,
        "soundness_floor_bits": report.X4_V4_SOUNDNESS_FLOOR_BITS,
        "soundness_resummed_new_terms": 0,
        "codec": {
            "opened_symbols": 27_564,
            "all_real_sibling_digests": 67_930,
            "packed_opening_frame": 2_615_414,
            "summed_bytes": 2_683_236,
            "serialized_bytes": 2_683_236,
            "encoded_sha256": "c" * 64,
        },
        "complete_pcs_bytes": 2_683_236,
        "g3_limit_bytes": 4_000_000,
        "g3_headroom_bytes": 1_316_764,
        "non_pcs_response_bytes": 41_270_464,
        "measured_response_bytes": 43_953_700,
        "response_limit_bytes": 45_270_464,
        "response_headroom_bytes": 1_316_764,
        "correlations_gpt2_claim_reduction": 2_208,
        "correlations_gpt2_seam": 106,
        "correlations_gpt2_total": 2_314,
        "logical_first_oracle_floor_bytes": 31_923_699_712,
        "production_codec": True,
        "cryptographic_oracle_materialized": False,
        "golden_decode": {
            "prompt_tokens": 100,
            "decode_tokens": 50,
            "checked": True,
            "exact_match": True,
        },
        "historical_records": [{"unchanged": True}] * 3,
        "historical_rows_mutated": False,
        "gate": {
            "g3_communication": "PASS — exact",
            "overall_x4": "NOT EVALUATED UNTIL A100 RECORDS",
        },
    }
    assert report._x4_v4_migration_result_valid(migration) is True
    bad_migration = copy.deepcopy(migration)
    bad_migration["codec"]["all_real_sibling_digests"] -= 1
    assert report._x4_v4_migration_result_valid(bad_migration) is False


def test_x4d_codec_reference_validator_is_exact_and_fail_closed(tmp_path):
    report = load_report_module()
    record_path = (
        report.DEFAULT_RESULTS
        / "x4d-codec-reference-2026-07-25-16e6c40.json"
    )
    row = json.loads(record_path.read_text())
    assert report._x4d_codec_reference_valid(row) is True
    assert report.validate_x4d_codec_reference(record_path) is True

    invalid = []
    bad = copy.deepcopy(row)
    bad["schema"] = True
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["git_sha"] = "f" * 40
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["git_dirty"] = True
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["historical_references_modified"] = True
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["proof_or_gate_verdict"] = True
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["response"]["materialized_wire_fixture"] = True
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["response"]["exact_response_bytes"] += 1
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["settlements"].reverse()
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["settlements"][2]["serialized_bytes"] += 1
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["settlements"][3]["sha256"] = "0" * 64
    invalid.append(bad)
    bad = copy.deepcopy(row)
    bad["unexpected"] = "schema extension without version bump"
    invalid.append(bad)

    for index, candidate in enumerate(invalid):
        path = tmp_path / f"invalid-x4d-{index}.json"
        path.write_text(json.dumps(candidate))
        assert report._x4d_codec_reference_valid(candidate) is False
        assert report.validate_x4d_codec_reference(path) is False

    amendment_path = (
        report.DEFAULT_RESULTS
        / "x4d-codec-reference-amendment1-2026-07-25-4efa5f6.json"
    )
    amendment = json.loads(amendment_path.read_text())
    assert report._x4d_codec_reference_valid(amendment) is True
    assert report.validate_x4d_codec_reference(amendment_path) is True
    assert amendment["settlements"][3]["serialized_bytes"] == 4_371_564
    assert amendment["settlements"][3]["settlement_bytes_per_response"] == 136_611.375

    bad_amendment = copy.deepcopy(amendment)
    bad_amendment["settlements"][0]["fixed_size_padding_bytes"] -= 1
    assert report._x4d_codec_reference_valid(bad_amendment) is False
    bad_amendment = copy.deepcopy(amendment)
    bad_amendment["fresh_query_length_semantics"] = "selected query tape"
    assert report._x4d_codec_reference_valid(bad_amendment) is False


def _x4d_phase3_hardware():
    return {
        "gpu_name": "NVIDIA A100-SXM4-80GB",
        "gpu_uuid": "GPU-11111111-2222-3333-4444-555555555555",
        "gpu_memory_mib": 81_920,
        "selected_gpu_count": 1,
        "mem_total_bytes": 300_000_000_000,
        "volume_total_bytes": 200_000_000_000,
        "volume_available_bytes": 180_000_000_000,
        "response_cpu_ids": list(range(8)),
        "settlement_cpu_ids": list(range(8, 35)),
        "split_policy_valid": True,
        "gpu_pass": True,
        "ram_pass": True,
        "volume_pass": True,
        "overall_pass": True,
    }


def _x4d_phase3_response(ordinal, role, *, prove_s=4.0):
    total = prove_s + 0.6 + 0.001
    digest = f"{ordinal + 1:064x}"
    nonce_digest = f"{ordinal + 101:064x}"
    raw = 4_793_590 + 2 * (181_933 + 2)
    return {
        "ordinal": ordinal,
        "role": role,
        "response_nonce_digest": digest,
        "model_prove_s": prove_s,
        "model_verify_s": 0.6,
        "claim_freeze_s": 0.001,
        "total_g1_s": total,
        "prefill_prove_upper_s": 2.5,
        "max_decode_marginal_s": 0.03,
        "flatness_last_over_first": 1.1,
        "h2d_bytes": 1_000_000,
        "synchronization_wall_upper_s": 0.01,
        "model_transcript_bytes": 41_270_400,
        "model_mac_closure_bytes": 64,
        "response_bytes": 41_270_464,
        "pcs_bytes": 0,
        "product_state_at_delivery": "WEIGHT_PENDING",
        "transcript_replay_bytes": 41_034_112,
        "transcript_replay_labels": 25,
        "correlations_consumed": raw,
        "freeze_journal": {
            "response_nonce_digest": nonce_digest,
            "first_claim_index": 102 * ordinal,
            "claim_count": 102,
            "ending_accumulator_digest": f"{ordinal + 201:064x}",
        },
        "connection_audit": {
            "response_nonce_digest": nonce_digest,
            "allocation_digest": f"{ordinal + 301:064x}",
            "channel_ledger_digest": f"{ordinal + 401:064x}",
            "correlations_consumed": raw,
            "channel_frames": 0,
        },
        "accepted": True,
    }


def _x4d_phase3_online_fixture(report, onboarding, onboarding_sha):
    roles = [
        "g1-warmup",
        "g1-measured",
        "g1-measured",
        "g1-measured",
        *["connection-fill"] * 10,
        "abba-isolated-a1",
        "connection-fill",
        "abba-settlement-queued-b",
        "abba-settlement-queued-b",
        "abba-isolated-a2",
    ]
    responses = [
        _x4d_phase3_response(
            ordinal,
            role,
            prove_s=4.099 if ordinal in (16, 17) else 4.0,
        )
        for ordinal, role in enumerate(roles)
    ]
    g1 = {
        "selected_total_s": 4.601,
        "selected_claim_freeze_s": 0.001,
        "selected_prefill_upper_s": 2.5,
        "selected_decode_marginal_s": 0.03,
        "selected_h2d_bytes": 1_000_000,
        "selected_sync_wall_upper_s": 0.01,
        "selected_flatness": 1.1,
        "total_pass": True,
        "freeze_pass": True,
        "prefill_pass": True,
        "decode_pass": True,
        "h2d_pass": True,
        "sync_pass": True,
        "flatness_pass": True,
        "overall_pass": True,
    }
    isolated = [responses[14]["total_g1_s"], responses[18]["total_g1_s"]]
    queued = [responses[16]["total_g1_s"], responses[17]["total_g1_s"]]
    isolated_upper = max(isolated)
    queued_upper = max(queued)
    isolated_upper_ns = int(isolated_upper * 1e9)
    queued_upper_ns = int(queued_upper * 1e9)
    delta = (queued_upper_ns - isolated_upper_ns) / 1e9
    settlement = {
        "responses": 16,
        "frozen_claims": 1_632,
        "masked_groups": 816,
        "settlement_epoch": 1,
        "settlement_bytes": report.X4D_PHASE3_SETTLEMENT_BYTES,
        "expected_settlement_bytes": report.X4D_PHASE3_SETTLEMENT_BYTES,
        "amortized_settlement_bytes_per_response":
            report.X4D_PHASE3_SETTLEMENT_BYTES / 16,
        "historical_four_mb_scope": "4,000,000 B is the immutable X4/X4b/X4c per-response PCS ceiling; X4d settlement uses the pinned batch formula",
        "seal_to_terminal_wall_s": 10.0,
        "proof_driver_wall_s": 2.0,
        "auxiliary_materialization_wall_s": 1.0,
        "response_priority_pause_wall_s": 1.0,
        "active_cpu_host_window_s": 3.0,
        "active_gpu_lease_host_window_s": 2.0,
        "lease_wait_wall_s": 0.0,
        "open_wall_s": 0.13,
        "verify_wall_s": 0.06,
        "open_pass": True,
        "verify_pass": True,
        "every_covered_response_weight_verified": True,
        "exact_bytes": True,
        "exact_correlations": True,
        "fresh_auxiliary_masks": 51,
        "static_weight_roots_reused": 3,
        "query_draws": 111,
        "soundness_expression": report.X4D_SOUNDNESS_EXPRESSION,
        "soundness_bits": report.X4D_SOUNDNESS_BITS,
        "interference": {
            "order": "A1,B1,B2,A2",
            "isolated_response_s": isolated,
            "settlement_queued_response_s": queued,
            "isolated_upper_median_s": isolated_upper,
            "settlement_queued_upper_median_s": queued_upper,
            "absolute_delta_s": delta,
            "percentage_delta": (
                100.0
                * (queued_upper_ns - isolated_upper_ns)
                / isolated_upper_ns
            ),
            "settlement_cpu_overlap_intervals": 0,
            "settlement_gpu_overlap_intervals": 0,
            "accounting_semantics": "B responses execute under strict response priority while the sealed settlement is queued; no CPU/GPU interval is falsely reported concurrent",
        },
        "accepted": True,
    }
    roots = onboarding["warmup_root_set"]
    return {
        "schema": 1,
        "milestone": report.X4D_PHASE3_ONLINE_MILESTONE,
        "git_sha": "a" * 40,
        "git_dirty": False,
        "producer_source_sha256": report.X4D_PHASE3_PRODUCER_SHA256,
        "profile": report.X4D_PHASE3_PROFILE,
        "protocol": report.X4D_PHASE3_PROTOCOL,
        "design_sha256": report.X4D_PHASE3_DESIGN_SHA256,
        "cloud": {
            "provider": "RunPod",
            "instance_id": "pod-test",
            "region": "EU",
            "image": "cuda",
            "driver_version": "570",
            "cuda_version": "12.8",
            "gpu_sku": "NVIDIA A100-SXM4-80GB",
            "cpu_model": "test",
            "ram_gib": "300",
            "vcpus": "64",
        },
        "hardware": _x4d_phase3_hardware(),
        "onboarding_path": "/remote/onboarding.json",
        "onboarding_sha256": onboarding_sha,
        "onboarding_exact": True,
        "crypto_build_id_scheme": onboarding["crypto_build_id_scheme"],
        "crypto_build_id": onboarding["crypto_build_id"],
        "durable_tier_bytes": 9_618_587_808,
        "rebuild_wall_s": 10.0,
        "rebuild_rows": [
            {"cohort_id": cohort_id, "accepted": True}
            for cohort_id in (0xA5000001, 0xA5000002, 0xA5000003, 0xA5000005, 0xA5000004)
        ],
        "rebuild_roots": roots,
        "rebuild_roots_equal_onboarding": True,
        "old_auxiliary_roots_rejected_for_settlement": True,
        "setup_wall_s": 10.0,
        "responses": responses,
        "g1": g1,
        "settlement": settlement,
        "cap_test_name": "claim_3321_refuses_until_settlement_succeeds",
        "cap_3321_permanent_test_present": True,
        "cap_preflight_3321_rejected": True,
        "soundness_expression_byte_exact": True,
        "g2_permanent_tests": report.X4D_PHASE3_G2_TESTS,
        "g6_test_name": "explicit_abort_before_settlement_marks_pending_terminal_unverified",
        "g6_abort_before_settlement_terminal_unverified": True,
        "no_retry_same_connection": True,
        "provider_contract_state_at_delivery": "complete and fully authenticated; weight consistency WEIGHT_PENDING",
        "provider_contract_state_at_settlement": "covered response set pronounced WEIGHT_VERIFIED only after settlement acceptance",
        "historical_rows_modified": False,
        "overall_pass": True,
    }


def test_x4d_phase3_validators_are_chained_and_fail_closed(tmp_path):
    report = load_report_module()
    preflight = {
        "schema": 1,
        "milestone": report.X4D_PHASE3_PREFLIGHT_MILESTONE,
        "git_sha": "a" * 40,
        "git_dirty": False,
        "profile": report.X4D_PHASE3_PROFILE,
        "protocol": report.X4D_PHASE3_PROTOCOL,
        "design_sha256": report.X4D_PHASE3_DESIGN_SHA256,
        "producer_source_sha256": report.X4D_PHASE3_PRODUCER_SHA256,
        "hardware": _x4d_phase3_hardware(),
        "inputs_exact": True,
        "soundness_expression": report.X4D_SOUNDNESS_EXPRESSION,
        "soundness_bits": report.X4D_SOUNDNESS_BITS,
        "overall_pass": True,
    }
    assert report._x4d_phase3_preflight_valid(preflight) is True
    preflight_path = tmp_path / "preflight.json"
    preflight_path.write_text(json.dumps(preflight))
    assert report.validate_x4d_phase3_preflight(preflight_path) is True

    roots = [f"{index + 1:064x}" for index in range(5)]
    onboarding = {
        "schema": 3,
        "milestone": "X4c-GPT2-real-weight-onboarding-crypto-id-v1",
        "git_dirty": False,
        "overall_pass": True,
        "crypto_build_id_scheme": "volta-x4c-crypto-build-v1",
        "crypto_build_id": "c" * 64,
        "warmup_root_set": roots,
    }
    onboarding_path = tmp_path / "onboarding.json"
    onboarding_path.write_text(json.dumps(onboarding))
    onboarding_sha = hashlib.sha256(onboarding_path.read_bytes()).hexdigest()
    online = _x4d_phase3_online_fixture(report, onboarding, onboarding_sha)
    assert report._x4d_phase3_online_valid(online, onboarding, onboarding_sha) is True
    online_path = tmp_path / "online.json"
    online_path.write_text(json.dumps(online))
    assert report.validate_x4d_phase3_online(online_path, onboarding_path) is True

    invalid = []
    bad = copy.deepcopy(preflight)
    bad["hardware"]["mem_total_bytes"] -= 100_000_000_000
    invalid.append(("preflight", bad))
    bad = copy.deepcopy(online)
    bad["responses"][16]["product_state_at_delivery"] = "WEIGHT_VERIFIED"
    invalid.append(("online", bad))
    bad = copy.deepcopy(online)
    bad["settlement"]["settlement_bytes"] = 3_439_595
    invalid.append(("online", bad))
    bad = copy.deepcopy(online)
    bad["settlement"]["interference"]["settlement_gpu_overlap_intervals"] = 1
    invalid.append(("online", bad))
    bad = copy.deepcopy(online)
    bad["g2_permanent_tests"].pop()
    invalid.append(("online", bad))
    bad = copy.deepcopy(online)
    bad["historical_rows_modified"] = True
    invalid.append(("online", bad))
    bad = copy.deepcopy(online)
    bad["unexpected"] = "unversioned schema extension"
    invalid.append(("online", bad))

    for kind, candidate in invalid:
        if kind == "preflight":
            assert report._x4d_phase3_preflight_valid(candidate) is False
        else:
            assert (
                report._x4d_phase3_online_valid(
                    candidate, onboarding, onboarding_sha
                )
                is False
            )


def test_x4d1_flatness_validator_keeps_informative_wall_out_of_gate(tmp_path):
    report = load_report_module()

    def run_summary(responses, wall, interference):
        return {
            "input_path": f"/records/x4d1-k{responses}.json",
            "input_sha256": f"{responses:064x}",
            "responses": responses,
            "settlement_wall_s": wall,
            "selected_g1_wall_s": 4.90,
            "g1_overall_pass": True,
            "settlement_accepted": True,
            "min_response_wall_s": 4.87,
            "max_response_wall_s": 5.04,
            "response_bytes": report.X4D1_RESPONSE_BYTES,
            "interference_percentage_delta": interference,
            "initial_encoded_symbols_read": report.X4D1_INITIAL_ENCODED_SYMBOLS,
            "combined_codeword_symbols": report.X4D1_COMBINED_CODEWORD_SYMBOLS,
            "materialized_relation_terms": 102,
            "fused_relation_terms": 102 * (responses - 1),
        }

    row = {
        "schema": 1,
        "milestone": report.X4D1_FLATNESS_MILESTONE,
        "git_sha": "a" * 40,
        "git_dirty": False,
        "producer_source_sha256": report.X4D1_FLATNESS_PRODUCER_SHA256,
        "profile": report.X4D_PHASE3_PROFILE,
        "protocol": report.X4D_PHASE3_PROTOCOL,
        "design_sha256": report.X4D1_DESIGN_SHA256,
        "same_host": True,
        "wall_semantics": report.X4D1_WALL_SEMANTICS,
        "k1": run_summary(1, 300.0, 0.2),
        "k16": run_summary(16, 350.0, 0.4),
        "settlement_wall_ratio_k16_over_k1": 350.0 / 300.0,
        "flatness_ceiling": 1.30,
        "wall_flatness_pass": True,
        "initial_encoded_symbols_equal": True,
        "combined_codeword_symbols_equal": True,
        "physical_counter_gate_pass": True,
        "g1_rerun_pass": True,
        "response_bytes_unchanged": True,
        "interference_ceiling_percentage_delta": 1.0,
        "interference_rerun_pass": True,
        "inherited_settlement_gates_pass": True,
        "binding_gate_verdict_verbatim": (
            "PASS — FLATNESS IN k: settlement_wall(k=16) <= 1.30 x "
            "settlement_wall(k=1), with equal initial_encoded_symbols_read and "
            "combined_codeword_symbols"
        ),
        "informative_target": {
            "lower_s": 288.0,
            "upper_s": 307.0,
            "k16_at_or_below_upper": False,
            "affects_binding_gate": False,
            "policy": (
                "Informative only: a 350 s k=16 wall with a green flatness gate "
                "is PASS with a note, not FAIL"
            ),
        },
        "historical_rows_modified": False,
        "overall_pass": True,
    }
    assert report._x4d1_flatness_valid(row) is True
    path = tmp_path / "x4d1-flatness.json"
    path.write_text(json.dumps(row))
    assert report.validate_x4d1_flatness(path) is True

    bad = copy.deepcopy(row)
    bad["informative_target"]["affects_binding_gate"] = True
    assert report._x4d1_flatness_valid(bad) is False
    bad = copy.deepcopy(row)
    bad["k16"]["initial_encoded_symbols_read"] += 1
    assert report._x4d1_flatness_valid(bad) is False
    bad = copy.deepcopy(row)
    bad["settlement_wall_ratio_k16_over_k1"] = 1.31
    assert report._x4d1_flatness_valid(bad) is False


def test_x4d2_flatness_validator_requires_every_physical_counter(tmp_path):
    report = load_report_module()

    def run_summary(responses, wall, interference):
        return {
            "input_path": f"/records/x4d2-k{responses}.json",
            "input_sha256": f"{responses:064x}",
            "responses": responses,
            "settlement_wall_s": wall,
            "selected_g1_wall_s": 4.90,
            "g1_overall_pass": True,
            "settlement_accepted": True,
            "min_response_wall_s": 4.87,
            "max_response_wall_s": 5.04,
            "response_bytes": report.X4D1_RESPONSE_BYTES,
            "interference_percentage_delta": interference,
            "claim_reduce_calls": 51 * responses,
            "claim_reduce_frozen_claims": 102 * responses,
            "claim_reduce_unique_sources": report.X4D2_UNIQUE_CLAIM_REDUCE_SOURCES,
            "claim_reduce_unique_source_symbols": (
                report.X4D2_UNIQUE_CLAIM_REDUCE_SOURCE_SYMBOLS
            ),
            "unique_evaluation_table_symbols": (
                report.X4D2_UNIQUE_EVALUATION_TABLE_SYMBOLS
            ),
            "encoded_oracle_full_passes": 1,
            "query_gather_calls": 1,
            "initial_encoded_symbols_read": report.X4D1_INITIAL_ENCODED_SYMBOLS,
            "combined_codeword_symbols": report.X4D1_COMBINED_CODEWORD_SYMBOLS,
            "materialized_relation_terms": 102,
            "fused_relation_terms": 102 * (responses - 1),
        }

    equality_fields = [
        "initial_encoded_symbols_equal",
        "combined_codeword_symbols_equal",
        "unique_evaluation_table_symbols_equal",
        "unique_claim_reduce_source_symbols_equal",
        "encoded_oracle_full_passes_equal",
        "query_gather_calls_equal",
    ]
    row = {
        "schema": 2,
        "milestone": report.X4D2_FLATNESS_MILESTONE,
        "git_sha": "b" * 40,
        "git_dirty": False,
        "producer_source_sha256": report.X4D2_FLATNESS_PRODUCER_SHA256,
        "profile": report.X4D_PHASE3_PROFILE,
        "protocol": report.X4D_PHASE3_PROTOCOL,
        "design_sha256": report.X4D2_DESIGN_SHA256,
        "same_host": True,
        "wall_semantics": report.X4D1_WALL_SEMANTICS,
        "k1": run_summary(1, 300.0, 0.2),
        "k16": run_summary(16, 350.0, 0.4),
        "settlement_wall_ratio_k16_over_k1": 350.0 / 300.0,
        "flatness_ceiling": 1.30,
        "wall_flatness_pass": True,
        **{field: True for field in equality_fields},
        "physical_counter_gate_pass": True,
        "g1_rerun_pass": True,
        "response_bytes_unchanged": True,
        "interference_ceiling_percentage_delta": 1.0,
        "interference_rerun_pass": True,
        "inherited_settlement_gates_pass": True,
        "binding_gate_verdict_verbatim": (
            "PASS — FLATNESS IN k: settlement_wall(k=16) <= 1.30 x "
            "settlement_wall(k=1), with equal initial_encoded_symbols_read, "
            "combined_codeword_symbols, unique physical evaluation/source "
            "symbols, encoded-oracle pass count and query-gather count"
        ),
        "informative_target": {
            "lower_s": 288.0,
            "upper_s": 307.0,
            "k16_at_or_below_upper": False,
            "affects_binding_gate": False,
            "policy": (
                "Informative only: a 350 s k=16 wall with a green flatness gate "
                "is PASS with a note, not FAIL"
            ),
        },
        "historical_rows_modified": False,
        "overall_pass": True,
    }
    assert report._x4d2_flatness_valid(row) is True
    path = tmp_path / "x4d2-flatness.json"
    path.write_text(json.dumps(row))
    assert report.validate_x4d2_flatness(path) is True

    for summary_field in (
        "claim_reduce_unique_source_symbols",
        "unique_evaluation_table_symbols",
        "encoded_oracle_full_passes",
        "query_gather_calls",
        "initial_encoded_symbols_read",
        "combined_codeword_symbols",
    ):
        bad = copy.deepcopy(row)
        bad["k16"][summary_field] += 1
        assert report._x4d2_flatness_valid(bad) is False
    bad = copy.deepcopy(row)
    bad["k16"]["claim_reduce_calls"] -= 1
    assert report._x4d2_flatness_valid(bad) is False


def test_x4_v4_pod_validator_accepts_only_the_fail_closed_physical_record():
    report = load_report_module()
    cohort_names = [
        "Wext-mu26-global-tied-roles",
        "Wext-mu22-all-layers",
        "Wext-mu20-layers-and-position",
        "auxiliary-ell17",
        "auxiliary-ell16",
    ]
    row = {
        "schema": 1,
        "milestone": "X4-v4-A100-production-record",
        "git_dirty": False,
        "git_sha": "d" * 40,
        "pod_profile": report.X4_V4_POD_PROFILE,
        "protocol_or_parameter_change": False,
        "machine": {
            "provider": "RunPod",
            "gpu": "NVIDIA A100-SXM4-80GB, GPU-test",
            "rayon_threads": 8,
            "timing_policy": "wall-only+counters; no CUDA-event timing",
            "memory_bytes": 2_000_000_000_000,
            "persistent_volume_available_bytes": 100_000_000_000_000,
        },
        "frozen": {
            "profile": report.X4_V4_PROFILE,
            "design_sha256": report.X4_V4_DESIGN_SHA256,
            "frozen_design_baseline_sha256": report.X4_V4_FROZEN_BASELINE_SHA256,
            "migration_sha256": report.X4_V4_MIGRATION_SHA256,
            "note6_sha256": report.X4_V4_NOTE6_SHA256,
            "rate": "1/8",
            "query_count": 111,
            "maximum_claim_union": 3320,
            "opened_symbols": 27_564,
            "real_sibling_digests": 67_930,
            "pcs_bytes": 2_683_236,
            "response_bytes": 43_953_700,
            "soundness_expression": report.X4_V4_SOUNDNESS_EXPRESSION,
            "soundness_bits": report.X4_V4_SOUNDNESS_BITS,
            "soundness_floor_bits": report.X4_V4_SOUNDNESS_FLOOR_BITS,
            "soundness_new_terms": 0,
        },
        "physical_inventory": {
            "source_equivalent_unpadded_floor_bytes": 31_923_699_712,
            "coefficient_bytes": 9_618_587_648,
            "physical_padded_first_oracle_bytes": 76_948_701_184,
            "inner_merkle_digests": 12_333_875_200,
            "outer_merkle_digests": 2_318_401_531,
            "merkle_digest_bytes": 468_872_855_392,
            "bytes_per_materialization": 545_821_556_576,
            "bytes_recomputed_per_response": 1_091_643_113_152,
            "persistent_coefficients_plus_roots_bytes": 9_618_587_808,
            "maximum_current_cohort_working_set_bytes": 363_998_478_304,
            "cohorts": [{"name": name} for name in cohort_names],
        },
        "production_commit_probe": [
            {
                "role": role,
                "exact_cohort": "Wext-mu26-global-tied-roles",
                "domain_log2": 30,
                "present_slots": 2,
                "structural_slots": 2,
                "ceiling_s": 15.0,
                "observed_wall_s": 15.05,
                "completed": False,
                "timed_out": True,
                "h2d_bytes": 0,
                "d2h_bytes": 0,
                "peak_vram_bytes": 0,
            }
            for role in ("warmup", "measured-1", "measured-2", "measured-3")
        ],
        "informative_streaming_commit": {
            "status": "MEASURED_EXACT_AUX17_ANCHOR; FULL_FLOOR_BLOCKED_BY_G4_TIMEOUT",
            "warmup_count": 1,
            "measured_candidates": 3,
            "candidate_wall_s": [1.0, 1.1, 1.2],
            "selected_upper_median_wall_s": 1.1,
            "measured_first_oracle_bytes_per_candidate": 33_554_432,
            "measured_merkle_bytes_per_candidate": 167_772_128,
            "selected_first_oracle_bytes_per_s": 30_000_000.0,
            "projected_unpadded_floor_wall_s_at_measured_rate": 1000.0,
            "projected_physical_padded_oracle_wall_s_at_measured_rate": 2500.0,
            "full_31_9gb_pass_completed": False,
        },
        "informative_per_query_cohort_recompute": {
            "query_count_per_candidate": 1,
            "candidate_wall_s": [1.0, 1.1, 1.2],
            "selected_upper_median_wall_s": 1.1,
            "source_bytes_read_per_query": 4_194_304,
            "oracle_bytes_recomputed_per_query": 33_554_432,
            "merkle_bytes_recomputed_per_query": 167_772_128,
            "total_logical_bytes_per_query": 205_520_864,
            "root_checked": True,
        },
        "informative_gpu_assisted_streaming_commit": {
            "available": False,
            "measured": False,
        },
        "gate": {
            "g1_lean": "PASS — exact",
            "g2_full_production_correctness": "NOT EVALUATED — commit failure",
            "g3_communication": "PASS — exact",
            "g4_commit": "FAIL — timeout",
            "g4_open": "NOT EVALUATED — commit failure",
            "g4_verify": "NOT EVALUATED — commit failure",
            "g6_storage_traffic": "NOT EVALUATED AS PASS — incomplete",
            "overall_x4": "FAIL — conjunctive G4 commit gate failed; no threshold was relaxed",
        },
    }
    assert report._x4_v4_pod_result_valid(row) is True
    bad = copy.deepcopy(row)
    bad["production_commit_probe"][2]["timed_out"] = False
    assert report._x4_v4_pod_result_valid(bad) is False
    bad = copy.deepcopy(row)
    bad["physical_inventory"]["physical_padded_first_oracle_bytes"] = 31_923_699_712
    assert report._x4_v4_pod_result_valid(bad) is False


def x4b_local_fixture(report):
    cpu_walls = [0.78, 0.80, 0.82, 0.76, 0.74]
    candidates = [
        {
            "wall_s": wall,
            "canonical_frame_bytes_per_s": report.X4B_CPU_CANONICAL_BYTES / wall,
            "oracle_bytes_per_s": 33_554_432 / wall,
            "hash_calls_per_s": report.X4B_CPU_HASH_CALLS / wall,
            "allocator": {
                "allocations": 10,
                "reallocations": 20,
                "deallocations": 9,
                "cumulative_requested_bytes": 1000,
            },
        }
        for wall in cpu_walls
    ]
    selected = sorted(cpu_walls)[len(cpu_walls) // 2]

    def opening(omitted, cache, saved, traffic, digest="c" * 64):
        opens = [0.10, 0.12, 0.11]
        verifies = [0.02, 0.03, 0.025]
        return {
            "name": "fixture",
            "bottom_outer_levels_omitted": omitted,
            "logical_outer_cache_bytes": cache,
            "cache_bytes_saved_vs_full": saved,
            "warmup_count": 1,
            "candidate_open_wall_s": opens,
            "selected_upper_median_open_wall_s": sorted(opens)[1],
            "open_ceiling_s": 1.5,
            "open_pass": True,
            "candidate_verify_wall_s": verifies,
            "selected_upper_median_verify_wall_s": sorted(verifies)[1],
            "verify_ceiling_s": 0.25,
            "verify_pass": True,
            "traffic_per_open": traffic,
            "encoded_bytes": 2_615_414,
            "encoded_blake3": digest,
        }

    return {
        "schema": 1,
        "milestone": "X4b-local-CPU-persisted-opening-preflight",
        "date": "2026-07-22",
        "git_sha": "e" * 40,
        "git_dirty": False,
        "profile": report.X4_V4_PROFILE,
        "pod_profile": report.X4B_POD_PROFILE,
        "design_sha256": report.X4B_DESIGN_SHA256,
        "source_policy": "PersistedOracle (record eligible)",
        "audit_recompute_refused": True,
        "profile_digest": "f" * 64,
        "query_derive_context": "volta-zk/x4/amendment5-gpt2-preflight/v1",
        "query_xof_input_ascii": "e29-r3-s111|gpt2-small|102-claims|2026-07-21",
        "query_count": 111,
        "query_draws_blake3": report.X4B_QUERY_TAPE_BLAKE3,
        "cpu_full_node_pipeline": {
            "status": "LOCAL_MEASUREMENT_ONLY",
            "measurement_scope": "serialization + pipeline allocations + BLAKE3 hash_many",
            "pinned_workers": 1,
            "warmup_count": 1,
            "measured_candidates": 5,
            "canonical_frame_bytes": report.X4B_CPU_CANONICAL_BYTES,
            "logical_oracle_bytes": 33_554_432,
            "hash_calls": report.X4B_CPU_HASH_CALLS,
            "candidates": candidates,
            "selected_upper_median_wall_s": selected,
            "selected_canonical_frame_bytes_per_s": report.X4B_CPU_CANONICAL_BYTES
            / selected,
            "gate_bytes_per_s_per_core": 500_000_000.0,
            "local_gate_comparison_only": True,
            "local_gate_met": True,
            "available_parallelism": 8,
            "all_local_cores_wall_s": 0.2,
            "all_local_cores_canonical_frame_bytes_per_s": 2_000_000_000.0,
            "root_hex": "a" * 64,
        },
        "sparse_artifacts": {
            "file_count": 32,
            "logical_bytes": 94_128_570_240,
            "allocated_bytes": 0,
            "scope": "fixture",
        },
        "persisted_open_full_cache": opening(
            0,
            report.X4B_FULL_INITIAL_CACHE_BYTES + report.X4B_FULL_FOLD_CACHE_BYTES,
            0,
            {
                "oracle_file_bytes_read": 875_328,
                "outer_cache_bytes_read": 1_930_304,
                "inner_trees_rebuilt": 6_720,
                "outer_frontier_leaves_rebuilt": 5_610,
                "outer_internal_nodes_rebuilt": 0,
            },
        ),
        "persisted_open_ram_degraded": opening(
            1,
            report.X4B_DEGRADED_INITIAL_CACHE_BYTES
            + report.X4B_DEGRADED_FOLD_CACHE_BYTES,
            35_727_081_344,
            {
                "oracle_file_bytes_read": 1_737_728,
                "outer_cache_bytes_read": 1_756_992,
                "inner_trees_rebuilt": 17_552,
                "outer_frontier_leaves_rebuilt": 16_442,
                "outer_internal_nodes_rebuilt": 5_416,
            },
        ),
        "full_and_degraded_openings_byte_identical": True,
        "local_pre_pod_gate_pass": True,
        "ram_guidance": "At approximately 125 GiB use the explicit degraded policy.",
    }


def test_x4b_local_validator_pins_full_pipeline_and_both_ram_policies():
    report = load_report_module()
    row = x4b_local_fixture(report)
    assert report._x4b_local_result_valid(row) is True
    bad = copy.deepcopy(row)
    bad["cpu_full_node_pipeline"]["measurement_scope"] = "hash-only"
    assert report._x4b_local_result_valid(bad) is False
    bad = copy.deepcopy(row)
    bad["persisted_open_ram_degraded"]["traffic_per_open"][
        "outer_internal_nodes_rebuilt"
    ] = 0
    assert report._x4b_local_result_valid(bad) is False


def test_x4b_pod_validator_accepts_honest_conjunctive_verdict_only():
    report = load_report_module()
    local = x4b_local_fixture(report)
    cohort_names = [
        "Wext-mu26-global-tied-roles",
        "Wext-mu22-all-layers",
        "Wext-mu20-layers-and-position",
        "auxiliary-ell17",
        "auxiliary-ell16",
    ]

    def accelerator():
        return {
            "timing_method": "wall-only-counters",
            "phase_attribution_available": False,
            "measurement_wall_s": 1.0,
            "operations": {},
            "h2d_bytes": 1,
            "d2h_bytes": 1,
            "explicit_d2d_copy_bytes": 0,
            "device_zeroed_bytes": 1,
            "device_generated_bytes": 1,
            "synchronizations": 1,
            "synchronization_s": 0.1,
            "sync_host_output": 1,
            "sync_upload_lifetime": 0,
            "sync_timing_flush": 0,
            "sync_profiling_legacy": 0,
            "sync_allocator_flush": 0,
            "allocation_calls": 1,
            "physical_free_calls": 1,
            "live_device_bytes": 0,
            "peak_device_bytes": 1_000,
            "timing_event_api_calls": 0,
            "timing_records": 0,
        }

    def initial(role, retained):
        return {
            "role": role,
            "wall_s": 20.0,
            "peak_rss_bytes": 1,
            "process_io": {},
            "accelerator": accelerator(),
            "cohorts": [{"name": name} for name in cohort_names],
            "totals": {
                "coefficient_bytes_persisted": 9_618_587_648,
                "oracle_bytes_persisted": 76_948_701_184,
                "root_bytes_persisted": 160,
                "persistent_artifact_bytes": 86_567_288_992,
            },
            "reconciliation_pass": True,
            "artifacts_retained": retained,
        }

    def isolated(role, wall):
        return {
            "role": role,
            "wall_s": wall,
            "ceiling_s": 15.0,
            "margin_s": 15.0 - wall,
            "margin_percent": 100.0 * (15.0 - wall) / 15.0,
            "pass": wall <= 15.0,
            "peak_rss_bytes": 1,
            "process_io": {},
            "accelerator": accelerator(),
            "root_hex": "1" * 64,
            "metrics": {},
            "reconciliation_pass": True,
        }

    def response(role, wall):
        return {
            "role": role,
            "epoch": 1,
            "seal_wall_s": 2.0,
            "open_wall_s": wall,
            "verify_wall_s": 0.05,
            "peak_rss_bytes": 1,
            "process_io": {},
            "accelerator_seal": accelerator(),
            "packed_opening_bytes": 2_615_414,
            "opened_symbols": 27_564,
            "real_sibling_digests": 67_930,
            "accepted": True,
            "metrics": {
                "recomputed_source_bytes_read": 0,
                "recomputed_oracle_bytes": 0,
                "recomputed_merkle_bytes": 0,
                "persisted_oracle_bytes_read": 1,
            },
            "g6_reconciliation_pass": True,
        }

    measured_initial = [initial(f"measured-{index}", False) for index in range(1, 4)]
    measured_isolated = [isolated(f"measured-{index}", wall) for index, wall in enumerate(
        [10.0, 11.0, 12.0], 1
    )]
    measured_response = [response(f"measured-{index}", wall) for index, wall in enumerate(
        [0.5, 0.6, 0.7], 1
    )]
    row = {
        "schema": 1,
        "milestone": "X4b-A100-production-record",
        "date": "2026-07-22",
        "git_sha": "f" * 40,
        "git_short_sha": "fffffff",
        "git_dirty": False,
        "pod_profile": report.X4B_POD_PROFILE,
        "protocol_or_parameter_change": False,
        "machine": {
            "provider": "RunPod",
            "gpu": "NVIDIA A100-SXM4-80GB",
            "rayon_threads": 8,
            "timing_policy": "wall-only+counters; no CUDA-event timing",
            "memory_bytes": report.X4B_BASELINE_RAM_BYTES,
            "persistent_volume_bytes": report.X4B_MIN_VOLUME_BYTES,
        },
        "frozen": {
            "design_sha256": report.X4B_DESIGN_SHA256,
            "migration_sha256": report.X4_V4_MIGRATION_SHA256,
            "amendment5_preflight_sha256": "ba87722362c8825e13e02a6c563a436797ea852e09e1cebcf4a9265c6ce56499",
            "local_preflight_sha256": "a" * 64,
            "note6": {"passed": True, "first_action": True, "sha256": "b" * 64},
            "profile": report.X4_V4_PROFILE,
            "rate": "1/8",
            "query_count": 111,
            "maximum_claim_union": 3_320,
            "opened_symbols": 27_564,
            "real_sibling_digests": 67_930,
            "packed_opening_bytes": 2_615_414,
            "pcs_bytes": 2_683_236,
            "response_bytes": 43_953_700,
            "soundness_expression": report.X4_V4_SOUNDNESS_EXPRESSION,
            "soundness_bits": report.X4_V4_SOUNDNESS_BITS,
            "soundness_floor_bits": report.X4_V4_SOUNDNESS_FLOOR_BITS,
            "soundness_new_terms": 0,
        },
        "cache_policy": {
            "name": "full",
            "bottom_levels_omitted": 0,
            "retained_initial_outer_cache_bytes": report.X4B_FULL_INITIAL_CACHE_BYTES,
            "retained_fold_outer_cache_bytes": report.X4B_FULL_FOLD_CACHE_BYTES,
            "retained_total_outer_cache_bytes": report.X4B_FULL_INITIAL_CACHE_BYTES
            + report.X4B_FULL_FOLD_CACHE_BYTES,
        },
        "local_preflight_of_record": copy.deepcopy(local),
        "pod_host_cpu_preflight": copy.deepcopy(local),
        "correctness": {
            "synthetic_preflight_before_full_pass": True,
            "contexts": [{"equal": True}] * 4,
            "synthetic": [{"equal": True}] * 5,
            "complete_aux_roots": [
                {
                    "all_equal": True,
                    "ntt_symbols_checked": 8,
                    "typed_inner_leaves_checked": 2,
                    "typed_inner_nodes_checked": 1,
                    "typed_inner_roots_checked": 1,
                    "typed_outer_leaves_checked": 8,
                    "outer_levels_checked": 20,
                }
            ]
            * 2,
            "larger_cohort_samples": [
                {
                    "all_equal": True,
                    "ntt_symbols_checked": 8,
                    "typed_inner_leaves_checked": 2,
                    "typed_inner_nodes_checked": 1,
                    "typed_inner_roots_checked": 1,
                    "typed_outer_leaves_checked": 8,
                    "outer_levels_checked": 30,
                }
            ]
            * 3,
            "all_equal": True,
        },
        "full_pass_commit": {
            "status": "MEASURED/INFORMATIVE; no hard ceiling in runpod-a100-x4b-v1",
            "warmup": initial("warmup", False),
            "measured": measured_initial,
            "selected_upper_median_wall_s": 20.0,
            "selected_throughput_oracle_bytes_per_s": 1.0,
            "final_materialization": initial("final", True),
            "hard_ceiling": None,
        },
        "isolated_wext_mu26_commit": {
            "warmup": isolated("warmup", 10.0),
            "measured": measured_isolated,
            "selected_upper_median_wall_s": 11.0,
            "ceiling_s": 15.0,
            "margin_s": 4.0,
            "margin_percent": 100.0 * 4.0 / 15.0,
            "pass": True,
        },
        "final_artifacts": {
            "page_cache_dontneed_bytes": 9_618_587_808,
            "page_cache_advice_calls": 10,
            "footprint": {
                "coefficient_bytes": 9_618_587_648,
                "oracle_bytes": 76_948_701_184,
                "root_bytes": 160,
                "durable_bytes": 86_567_288_992,
                "all_lengths_and_bindings_checked": True,
            },
        },
        "persisted_response": {
            "source_policy": "PersistedOracle (record eligible); AuditRecompute refused",
            "warmup": response("warmup", 0.5),
            "measured": measured_response,
            "selected_upper_median_open_wall_s": 0.6,
            "selected_upper_median_verify_wall_s": 0.05,
            "open_ceiling_s": 1.5,
            "verify_ceiling_s": 0.25,
            "open_pass": True,
            "verify_pass": True,
            "all_accepted": True,
            "all_byte_counts_exact": True,
            "all_g6_reconciled": True,
        },
        "codec_reference": {
            "migration_sha256": report.X4_V4_MIGRATION_SHA256,
            "packed_opening_bytes": 2_615_414,
            "complete_pcs_bytes": 2_683_236,
            "response_bytes": 43_953_700,
            "golden_decode_exact": True,
            "exact_match": True,
        },
        "audit_recompute_refused": True,
        "draw_before_complete_seal_rejected": True,
        "historical_baseline": {
            "immutable": True,
            "verdict": "G4 COMMIT FAIL; OVERALL X4 FAIL",
        },
        "gate": {
            "overall_x4b": "PASS — conjunctive",
            "historical_x4": "FAIL IMMUTABLE — historical",
        },
    }
    assert report._x4b_pod_result_valid(row) is True
    bad = copy.deepcopy(row)
    bad["persisted_response"]["measured"][1]["packed_opening_bytes"] += 1
    assert report._x4b_pod_result_valid(bad) is False
    bad = copy.deepcopy(row)
    bad["machine"]["memory_bytes"] = 125 * 1024**3
    bad["gate"]["overall_x4b"] = "PASS — improperly ignored hardware"
    assert report._x4b_pod_result_valid(bad) is False


def test_x4c_phase1_validator_derives_refutation_and_rejects_schema1(tmp_path):
    report = load_report_module()
    repo = Path(__file__).resolve().parents[1]
    eligible_path = (
        repo
        / "benchmarks/results/x4c-phase1-open-decomposition-2026-07-23-f772013.json"
    )
    schema1_path = (
        repo
        / "benchmarks/results/x4c-phase1-open-decomposition-2026-07-23-61bf1fb.json"
    )
    assert report.validate_x4c_phase1_result(eligible_path) is True
    assert report.validate_x4c_phase1_result(schema1_path) is False

    eligible = json.loads(eligible_path.read_text())
    assert (
        eligible["open_postdiction"]["hypothesis_disposition_code"]
        == "REFUTED_LOCAL_SYNTHETIC_DIRECT_PROJECTION"
    )
    assert (
        eligible["analytic_pod_scale_projection"][
            "projected_teardown_wall_s_high"
        ]
        < eligible["open_postdiction"]["lifecycle_debt_dominance_threshold_s"]
    )

    mutations = [
        ("schema", 1),
        ("pod_contacted", True),
        ("design_sha256", report.X4C_PREREGISTRATION_V1_SHA256),
    ]
    for key, value in mutations:
        candidate = copy.deepcopy(eligible)
        candidate[key] = value
        path = tmp_path / f"x4c-bad-{key}.json"
        path.write_text(json.dumps(candidate))
        assert report.validate_x4c_phase1_result(path) is False

    bad_disposition = copy.deepcopy(eligible)
    bad_disposition["open_postdiction"][
        "hypothesis_disposition_code"
    ] = "CONFIRMED_LOCAL_SYNTHETIC_DIRECT_PROJECTION"
    bad_path = tmp_path / "x4c-bad-disposition.json"
    bad_path.write_text(json.dumps(bad_disposition))
    assert report.validate_x4c_phase1_result(bad_path) is False

    bad_projection = copy.deepcopy(eligible)
    bad_projection["analytic_pod_scale_projection"][
        "projected_teardown_wall_s_high"
    ] += 1e-3
    bad_path = tmp_path / "x4c-bad-projection.json"
    bad_path.write_text(json.dumps(bad_projection))
    assert report.validate_x4c_phase1_result(bad_path) is False


def _upgrade_x4c_io_schema2(row, *, response):
    upgraded = copy.deepcopy(row)
    upgraded.update(
        {
            "syscr": 1,
            "syscw": 0,
            "cancelled_write_bytes": 0,
            "observer_rchar_bytes": upgraded["rchar"] if response else 0,
            "unexpected_rchar_bytes": 0,
            "unexpected_wchar_bytes": 0,
            "unexpected_read_bytes": 0,
            "unexpected_write_bytes": 0,
            "response_window_exact": response,
        }
    )
    return upgraded


def _upgrade_x4c_backend_schema2(row):
    upgraded = copy.deepcopy(row)
    names = [item[0] for item in upgraded["operations"]]
    upgraded.update(
        {
            "unattributed_cpu_residual_ns": upgraded["measurement_wall_ns"],
            "operation_kernel_ns": [[name, 0] for name in names],
            "operation_cpu_residual_ns": [[name, 0] for name in names],
            "explicit_d2d_copy_bytes": 0,
            "device_generated_bytes": 0,
            "resident_h2d_host_calls": 1,
            "resident_d2h_host_calls": 1,
            "sync_host_output": upgraded["synchronizations"],
            "sync_upload_lifetime": 0,
            "sync_timing_flush": 0,
            "sync_profiling_legacy": 0,
            "sync_allocator_flush": 0,
            "live_device_bytes": 0,
            "pinned_host_write_calls": 1,
            "pinned_host_write_bytes": 1,
            "live_pinned_bytes": 1_090_741_982,
            "peak_pinned_bytes": 1_090_741_982,
            "x4c_control_peek_calls": 2,
            "x4c_control_peek_pending": 0,
            "timing_records": 0,
            "timing_elapsed_query_attempts": 0,
            "timing_elapsed_no_write": 0,
            "timing_event_queries": 0,
            "timing_pending_high_water": 0,
            "timing_flush_count": 0,
            "coarse_timing_scopes": 0,
        }
    )
    return upgraded


def _x4c_schema2_durable_census(report):
    return {
        "cohort_directory_count": 5,
        "cohort_ids": [cohort[0] for cohort in report.X4C_COHORTS],
        "coefficient_file_count": 5,
        "root_file_count": 5,
        "oracle_file_count": 0,
        "other_file_count": 0,
        "other_directory_count": 0,
        "symlink_count": 0,
        "total_regular_file_bytes": report.X4C_DURABLE_BYTES,
        "unexpected_paths": [],
        "exact": True,
    }


def _upgrade_x4c_arena_schema2(old, backend, *, proof_ready):
    arena_bytes = 43_486_546_048
    baseline_device = old["active_device_allocations"] - (1 if proof_ready else 0)
    baseline_pinned = old["active_pinned_allocations"] - 4
    upgraded = copy.deepcopy(old)
    upgraded.update(
        {
            "peak_bytes": backend["peak_device_bytes"],
            "response_round_allocations": 0,
            "reallocations": 0,
            "accelerator_available": True,
            "backend_workspace_bytes": 0,
            "backend_baseline_resident_bytes": 0,
            "backend_resident_bytes": arena_bytes if proof_ready else 0,
            "backend_cached_resident_bytes": 0 if proof_ready else arena_bytes,
            "baseline_active_device_allocations": baseline_device,
            "cached_device_allocations": 0 if proof_ready else 1,
            "baseline_active_pinned_allocations": baseline_pinned,
            "baseline_active_pinned_bytes": 0,
            "cached_pinned_allocations": 0,
            "in_flight_pinned_allocations": 0,
            "cached_pinned_bytes": 0,
            "pinned_pool_allocations": 4,
            "pinned_pool_requested_bytes": 1_090_741_982,
            "native_live_device_bytes": arena_bytes if proof_ready else 0,
            "native_peak_device_bytes": backend["peak_device_bytes"],
            "native_resident_alloc_requests": 1,
            "native_resident_reuse_hits": backend["resident_reuse_hits"],
            "native_resident_free_requests": 0 if proof_ready else 1,
            "native_arena_reset_calls": 0 if proof_ready else 1,
            "native_arena_reset_bytes": 0 if proof_ready else arena_bytes,
            "native_device_zeroed_bytes": 0 if proof_ready else arena_bytes,
        }
    )
    return upgraded


def _x4c_schema2_records(report):
    root = Path(__file__).resolve().parents[1]
    onboarding = json.loads(
        (
            root
            / "benchmarks/results/10-x4c-onboarding-2026-07-24-603d5a7.json"
        ).read_text()
    )
    online = json.loads(
        (
            root / "benchmarks/results/11-x4c-online-2026-07-24-603d5a7.json"
        ).read_text()
    )
    onboarding["schema"] = 2
    onboarding["design_sha256"] = report.X4C_V1_DESIGN_SHA256
    onboarding["durable_census"] = _x4c_schema2_durable_census(report)
    for candidate in [onboarding["warmup"], *onboarding["measured"]]:
        candidate["io"] = _upgrade_x4c_io_schema2(candidate["io"], response=False)
        candidate["backend"] = _upgrade_x4c_backend_schema2(candidate["backend"])

    online["schema"] = 2
    online["design_sha256"] = report.X4C_V1_DESIGN_SHA256
    census = _x4c_schema2_durable_census(report)
    rebuild = online["fresh_process_rebuild"]
    rebuild["io"] = _upgrade_x4c_io_schema2(rebuild["io"], response=False)
    rebuild["durable_census_before"] = copy.deepcopy(census)
    rebuild["durable_census_after"] = copy.deepcopy(census)
    rebuild["durable_census_stable"] = True
    for candidate in [online["warmup"], *online["measured"]]:
        candidate["process_io"] = _upgrade_x4c_io_schema2(
            candidate["process_io"], response=True
        )
        candidate["response_window_io_exact"] = True
        candidate["backend"] = _upgrade_x4c_backend_schema2(candidate["backend"])
        candidate["metrics"]["proof_ready_arena"] = _upgrade_x4c_arena_schema2(
            candidate["metrics"]["proof_ready_arena"],
            candidate["backend"],
            proof_ready=True,
        )
        candidate["metrics"]["session_reusable_arena"] = (
            _upgrade_x4c_arena_schema2(
                candidate["metrics"]["session_reusable_arena"],
                candidate["backend"],
                proof_ready=False,
            )
        )
    online["expected_onboarding_sha256"] = "0" * 64
    online["onboarding_sha256_exact"] = True
    return onboarding, online


def _write_x4c_schema2_chain(tmp_path, onboarding, online):
    tmp_path.mkdir(parents=True, exist_ok=True)
    onboarding_path = tmp_path / "onboarding.json"
    onboarding_path.write_text(json.dumps(onboarding, indent=2) + "\n")
    import hashlib

    digest = hashlib.sha256(onboarding_path.read_bytes()).hexdigest()
    online = copy.deepcopy(online)
    online["onboarding"]["path"] = str(onboarding_path)
    online["onboarding"]["sha256"] = digest
    online["expected_onboarding_sha256"] = digest
    online_path = tmp_path / "online.json"
    online_path.write_text(json.dumps(online, indent=2) + "\n")
    return onboarding_path, online_path


def test_x4c_onboarding_and_online_validators_are_complete_and_fail_closed(tmp_path):
    report = load_report_module()
    onboarding, online = _x4c_schema2_records(report)
    onboarding_path, online_path = _write_x4c_schema2_chain(
        tmp_path, onboarding, online
    )
    assert report.validate_x4c_onboarding_result(onboarding_path) is True
    assert report.validate_x4c_online_result(online_path, onboarding_path) is True

    onboarding_mutations = [
        lambda row: row.pop("durable_census"),
        lambda row: row["durable_census"].update({"oracle_file_count": 1}),
        lambda row: row.update({"selected_upper_median_wall_s": 0.0}),
    ]
    for index, mutate in enumerate(onboarding_mutations):
        bad = copy.deepcopy(onboarding)
        mutate(bad)
        path = tmp_path / f"bad-onboarding-{index}.json"
        path.write_text(json.dumps(bad))
        assert report.validate_x4c_onboarding_result(path) is False

    mutations = (
        lambda row: row["warmup"].pop("response_window_io_exact"),
        lambda row: row["onboarding"].update({"git_sha": "f" * 40}),
        lambda row: row.update({"selected_upper_median_open_wall_s": 0.0}),
        lambda row: row["measured"][0].update(
            {"complete_pcs_bytes": row["measured"][0]["complete_pcs_bytes"] + 1}
        ),
        lambda row: row["measured"][0]["process_io"].update({"read_bytes": 1}),
        lambda row: row["measured"][0]["metrics"]["response_io"].update(
            {"response_staging_bytes_written": 1}
        ),
        lambda row: row["measured"][0]["metrics"]["execution"].update(
            {"query_gather_calls": 2}
        ),
        lambda row: row["measured"][0]["metrics"]["proof_ready_arena"].update(
            {"response_round_allocations": 1}
        ),
    )
    for index, mutate in enumerate(mutations):
        bad = copy.deepcopy(online)
        mutate(bad)
        case = tmp_path / f"case-{index}"
        bad_onboarding_path, bad_online_path = _write_x4c_schema2_chain(
            case, onboarding, bad
        )
        assert (
            report.validate_x4c_online_result(
                bad_online_path, bad_onboarding_path
            )
            is False
        )


def _x4c_gpt2_backend(report, *, h2d=1, d2h=1):
    return {
        "measurement_wall_ns": 1,
        "operations": [
            [name, 0]
            for name in (
                "gemm",
                "logup",
                "pcs_rows",
                "pcs_ntt",
                "pcs_merkle",
                "auth_masks",
                "mailbox",
            )
        ],
        "h2d_bytes": h2d,
        "d2h_bytes": d2h,
        "explicit_d2d_copy_bytes": 0,
        "device_zeroed_bytes": report.X4C_ARENA_BYTES,
        "device_generated_bytes": 0,
        "resident_alloc_requests": 1,
        "resident_reuse_hits": 0,
        "resident_free_requests": 1,
        "live_device_bytes": 0,
        "peak_device_bytes": report.X4C_ARENA_BYTES,
        "pinned_allocation_calls": 0,
        "pinned_alloc_requests": 0,
        "pinned_reuse_hits": 0,
        "pinned_free_requests": 0,
        "pinned_physical_free_calls": 0,
        "live_pinned_bytes": 1_090_741_982,
        "peak_pinned_bytes": 1_090_741_982,
        "x4c_arena_reset_calls": 1,
        "x4c_arena_reset_bytes": report.X4C_ARENA_BYTES,
        "timing_event_api_calls": 0,
        "outstanding_timing_records": 0,
    }


def _x4c_gpt2_io(*, response):
    return {
        "rchar": 100,
        "wchar": 0,
        "syscr": 1,
        "syscw": 0,
        "read_bytes": 0,
        "write_bytes": 0,
        "cancelled_write_bytes": 0,
        "observer_rchar_bytes": 100,
        "unexpected_rchar_bytes": 0,
        "unexpected_wchar_bytes": 0,
        "unexpected_read_bytes": 0,
        "unexpected_write_bytes": 0,
        "response_window_exact": response,
    }


def _x4c_gpt2_arena(report, *, proof_ready):
    arena = report.X4C_ARENA_BYTES
    return {
        "capacity_bytes": arena,
        "committed_bytes": arena,
        "peak_bytes": arena,
        "logical_allocations": 1,
        "response_round_allocations": 0,
        "reallocations": 0,
        "logical_deallocations": 0 if proof_ready else 1,
        "reset_count": 0 if proof_ready else 1,
        "zeroed_bytes": 0 if proof_ready else arena,
        "outstanding_allocations": 1 if proof_ready else 0,
        "outstanding_bytes": arena if proof_ready else 0,
        "cached_reusable_bytes": 0 if proof_ready else arena,
        "accelerator_available": True,
        "baseline_active_device_allocations": 10,
        "baseline_active_pinned_allocations": 2,
        "baseline_active_pinned_bytes": 4096,
        "active_device_allocations": 11 if proof_ready else 10,
        "active_pinned_allocations": 6,
        "active_pinned_bytes": 4096 + 1_090_741_982,
        "outstanding_cuda_operations": 0,
        "stream_synchronized": True,
        "pinned_pool_allocations": 4,
        "pinned_pool_requested_bytes": 1_090_741_982,
        "native_live_device_bytes": arena if proof_ready else 0,
        "native_peak_device_bytes": arena,
        "native_resident_alloc_requests": 1,
        "native_resident_reuse_hits": 0,
        "native_resident_free_requests": 0 if proof_ready else 1,
        "native_arena_reset_calls": 0 if proof_ready else 1,
        "native_arena_reset_bytes": 0 if proof_ready else arena,
        "native_device_zeroed_bytes": 0 if proof_ready else arena,
    }


def _x4c_gpt2_records(report):
    roots = [f"{100 + index:064x}" for index in range(5)]
    io = _x4c_gpt2_io(response=False)
    backend = _x4c_gpt2_backend(report)

    def onboarding_pass(role, measured, wall, retained):
        return {
            "role": role,
            "measured": measured,
            "wall_s": wall,
            "io": copy.deepcopy(io),
            "backend": copy.deepcopy(backend),
            "roots": roots,
            "coefficient_bytes": report.X4C_DURABLE_COEFFICIENT_BYTES,
            "oracle_bytes": report.X4C_INITIAL_ORACLE_BYTES,
            "root_bytes": report.X4C_DURABLE_ROOT_BYTES,
            "retained_durable": retained,
            "cleanup_complete": True,
            "accepted": True,
        }

    durable = [
        {
            "cohort_id": cohort_id,
            "coefficient_bytes": coefficient_bytes,
            "coefficient_sha256": f"{200 + index:064x}",
            "root_bytes": 32,
            "root_hex": roots[index],
            "root_sha256": f"{300 + index:064x}",
        }
        for index, (cohort_id, coefficient_bytes, _) in enumerate(
            report.X4C_COHORTS
        )
    ]
    measured_onboarding = [
        onboarding_pass("measured-1", True, 1.0, False),
        onboarding_pass("measured-2", True, 3.0, False),
        onboarding_pass("measured-3", True, 2.0, True),
    ]
    onboarding = {
        "schema": 2,
        "milestone": report.X4C_GPT2_ONBOARDING_MILESTONE,
        "git_sha": "a" * 40,
        "git_dirty": False,
        "profile": report.X4C_POD_PROFILE,
        "protocol": report.X4C_GPT2_PROTOCOL,
        "design_sha256": report.X4C_V1_DESIGN_SHA256,
        **report.X4C_GPT2_INPUT_SHA256,
        "model_config_digest": report.X4C_GPT2_INPUT_SHA256[
            "input_json_sha256"
        ],
        "weights_digest": report.X4C_GPT2_INPUT_SHA256["input_bin_sha256"],
        "parent_domains": [[2 * index, 2 * index + 1] for index in range(51)],
        "descriptor_digests": [
            f"{1000 + index:064x}" for index in range(51)
        ],
        "mask_seed_commitment_blake3": "b" * 64,
        "warmup": onboarding_pass("warmup", False, 0.5, False),
        "measured": measured_onboarding,
        "selected_upper_median_wall_s": 2.0,
        "warmup_root_set": roots,
        "measured_root_sets": [roots, roots, roots],
        "durable": durable,
        "durable_census": _x4c_schema2_durable_census(report),
        "durable_bytes": report.X4C_DURABLE_BYTES,
        "durable_tier_exact": True,
        "roots_identical": True,
        "golden_match": True,
        "overall_pass": True,
    }
    execution = {
        "direct_fold_calls": 27,
        "diagnostic_comparisons": 1_592,
        "diagnostic_mismatches": 0,
        "diagnostic_gather_calls": 53,
        "diagnostic_index_h2d_bytes": 37_184,
        "diagnostic_value_d2h_bytes": 74_368,
        "n4_tree_calls": 27,
        "query_gather_calls": 1,
        "query_gather_operation_count": 53_898,
        "query_gather_operation_h2d_bytes": 4_743_024,
        "canonical_template_h2d_bytes": report.X4C_PACKED_OPENING_BYTES,
        "query_draw_count": 111,
        "canonical_opening_d2h_bytes": report.X4C_PACKED_OPENING_BYTES,
        "noncanonical_opening_d2h_bytes": 0,
        "cpu_fold_tree_clone_bytes": 0,
    }
    h2d = (
        1_159_200_768 * 16
        + execution["diagnostic_index_h2d_bytes"]
        + execution["query_gather_operation_h2d_bytes"]
        + execution["canonical_template_h2d_bytes"]
    )
    d2h = (
        27 * 32
        + execution["diagnostic_value_d2h_bytes"]
        + execution["canonical_opening_d2h_bytes"]
    )
    response_io = {
        key: 0
        for key in (
            "response_e_ntt_calls",
            "response_coefficient_files_created",
            "response_coefficient_bytes_read",
            "response_coefficient_bytes_written",
            "response_oracle_files_created",
            "response_oracle_bytes_read",
            "response_oracle_bytes_written",
            "response_full_oracle_comparison_bytes",
            "staging_files_created",
            "staging_bytes_read",
            "staging_bytes_written",
            "cpu_fold_tree_clone_bytes",
            "response_overlay_reread_bytes",
            "response_fadv_dontneed_calls",
        )
    }
    model_sub = 100
    model_full = 200
    full = model_full + 2_314 + 2

    def candidate(ordinal, open_wall, verify_wall):
        return {
            "role": "warmup" if ordinal == 0 else f"measured-{ordinal}",
            "ordinal": ordinal,
            "measured": ordinal != 0,
            "epoch": 500 + ordinal,
            "challenge_seed_digest": f"{400 + ordinal:064x}",
            "response_nonce_digest": f"{500 + ordinal:064x}",
            "freshness_binding_digest": f"{600 + ordinal:064x}",
            "freshness_record_digest": f"{700 + ordinal:064x}",
            "authorization_record_digest": f"{800 + ordinal:064x}",
            "freshness_markers_persisted": True,
            "model_root": f"{900 + ordinal:064x}",
            "model_prove_s": 1.0,
            "model_verify_s": 0.1,
            "model_transcript_prover_bytes": (
                report.X4C_GPT2_MODEL_TRANSCRIPT_PROVER_BYTES
            ),
            "model_transcript_replay_bytes": (
                report.X4C_GPT2_MODEL_TRANSCRIPT_REPLAY_BYTES
            ),
            "model_transcript_replay_labels": (
                report.X4C_GPT2_MODEL_TRANSCRIPT_REPLAY_LABELS
            ),
            "model_transcript_accounting_exact": True,
            "pcs_total_s": 2.0,
            "seal_wall_s": 1.0,
            "open_wall_s": open_wall,
            "verify_wall_s": verify_wall,
            "proof_ready_wall_s": 3.0 + ordinal,
            "session_reusable_wall_s": 4.0 + ordinal,
            "complete_e2e_wall_s": 10.0 + ordinal,
            "complete_pcs_bytes": report.X4_V4_PCS_BYTES,
            "response_bytes": report.X4_V4_RESPONSE_BYTES,
            "sub_correlations": model_sub,
            "full_correlations": full,
            "expected_sub_correlations": model_sub,
            "expected_full_correlations": full,
            "correlation_allocation_digest": f"{1000 + ordinal:064x}",
            "prover_verifier_correlation_digest_equal": True,
            "transcript_bytes_equal": True,
            "transcript_ledger_equal": True,
            "process_io": _x4c_gpt2_io(response=True),
            "response_window_io_exact": True,
            "backend": _x4c_gpt2_backend(report, h2d=h2d, d2h=d2h),
            "metrics": {
                "response_io": copy.deepcopy(response_io),
                "execution": copy.deepcopy(execution),
                "proof_ready_arena": _x4c_gpt2_arena(
                    report, proof_ready=True
                ),
                "session_reusable_arena": _x4c_gpt2_arena(
                    report, proof_ready=False
                ),
                "proof_ready_wall_ns": 3_000_000_000 + ordinal,
                "session_reusable_wall_ns": 4_000_000_000 + ordinal,
                "source_coefficients_read": 601_161_728,
                "initial_encoded_symbols_read": 4_809_293_824,
                "combined_codeword_symbols": 1_159_200_768,
                "serialized_fold_bytes": 2_446,
                "serialized_packed_opening_bytes": report.X4C_PACKED_OPENING_BYTES,
                "sampling_soundness_credit_bits": 0,
            },
            "expected_h2d_bytes": h2d,
            "expected_d2h_bytes": d2h,
            "traffic_exact": True,
            "zero_response_staging": True,
            "verifier_accepted": True,
            "connection_audit": {
                "response_nonce_digest": f"{500 + ordinal:064x}",
                "allocation_digest": f"{1100 + ordinal:064x}",
                "channel_ledger_digest": f"{1200 + ordinal:064x}",
                "correlations_consumed": model_sub + 2 * full,
                "channel_frames": 0,
            },
            "accepted": True,
        }

    candidates = [
        candidate(0, 0.05, 0.01),
        candidate(1, 0.1, 0.01),
        candidate(2, 0.3, 0.03),
        candidate(3, 0.2, 0.02),
    ]
    rebuild = {
        "wall_s": 5.0,
        "io": _x4c_gpt2_io(response=False),
        "parallel_task_count": 5,
        "rayon_workers": 8,
        "cohorts": [
            {
                "cohort_id": cohort_id,
                "coefficient_bytes_read": coefficient_bytes,
                "host_oracle_bytes": coefficient_bytes * 8,
                "host_outer_cache_bytes": cache_bytes,
                "root": roots[index],
                "expected_root": roots[index],
                "root_equal": True,
                "accepted": True,
            }
            for index, (cohort_id, coefficient_bytes, cache_bytes) in enumerate(
                report.X4C_COHORTS
            )
        ],
        "coefficient_bytes_read": report.X4C_DURABLE_COEFFICIENT_BYTES,
        "evaluation_table_bytes": report.X4C_DURABLE_COEFFICIENT_BYTES,
        "host_oracle_bytes": report.X4C_INITIAL_ORACLE_BYTES,
        "host_outer_cache_bytes": report.X4C_INITIAL_OUTER_CACHE_BYTES,
        "roots_equal_onboarding": True,
        "durable_census_before": copy.deepcopy(onboarding["durable_census"]),
        "durable_census_after": copy.deepcopy(onboarding["durable_census"]),
        "durable_census_stable": True,
        "accepted": True,
    }
    online = {
        "schema": 2,
        "milestone": report.X4C_GPT2_ONLINE_MILESTONE,
        "git_sha": onboarding["git_sha"],
        "git_dirty": False,
        "profile": report.X4C_POD_PROFILE,
        "protocol": report.X4C_GPT2_PROTOCOL,
        "design_sha256": report.X4C_V1_DESIGN_SHA256,
        "onboarding_path": "onboarding.json",
        "onboarding_sha256": "0" * 64,
        "onboarding_sha256_exact": True,
        "onboarding_git_sha": onboarding["git_sha"],
        "clean_source_sha256": "c" * 64,
        "selected_query_tape_blake3": report.X4C_GPT2_SELECTED_TAPE,
        **report.X4C_GPT2_INPUT_SHA256,
        "prefill_tokens": 100,
        "decode_tokens": 50,
        "pcg_prg": "aes128-mmo",
        "pcg_stage_plan": "terminal-one",
        "model_sub_correlations": model_sub,
        "model_full_correlations": model_full,
        "x4c_full_correlations": 2_314,
        "closure_full_correlations": 2,
        "golden_match": True,
        "cpu_cuda_prefill_logits_equal": True,
        "cpu_cuda_band_logits_equal": True,
        "rebuild": rebuild,
        "rebuild_roots": roots,
        "rebuild_roots_equal_onboarding": True,
        "rebuild_parallel_tasks": 5,
        "warmup_count": 1,
        "measured_count": 3,
        "candidates": candidates,
        "selected_upper_median_open_wall_s": 0.2,
        "selected_upper_median_verify_wall_s": 0.02,
        "selected_upper_median_proof_ready_wall_s": 5.0,
        "selected_upper_median_session_reusable_wall_s": 6.0,
        "selected_upper_median_complete_e2e_wall_s": 12.0,
        "open_ceiling_s": 1.50,
        "verify_ceiling_s": 0.25,
        "open_pass": True,
        "verify_pass": True,
        "pinned_pool_release_wall_s": 0.01,
        "pinned_pool_release_restored_ownership": True,
        "pcs_bytes": report.X4_V4_PCS_BYTES,
        "response_bytes": report.X4_V4_RESPONSE_BYTES,
        "rate": "1/8",
        "query_count": 111,
        "all_candidates_accepted": True,
        "zero_response_staging": True,
        "exact_communication": True,
        "diagnostic_comparisons": 1_592,
        "diagnostic_soundness_credit_bits": 0,
        "protocol_or_parameter_change": False,
        "root_or_proof_format_change": False,
        "lean_or_soundness_change": False,
        "overall_pass": True,
    }
    return onboarding, online


def _write_x4c_gpt2_chain(tmp_path, onboarding, online):
    tmp_path.mkdir(parents=True, exist_ok=True)
    onboarding_path = tmp_path / "onboarding.json"
    onboarding_path.write_text(json.dumps(onboarding, indent=2) + "\n")
    digest = hashlib.sha256(onboarding_path.read_bytes()).hexdigest()
    online = copy.deepcopy(online)
    online["onboarding_sha256"] = digest
    online_path = tmp_path / "online.json"
    online_path.write_text(json.dumps(online, indent=2) + "\n")
    return onboarding_path, online_path


def _write_x4c_gpt2_v3_chain(tmp_path, report, onboarding, online):
    tmp_path.mkdir(parents=True, exist_ok=True)
    onboarding_path = tmp_path / "onboarding.json"
    onboarding_path.write_text(json.dumps(onboarding, indent=2) + "\n")
    onboarding_sha256 = hashlib.sha256(
        onboarding_path.read_bytes()
    ).hexdigest()
    online = copy.deepcopy(online)
    online["onboarding_sha256"] = onboarding_sha256
    admission = {
        "schema": 1,
        "milestone": report.X4C_SCHEMA3_REBUILD_ADMISSION_MILESTONE,
        "producer_git_sha": online["git_sha"],
        "producer_source_sha256": online["producer_source_sha256"],
        "crypto_build_id_scheme": online["crypto_build_id_scheme"],
        "crypto_build_id": online.get(
            "crypto_build_id", onboarding["crypto_build_id"]
        ),
        "onboarding_sha256": onboarding_sha256,
        "campaign_target_s": online["campaign_target_s"],
        "campaign_started_unix_s": online["campaign_started_unix_s"],
        "campaign_rebuild_finished_unix_s":
            online["campaign_rebuild_finished_unix_s"],
        "campaign_elapsed_through_rebuild_s":
            online["campaign_elapsed_through_rebuild_s"],
        "rebuild_campaign_target_met":
            online["rebuild_campaign_target_met"],
        "rebuild_roots": online["rebuild_roots"],
        "rebuild_roots_equal_onboarding": True,
        "accepted": True,
    }
    admission_path = tmp_path / "rebuild-admission.json"
    admission_path.write_text(json.dumps(admission, indent=2) + "\n")
    online["rebuild_admission_marker_path"] = str(admission_path)
    online["rebuild_admission_marker_sha256"] = hashlib.sha256(
        admission_path.read_bytes()
    ).hexdigest()
    online_path = tmp_path / "online.json"
    online_path.write_text(json.dumps(online, indent=2) + "\n")
    return onboarding_path, online_path, admission_path


def _x4c_gpt2_accelerated_online(report, online):
    accelerated = copy.deepcopy(online)
    accelerated["milestone"] = report.X4C_GPT2_ACCELERATED_ONLINE_MILESTONE
    accelerated["rebuild_parallel_tasks"] = 1
    accelerated["rebuild"]["parallel_task_count"] = 1
    gate_keys = (
        "verifier_accepted",
        "freshness_markers_persisted",
        "model_transcript_accounting_exact",
        "transcript_bytes_equal",
        "transcript_ledger_equal",
        "correlation_counters_equal",
        "sub_correlations_exact",
        "full_correlations_exact",
        "correlation_allocation_digest_equal",
        "pcs_bytes_exact",
        "query_gather_exact",
        "direct_fold_comparisons_exact",
        "direct_fold_mismatches_zero",
        "zero_soundness_credit",
        "zero_response_staging",
        "traffic_exact",
    )
    for candidate in accelerated["candidates"]:
        native_resident_bytes = report.X4C_ARENA_BYTES + 4096
        expected_device_generated_bytes = (
            report.X4C_PRODUCTION_FRESH_DEVICE_GENERATED_BYTES
            if candidate["ordinal"] == 0
            else report.X4C_PRODUCTION_REUSED_DEVICE_GENERATED_BYTES
        )
        candidate["expected_explicit_d2d_copy_bytes"] = (
            report.X4C_PRODUCTION_EXPLICIT_D2D_COPY_BYTES
        )
        candidate["expected_device_generated_bytes"] = expected_device_generated_bytes
        candidate["backend"]["explicit_d2d_copy_bytes"] = (
            report.X4C_PRODUCTION_EXPLICIT_D2D_COPY_BYTES
        )
        candidate["backend"]["device_generated_bytes"] = expected_device_generated_bytes
        candidate["backend"]["live_device_bytes"] = native_resident_bytes
        candidate["backend"]["peak_device_bytes"] = native_resident_bytes
        for arena_name in ("proof_ready_arena", "session_reusable_arena"):
            arena = candidate["metrics"][arena_name]
            arena["peak_bytes"] = native_resident_bytes
            arena["native_live_device_bytes"] = native_resident_bytes
            arena["native_peak_device_bytes"] = native_resident_bytes
        candidate["metrics"]["execution"][
            "expected_explicit_d2d_copy_bytes"
        ] = report.X4C_PRODUCTION_EXPLICIT_D2D_COPY_BYTES
        candidate["metrics"]["execution"][
            "expected_device_generated_bytes"
        ] = expected_device_generated_bytes
        candidate["gate_audit"] = {
            **{key: True for key in gate_keys},
            "failed": [],
            "all_pass": True,
        }
    schedule = [
        0xA5000001,
        0xA5000002,
        0xA5000003,
        0xA5000101,
        0xA5000100,
    ]
    expected_by_id = {cohort[0]: cohort for cohort in report.X4C_COHORTS}
    structural_and_present = {
        0xA5000001: (2, 2),
        0xA5000002: (64, 36),
        0xA5000003: (16, 13),
        0xA5000100: (2, 2),
        0xA5000101: (64, 49),
    }

    def control(cached_device_bytes=8192):
        return {
            "stream_state": "idle",
            "measurement_active": False,
            "coarse_timing_active": False,
            "timing_record_active": False,
            "measurement_poisoned": False,
            "outstanding_cuda_operations": 0,
            "pending_timing_records": 0,
            "active_device_allocations": 4,
            "cached_device_allocations": 2,
            "workspace_device_bytes": 0,
            "active_device_bytes": 4096,
            "cached_device_bytes": cached_device_bytes,
            "active_pinned_allocations": 0,
            "cached_pinned_allocations": 1,
            "in_flight_pinned_allocations": 0,
            "active_pinned_bytes": 0,
            "cached_pinned_bytes": 4096,
        }

    rows = []
    for ordinal, cohort_id in enumerate(schedule, 1):
        _, coefficient_bytes, cache_bytes = expected_by_id[cohort_id]
        h2d = coefficient_bytes + ordinal
        d2h = coefficient_bytes * 8 + ordinal
        backend = _x4c_gpt2_backend(report, h2d=h2d, d2h=d2h)
        backend.update(
            {
                "device_zeroed_bytes": 0,
                "resident_alloc_requests": 2,
                "resident_free_requests": 2,
                "live_device_bytes": 20_480,
                "live_pinned_bytes": 4096,
                "peak_pinned_bytes": 4096,
                "x4c_arena_reset_calls": 0,
                "x4c_arena_reset_bytes": 0,
                "peak_device_bytes": 30_000 + ordinal,
            }
        )
        rows.append(
            {
                "cohort_id": cohort_id,
                "strategy": "cuda-ram-v1",
                "wall_s": 1e-8,
                "phases": {
                    "e_ntt_ns": 1,
                    "n4_inner_ns": 1,
                    "n4_outer_ns": 1,
                    "assemble_and_root_check_ns": 1,
                    "cleanup_ns": 1,
                    "total_ns": 10,
                },
                "process_memory_before": {
                    "rss_bytes": 100 + ordinal,
                    "peak_rss_bytes": 200 + ordinal,
                },
                "process_memory_after": {
                    "rss_bytes": 110 + ordinal,
                    "peak_rss_bytes": 210 + ordinal,
                },
                "backend": backend,
                "device_memory_before": {
                    "workspace_bytes": 0,
                    "resident_bytes": 4096,
                    "cached_resident_bytes": 8192,
                },
                "device_memory_after": {
                    "workspace_bytes": 0,
                    "resident_bytes": 4096,
                    "cached_resident_bytes": 16384,
                },
                "control_before": control(),
                "control_after": control(16384),
                "structural_slots": structural_and_present[cohort_id][0],
                "present_slots": structural_and_present[cohort_id][1],
                "coefficient_bytes": coefficient_bytes,
                "host_oracle_bytes": coefficient_bytes * 8,
                "host_outer_cache_bytes": cache_bytes,
                "ntt_calls": structural_and_present[cohort_id][1],
                "n4_inner_calls": 1,
                "n4_outer_calls": 1,
                "expected_h2d_bytes": h2d,
                "expected_d2h_bytes": d2h,
                "scratch_files_created": 0,
                "scratch_bytes_read": 0,
                "scratch_bytes_written": 0,
                "file_backed_bytes": 0,
                "owned_file_count": 0,
                "owned_mapping_count": 0,
                "root_equal": True,
                "traffic_exact": True,
                "cleanup_complete": True,
                "accepted": True,
            }
        )
    accelerated["rebuild"]["accelerated"] = {
        "contract": "x4c-gpt2-accelerated-rebuild-schema-1",
        "strategy": "cuda-ram-v1",
        "deterministic_schedule": schedule,
        "cuda_cohort_concurrency": 1,
        "mu26_mu22_overlap": False,
        "automatic_cpu_fallback": False,
        "cpu_fallback_opt_in_only": True,
        "evaluation_table_wall_s": 1.0,
        "cohorts": rows,
        "expected_h2d_bytes": sum(row["expected_h2d_bytes"] for row in rows),
        "expected_d2h_bytes": sum(row["expected_d2h_bytes"] for row in rows),
        "peak_host_rss_bytes": max(
            row["process_memory_after"]["peak_rss_bytes"] for row in rows
        ),
        "peak_device_bytes": max(
            row["backend"]["peak_device_bytes"] for row in rows
        ),
        "scratch_files_created": 0,
        "scratch_bytes_read": 0,
        "scratch_bytes_written": 0,
        "outstanding_cuda_operations": 0,
        "rebuild_workspace_bytes_before_context_drop": rows[-1][
            "device_memory_after"
        ]["workspace_bytes"],
        "rebuild_live_device_bytes_before_context_drop": rows[-1]["backend"][
            "live_device_bytes"
        ],
        "backend_context_cleanup_wall_s": 0.01,
        "backend_context_dropped_before_response": True,
        "online_backend_fresh_context": True,
        "fresh_online_backend_device_bytes": 0,
        "fresh_online_backend_outstanding_cuda_operations": 0,
        "cleanup_complete": True,
        "traffic_exact": True,
        "accepted": True,
    }
    return accelerated


def _x4c_gpt2_v3_records(report):
    onboarding, online = _x4c_gpt2_records(report)
    onboarding = copy.deepcopy(onboarding)
    onboarding.update(
        {
            "schema": 3,
            "milestone": report.X4C_GPT2_V3_ONBOARDING_MILESTONE,
            "producer_source_sha256": "b" * 64,
            "crypto_build_id_scheme": report.X4C_CRYPTO_BUILD_ID_SCHEME,
            "crypto_build_id": "c" * 64,
            "crypto_build_manifest_blake3": "d" * 64,
            "crypto_build_file_count": 321,
            "crypto_build_source_bytes": 12_345_678,
            "campaign_target_s": report.X4C_CAMPAIGN_TARGET_S,
            "campaign_started_unix_s": 1_000,
            "campaign_finished_unix_s": 1_900,
            "campaign_elapsed_s": 900,
            "campaign_target_met": True,
        }
    )
    online = _x4c_gpt2_accelerated_online(report, online)
    online.update(
        {
            "schema": 3,
            "milestone":
                report.X4C_GPT2_V3_ACCELERATED_ONLINE_MILESTONE,
            "git_sha": "e" * 40,
            "producer_source_sha256": "f" * 64,
            "clean_source_sha256": "f" * 64,
            "crypto_build_id_scheme": report.X4C_CRYPTO_BUILD_ID_SCHEME,
            "crypto_build_id": "c" * 64,
            "crypto_build_manifest_blake3": "d" * 64,
            "crypto_build_file_count": 321,
            "crypto_build_source_bytes": 12_345_678,
            "campaign_target_s": report.X4C_CAMPAIGN_TARGET_S,
            "campaign_started_unix_s": 2_000,
            "campaign_rebuild_finished_unix_s": 2_240,
            "campaign_elapsed_through_rebuild_s": 240,
            "rebuild_campaign_target_met": True,
        }
    )
    return onboarding, online


def test_x4c_gpt2_e2e_validators_are_complete_and_fail_closed(tmp_path):
    report = load_report_module()
    onboarding, online = _x4c_gpt2_records(report)
    onboarding_path, online_path = _write_x4c_gpt2_chain(
        tmp_path, onboarding, online
    )
    assert report.validate_x4c_gpt2_onboarding_result(onboarding_path) is True
    assert (
        report.validate_x4c_gpt2_online_result(online_path, onboarding_path)
        is True
    )

    onboarding_mutations = (
        lambda row: row.pop("parent_domains"),
        lambda row: row.pop("design_sha256"),
        lambda row: row["durable_census"].update({"oracle_file_count": 1}),
        lambda row: row.update({"selected_upper_median_wall_s": 0.0}),
        lambda row: row["measured"][2].update({"retained_durable": False}),
    )
    for index, mutate in enumerate(onboarding_mutations):
        bad = copy.deepcopy(onboarding)
        mutate(bad)
        path = tmp_path / f"bad-gpt2-onboarding-{index}.json"
        path.write_text(json.dumps(bad))
        assert report.validate_x4c_gpt2_onboarding_result(path) is False

    online_mutations = (
        lambda row: row["candidates"][0].pop("freshness_record_digest"),
        lambda row: row.update({"design_sha256": "0" * 64}),
        lambda row: row.update({"selected_upper_median_open_wall_s": 0.0}),
        lambda row: row["candidates"][0].update({"complete_pcs_bytes": 1}),
        lambda row: row["candidates"][0]["process_io"].update(
            {"unexpected_read_bytes": 1}
        ),
        lambda row: row["candidates"][0]["metrics"]["response_io"].update(
            {"staging_bytes_written": 1}
        ),
        lambda row: row["candidates"][0]["metrics"]["execution"].update(
            {"query_gather_calls": 2}
        ),
        lambda row: row["candidates"][0]["metrics"][
            "proof_ready_arena"
        ].update({"response_round_allocations": 1}),
        lambda row: row["candidates"][0].update(
            {"expected_full_correlations": 1}
        ),
        lambda row: row["candidates"][0].pop(
            "model_transcript_replay_bytes"
        ),
        lambda row: row["candidates"][0].update(
            {"model_transcript_replay_labels": 24}
        ),
        lambda row: row["rebuild"].update({"host_oracle_bytes": 1}),
    )
    for index, mutate in enumerate(online_mutations):
        bad = copy.deepcopy(online)
        mutate(bad)
        case = tmp_path / f"bad-gpt2-online-{index}"
        bad_onboarding, bad_online = _write_x4c_gpt2_chain(
            case, onboarding, bad
        )
        assert (
            report.validate_x4c_gpt2_online_result(
                bad_online, bad_onboarding
            )
            is False
        )

    different_onboarding = copy.deepcopy(onboarding)
    different_onboarding["mask_seed_commitment_blake3"] = "d" * 64
    mismatched_onboarding, _ = _write_x4c_gpt2_chain(
        tmp_path / "chain-mismatch", different_onboarding, online
    )
    assert (
        report.validate_x4c_gpt2_online_result(
            online_path, mismatched_onboarding
        )
        is False
    )


def test_x4c_gpt2_accelerated_validator_requires_native_counters(tmp_path):
    report = load_report_module()
    onboarding, online = _x4c_gpt2_records(report)
    accelerated = _x4c_gpt2_accelerated_online(report, online)
    onboarding_path, accelerated_path = _write_x4c_gpt2_chain(
        tmp_path / "valid", onboarding, accelerated
    )
    assert (
        report.validate_x4c_gpt2_accelerated_online_result(
            accelerated_path, onboarding_path
        )
        is True
    )
    assert (
        report.validate_x4c_gpt2_online_result(
            accelerated_path, onboarding_path
        )
        is False
    )

    mutations = (
        lambda row: row["candidates"][0].pop("gate_audit"),
        lambda row: row["candidates"][0]["gate_audit"].update(
            {"traffic_exact": False}
        ),
        lambda row: row["candidates"][0]["gate_audit"].update(
            {"failed": ["traffic_exact"]}
        ),
        lambda row: row["candidates"][0]["gate_audit"].update(
            {"all_pass": False}
        ),
        lambda row: row["candidates"][0].pop(
            "expected_explicit_d2d_copy_bytes"
        ),
        lambda row: row["candidates"][0].pop(
            "expected_device_generated_bytes"
        ),
        lambda row: row["candidates"][0]["metrics"]["execution"].pop(
            "expected_explicit_d2d_copy_bytes"
        ),
        lambda row: row["candidates"][0]["metrics"]["execution"].update(
            {"expected_device_generated_bytes": 1}
        ),
        lambda row: row["candidates"][0]["backend"].update(
            {"explicit_d2d_copy_bytes": 1}
        ),
        lambda row: row["candidates"][0]["backend"].update(
            {"device_generated_bytes": 1}
        ),
        lambda row: row["candidates"][1].update(
            {
                "expected_device_generated_bytes":
                    report.X4C_PRODUCTION_FRESH_DEVICE_GENERATED_BYTES
            }
        ),
        lambda row: row["candidates"][0]["metrics"][
            "session_reusable_arena"
        ].update({"native_live_device_bytes": 0}),
        lambda row: row["candidates"][0]["metrics"][
            "proof_ready_arena"
        ].update({"native_peak_device_bytes": report.X4C_ARENA_BYTES}),
        lambda row: row["candidates"][0]["backend"].update(
            {"live_device_bytes": report.X4C_ARENA_BYTES}
        ),
        lambda row: row["rebuild"].pop("accelerated"),
        lambda row: row["rebuild"]["accelerated"].pop("expected_h2d_bytes"),
        lambda row: row["rebuild"]["accelerated"].update(
            {"automatic_cpu_fallback": True}
        ),
        lambda row: row["rebuild"]["accelerated"].update(
            {"mu26_mu22_overlap": True}
        ),
        lambda row: row["rebuild"]["accelerated"]["cohorts"][0][
            "backend"
        ].update({"h2d_bytes": 1}),
        lambda row: row["rebuild"]["accelerated"]["cohorts"][0][
            "control_after"
        ].update({"outstanding_cuda_operations": 1}),
        lambda row: row["rebuild"]["accelerated"]["cohorts"][0][
            "control_after"
        ].pop("coarse_timing_active"),
        lambda row: row["rebuild"]["accelerated"]["cohorts"][0].update(
            {"scratch_bytes_written": 1}
        ),
        lambda row: row["rebuild"]["accelerated"]["cohorts"][0].update(
            {"owned_file_count": 1}
        ),
        lambda row: row["rebuild"]["accelerated"]["cohorts"][0].update(
            {"owned_mapping_count": 1}
        ),
        lambda row: row["rebuild"]["accelerated"]["cohorts"][0].update(
            {"root_equal": False}
        ),
        lambda row: row["rebuild"]["accelerated"].update(
            {"peak_device_bytes": 1}
        ),
        lambda row: row["rebuild"]["accelerated"].pop(
            "backend_context_cleanup_wall_s"
        ),
        lambda row: row["rebuild"]["accelerated"].update(
            {"backend_context_dropped_before_response": False}
        ),
        lambda row: row["rebuild"]["accelerated"].update(
            {"online_backend_fresh_context": False}
        ),
        lambda row: row["rebuild"]["accelerated"].update(
            {"fresh_online_backend_device_bytes": 1}
        ),
        lambda row: row["rebuild"]["accelerated"].update(
            {"fresh_online_backend_outstanding_cuda_operations": 1}
        ),
        lambda row: row["rebuild"]["durable_census_after"].update(
            {"other_file_count": 1}
        ),
        lambda row: row.update({"rebuild_parallel_tasks": 5}),
    )
    for index, mutate in enumerate(mutations):
        bad = copy.deepcopy(accelerated)
        mutate(bad)
        bad_onboarding, bad_online = _write_x4c_gpt2_chain(
            tmp_path / f"tamper-{index}", onboarding, bad
        )
        assert (
            report.validate_x4c_gpt2_accelerated_online_result(
                bad_online, bad_onboarding
            )
            is False
        )


def test_x4c_gpt2_v3_crypto_identity_allows_only_compatible_descendants(
    tmp_path, monkeypatch
):
    report = load_report_module()
    onboarding, online = _x4c_gpt2_v3_records(report)
    onboarding_path, online_path, admission_path = (
        _write_x4c_gpt2_v3_chain(
            tmp_path / "valid-v3", report, onboarding, online
        )
    )
    assert onboarding["git_sha"] != online["git_sha"]
    assert report.validate_x4c_gpt2_v3_onboarding_result(onboarding_path)
    assert report.validate_x4c_gpt2_v3_accelerated_online_result(
        online_path, onboarding_path, admission_path
    )
    assert not report.validate_x4c_gpt2_accelerated_online_result(
        online_path, onboarding_path
    )

    target_miss = copy.deepcopy(online)
    target_miss["campaign_rebuild_finished_unix_s"] = (
        target_miss["campaign_started_unix_s"]
        + report.X4C_CAMPAIGN_TARGET_S
        + 300
    )
    target_miss["campaign_elapsed_through_rebuild_s"] = (
        report.X4C_CAMPAIGN_TARGET_S + 300
    )
    target_miss["rebuild_campaign_target_met"] = False
    miss_onboarding, miss_online, miss_admission = (
        _write_x4c_gpt2_v3_chain(
            tmp_path / "valid-target-miss-v3",
            report,
            onboarding,
            target_miss,
        )
    )
    assert report.validate_x4c_gpt2_v3_accelerated_online_result(
        miss_online, miss_onboarding, miss_admission
    )

    mutations = (
        lambda row: row["online"].pop("crypto_build_id"),
        lambda row: row["online"].update({"crypto_build_id": "1" * 64}),
        lambda row: row["online"].update(
            {"crypto_build_id_scheme": "unregistered"}
        ),
        lambda row: row["online"].update(
            {"crypto_build_manifest_blake3": "2" * 64}
        ),
        lambda row: row["online"].update({"crypto_build_file_count": 320}),
        lambda row: row["online"].update({"producer_source_sha256": "3" * 64}),
        lambda row: row["online"].update({"campaign_target_s": 2_701}),
        lambda row: row["online"].update(
            {"campaign_elapsed_through_rebuild_s": 241}
        ),
        lambda row: row["online"].update(
            {"rebuild_campaign_target_met": False}
        ),
        lambda row: row["onboarding"].update(
            {"campaign_target_met": False}
        ),
    )
    for index, mutate in enumerate(mutations):
        pair = {
            "onboarding": copy.deepcopy(onboarding),
            "online": copy.deepcopy(online),
        }
        mutate(pair)
        bad_onboarding, bad_online, bad_admission = (
            _write_x4c_gpt2_v3_chain(
                tmp_path / f"tamper-v3-{index}",
                report,
                pair["onboarding"],
                pair["online"],
            )
        )
        assert not report.validate_x4c_gpt2_v3_accelerated_online_result(
            bad_online, bad_onboarding, bad_admission
        )

    monkeypatch.setattr(
        report,
        "_clean_validator_provenance",
        lambda: ("9" * 40, "8" * 64),
    )
    receipt_path = tmp_path / "receipt.json"
    assert (
        report.write_x4c_gpt2_v3_validation_receipt(
            online_path, onboarding_path, admission_path, receipt_path
        )
        == receipt_path
    )
    receipt = json.loads(receipt_path.read_text())
    assert receipt["overall_pass"] is True
    assert receipt["crypto_build_id"] == online["crypto_build_id"]
    assert receipt["validator_git_sha"] == "9" * 40
    assert receipt["validator_implementation_sha256"] == "8" * 64
    with pytest.raises(FileExistsError):
        report.write_x4c_gpt2_v3_validation_receipt(
            online_path, onboarding_path, admission_path, receipt_path
        )


def _x4c_rebuild_preflight_record(report):
    _, online = _x4c_gpt2_records(report)
    accelerated = _x4c_gpt2_accelerated_online(report, online)
    rebuild = copy.deepcopy(
        accelerated["rebuild"]["accelerated"]["cohorts"][3]
    )
    fixture = report._X4C_REBUILD_PREFLIGHT_STAGES["aux-ell16"]
    logical = fixture["final_resident_host_bytes"]
    census = {
        "root_exists": False,
        "directory_count": 0,
        "file_count": 0,
        "symlink_count": 0,
        "byte_count": 0,
        "structural_blake3": "d" * 64,
    }
    return {
        "schema": 2,
        "milestone": report.X4C_GPT2_REBUILD_PREFLIGHT_MILESTONE,
        "git_sha": "a" * 40,
        "git_dirty": False,
        "profile": report.X4C_POD_PROFILE,
        "protocol": report.X4C_GPT2_PROTOCOL,
        "design_sha256": report.X4C_V1_DESIGN_SHA256,
        "stage": "aux-ell16",
        "manual_single_stage": True,
        "next_stage_launched": False,
        "automatic_cpu_fallback": False,
        "production_gate_credit": False,
        "fixture": copy.deepcopy(fixture),
        "durable_census_before": copy.deepcopy(census),
        "durable_census_after": copy.deepcopy(census),
        "durable_census_stable": True,
        "host_memory_preflight": {
            "mem_available_bytes": fixture["estimated_rebuild_peak_bytes"] + 1,
            "estimated_rebuild_peak_bytes": fixture[
                "estimated_rebuild_peak_bytes"
            ],
            "sufficient": True,
        },
        "cuda_memory_preflight": {
            "free_bytes": fixture["estimated_device_working_set_bytes"] + 1,
            "total_bytes": fixture["estimated_device_working_set_bytes"] + 2,
            "estimated_working_set_bytes": fixture[
                "estimated_device_working_set_bytes"
            ],
            "sufficient": True,
        },
        "fixture_generation_wall_s": 0.1,
        "cpu_reference_wall_s": 0.2,
        "cpu_reference_root": "e" * 64,
        "cuda_rebuild_root": "e" * 64,
        "root_reference_equality": True,
        "rebuild": rebuild,
        "logical_rebuild_bytes": logical,
        "logical_bytes_per_second": logical / rebuild["wall_s"],
        "final_process_memory": {
            "rss_bytes": 100,
            "peak_rss_bytes": 200,
        },
        "scratch_files_created": 0,
        "scratch_bytes_read": 0,
        "scratch_bytes_written": 0,
        "abort_reasons": [],
        "accepted": True,
    }


def test_x4c_rebuild_preflight_validator_is_progressive_and_fail_closed(
    tmp_path,
):
    report = load_report_module()
    row = _x4c_rebuild_preflight_record(report)
    path = tmp_path / "preflight.json"
    path.write_text(json.dumps(row))
    assert report.validate_x4c_rebuild_preflight_result(path) is True

    mutations = (
        lambda item: item.pop("cuda_memory_preflight"),
        lambda item: item.update({"next_stage_launched": True}),
        lambda item: item.update({"production_gate_credit": True}),
        lambda item: item.update({"root_reference_equality": False}),
        lambda item: item["rebuild"]["backend"].update({"d2h_bytes": 1}),
        lambda item: item["rebuild"]["control_after"].update(
            {"measurement_active": True}
        ),
        lambda item: item.update({"scratch_files_created": 1}),
        lambda item: item["durable_census_after"].update({"file_count": 1}),
        lambda item: item["host_memory_preflight"].update(
            {"sufficient": False}
        ),
    )
    for index, mutate in enumerate(mutations):
        bad = copy.deepcopy(row)
        mutate(bad)
        bad_path = tmp_path / f"bad-preflight-{index}.json"
        bad_path.write_text(json.dumps(bad))
        assert report.validate_x4c_rebuild_preflight_result(bad_path) is False


def test_x4c_rebuild_projection_is_diagnostic_only(tmp_path):
    report = load_report_module()
    stage = _x4c_rebuild_preflight_record(report)
    floor = stage["logical_bytes_per_second"]
    census = copy.deepcopy(stage["durable_census_before"])
    targets = []
    for name, expected in (
        (
            "mu22",
            report._x4c_rebuild_preflight_geometry(
                0xA5000002,
                26,
                64,
                36,
                oracle_kind="weight-extension",
                production=True,
            ),
        ),
        (
            "mu26",
            report._x4c_rebuild_preflight_geometry(
                0xA5000001,
                30,
                2,
                2,
                oracle_kind="weight-extension",
                production=True,
            ),
        ),
    ):
        targets.append(
            {
                "cohort_id": expected["cohort_id"],
                "name": name,
                "coefficient_bytes": expected["coefficient_bytes"],
                "host_oracle_bytes": expected["host_oracle_bytes"],
                "host_outer_cache_bytes": expected[
                    "host_outer_cache_bytes"
                ],
                "final_resident_host_bytes": expected[
                    "final_resident_host_bytes"
                ],
                "estimated_rebuild_peak_bytes": expected[
                    "estimated_rebuild_peak_bytes"
                ],
                "estimated_device_working_set_bytes": expected[
                    "estimated_device_working_set_bytes"
                ],
                "projected_wall_s": (
                    expected["final_resident_host_bytes"] / floor
                ),
            }
        )
    projection = {
        "schema": 2,
        "milestone": report.X4C_GPT2_REBUILD_PREFLIGHT_MILESTONE,
        "git_sha": "a" * 40,
        "git_dirty": False,
        "profile": report.X4C_POD_PROFILE,
        "protocol": report.X4C_GPT2_PROTOCOL,
        "design_sha256": report.X4C_V1_DESIGN_SHA256,
        "stage": "project",
        "manual_single_stage": True,
        "next_stage_launched": False,
        "production_gate_credit": False,
        "source_stages": ["aux-ell16", "aux-ell17", "mu20"],
        "source_record_blake3": ["a" * 64, "b" * 64, "c" * 64],
        "conservative_floor_logical_bytes_per_second": floor,
        "targets": targets,
        "durable_census_before": copy.deepcopy(census),
        "durable_census_after": copy.deepcopy(census),
        "durable_census_stable": True,
        "decision_only": True,
        "accepted": True,
    }
    path = tmp_path / "projection.json"
    path.write_text(json.dumps(projection))
    assert report.validate_x4c_rebuild_preflight_result(path) is True
    projection["production_gate_credit"] = True
    path.write_text(json.dumps(projection))
    assert report.validate_x4c_rebuild_preflight_result(path) is False


def _x4c_test_availability():
    return {"available": True, "reason": ""}


def _x4c_test_ownership(codewords=0, cache=0, other=0, borrowed=0):
    borrowed_paths = [f"/persistent/oracle-{index}" for index in range(borrowed)]
    return {
        "fold_codeword_bytes": codewords,
        "fold_outer_cache_bytes": cache,
        "other_ordinary_host_bytes": other,
        "ordinary_host_bytes": codewords + cache + other,
        "pinned_host_bytes": 0,
        "device_bytes": 0,
        "file_backed_bytes": 0,
        "owned_file_count": 0,
        "owned_mapping_count": 0,
        "owned_files": [],
        "owned_mappings": [],
        "borrowed_initial_source_file_count": borrowed,
        "borrowed_initial_source_files": borrowed_paths,
    }


def _x4c_test_boundary(seq, label, ownership, *, cuda_pending=False):
    enter = seq * 100
    allocated = 10_000 + seq * 100
    deallocated = 1_000 + seq * 10
    return {
        "schema": 1,
        "seq": seq,
        "label": label,
        "monotonic_enter_ns": enter,
        "monotonic_exit_ns": enter + 10,
        "snapshot_probe_wall_ns": 10,
        "process_io": {
            "availability": _x4c_test_availability(),
            "rchar": 100 + seq,
            "wchar": 200 + seq,
            "read_bytes": 300 + seq,
            "write_bytes": 400 + seq,
        },
        "page_faults": {
            "availability": _x4c_test_availability(),
            "minor_faults": 10 + seq,
            "major_faults": seq,
        },
        "process_memory": {
            "availability": _x4c_test_availability(),
            "rss_bytes": 1_000_000,
            "locked_bytes": 0,
        },
        "smaps_rollup": {
            "availability": _x4c_test_availability(),
            "rss_bytes": 1_000_000,
            "pss_bytes": 900_000,
            "anonymous_bytes": 800_000,
            "file_bytes": 100_000,
            "shmem_bytes": 0,
            "private_clean_bytes": 0,
            "private_dirty_bytes": 800_000,
            "shared_clean_bytes": 100_000,
            "shared_dirty_bytes": 100_000,
            "swap_bytes": 0,
        },
        "allocator": {
            "availability": _x4c_test_availability(),
            "allocation_calls": 100 + seq,
            "alloc_zeroed_calls": seq,
            "reallocation_calls": seq,
            "deallocation_calls": 50 + seq,
            "cumulative_allocated_bytes": allocated,
            "cumulative_deallocated_bytes": deallocated,
            "outstanding_requested_bytes": allocated - deallocated,
            "allocator_allocated_bytes": 500_000,
            "allocator_mapped_bytes": 1_000_000,
            "arena_bytes": 800_000,
            "mmap_region_bytes": 200_000,
            "free_arena_bytes": 300_000,
        },
        "numa": {
            "availability": _x4c_test_availability(),
            "page_size_bytes": 4096,
            "total_node_pages": 100,
            "node_pages": {"N0": 100},
        },
        "cuda": {
            "availability": _x4c_test_availability(),
            "device_workspace_bytes": 0,
            "device_resident_bytes": 0,
            "device_cached_bytes": 0,
            "device_live_bytes": 0,
            "pinned_host_bytes": 0,
            "outstanding_operations": 1 if cuda_pending else 0,
            "measurement_active": cuda_pending,
            "synchronized": not cuda_pending,
        },
        "sealed_ownership": copy.deepcopy(ownership),
        "temporary_files": {
            "live_file_count": 0,
            "live_file_bytes": 0,
            "live_directory_count": 0,
            "cumulative_created_files": 0,
            "cumulative_deleted_files": 0,
            "cumulative_created_directories": 0,
            "cumulative_deleted_directories": 0,
        },
    }


def _x4c_test_machine():
    return {
        "provider": "RunPod",
        "gpu": "NVIDIA A100-SXM4-80GB",
        "memory_bytes": 256 * 1024**3,
        "rayon_threads": 8,
        "commit_seal_open_unpinned": True,
        "durable_tier": "coefficients_plus_five_roots_on_persistent",
        "local_storage_role": "scratch_ram_spill_and_records",
        "persistent_class": "PERSISTENT",
        "persistent_volume": {
            "path": "/persistent",
            "filesystem_type": "ext4",
            "mount_point": "/persistent",
            "available_bytes": 20_000_000_000,
        },
        "local_non_mfs_storage": {
            "path": "/local",
            "filesystem_type": "ext4",
            "mount_point": "/local",
            "available_bytes": 200_000_000_000,
        },
    }


def _x4c_test_immutable():
    return {
        "protocol_profile": "x4-zkdeepfold-ud-e29-v4",
        "rate": "1/8",
        "query_count": 111,
        "pcs_bytes": 2_683_236,
        "response_bytes": 43_953_700,
        "proof_format_changed": False,
        "root_changed": False,
        "lean_changed": False,
        "soundness_changed": False,
    }


def _x4c_test_probe_candidate(variant, ordinal, measured, pid, wall):
    geometry = {
        "domain_log2": 29,
        "fold_rounds": 27,
        "fold_codeword_bytes": 17_179_869_056,
        "fold_outer_cache_bytes": 34_359_737_248,
        "populated_bytes": 51_539_606_304,
    }
    zero = _x4c_test_ownership()
    populated = _x4c_test_ownership(
        geometry["fold_codeword_bytes"], geometry["fold_outer_cache_bytes"]
    )
    labels_and_ownership = [("probe_start", zero), ("payload_populated", populated)]
    timing = {
        "allocation_population_wall_ns": 10,
        "proof_ready_wall_ns": 20,
        "distributed_drop_wall_ns": 0,
        "destroy_codewords_wall_ns": 0,
        "destroy_outer_cache_levels_wall_ns": 0,
        "destroy_remaining_state_wall_ns": 0,
        "logical_arena_reset_wall_ns": 0,
        "backing_release_wall_ns": 0,
        "teardown_total_wall_ns": 0,
        "session_reusable_wall_ns": 30,
        "parent_child_wall_ns": wall,
        "child_reap_wall_ns": 1,
    }
    termination = "normal_return_after_explicit_teardown"
    retained = 0
    arena_retained = 0
    outstanding = 0
    if variant == "distributed_drop":
        timing["distributed_drop_wall_ns"] = 1
        timing["teardown_total_wall_ns"] = 2
        labels_and_ownership.append(("distributed_state_destroyed", zero))
    elif variant == "manually_drop_no_teardown":
        labels_and_ownership[1] = ("payload_populated_no_teardown", populated)
        timing["session_reusable_wall_ns"] = None
        termination = "_exit_no_destructors"
        retained = geometry["populated_bytes"]
        outstanding = geometry["populated_bytes"]
    elif variant == "categorized_drop":
        timing["destroy_codewords_wall_ns"] = 1
        timing["destroy_outer_cache_levels_wall_ns"] = 1
        timing["destroy_remaining_state_wall_ns"] = 1
        timing["teardown_total_wall_ns"] = 3
        labels_and_ownership.extend(
            [
                (
                    "codewords_destroyed",
                    _x4c_test_ownership(0, geometry["fold_outer_cache_bytes"]),
                ),
                ("outer_cache_levels_destroyed", zero),
                ("remaining_state_destroyed", zero),
            ]
        )
    elif variant == "single_arena_reset":
        timing["logical_arena_reset_wall_ns"] = 1
        timing["backing_release_wall_ns"] = 1
        timing["teardown_total_wall_ns"] = 2
        arena_retained = geometry["populated_bytes"]
        labels_and_ownership.extend(
            [
                (
                    "arena_logically_reset_backing_retained",
                    _x4c_test_ownership(0, 0, geometry["populated_bytes"]),
                ),
                ("arena_backing_released", zero),
            ]
        )
    else:
        raise AssertionError(variant)
    boundaries = [
        _x4c_test_boundary(seq, label, ownership)
        for seq, (label, ownership) in enumerate(labels_and_ownership)
    ]
    return {
        "ordinal": ordinal,
        "measured": measured,
        "child_pid": pid,
        "variant": variant,
        "geometry": copy.deepcopy(geometry),
        "populated_bytes": geometry["populated_bytes"],
        "touched_pages": 1,
        "population_checksum_u64": 123,
        "timing": timing,
        "boundaries": boundaries,
        "termination": termination,
        "intentionally_retained_bytes": retained,
        "arena_backing_retained_after_reset_bytes": arena_retained,
        "outstanding_payload_bytes_after_teardown": outstanding,
        "child_exit_success": True,
        "child_exit_code": 0,
        "accepted": True,
        "obstruction_reasons": [],
    }


def _x4c_test_probe_record():
    geometry = {
        "domain_log2": 29,
        "fold_rounds": 27,
        "fold_codeword_bytes": 17_179_869_056,
        "fold_outer_cache_bytes": 34_359_737_248,
        "populated_bytes": 51_539_606_304,
    }
    variants = []
    pid = 1000
    for name in (
        "distributed_drop",
        "manually_drop_no_teardown",
        "categorized_drop",
        "single_arena_reset",
    ):
        warmup = _x4c_test_probe_candidate(name, 0, False, pid, 500)
        pid += 1
        measured = [
            _x4c_test_probe_candidate(name, 1, True, pid, 1000),
            _x4c_test_probe_candidate(name, 2, True, pid + 1, 3000),
            _x4c_test_probe_candidate(name, 3, True, pid + 2, 2000),
        ]
        pid += 3
        variants.append(
            {
                "variant": name,
                "warmup_count": 1,
                "measured_candidate_count": 3,
                "warmup": warmup,
                "measured_candidates": measured,
                "selected_upper_median_ordinal": 3,
                "all_accepted": True,
            }
        )
    return {
        "schema": 1,
        "milestone": "X4c-phase2-exact-size-lifecycle-probe",
        "phase": 2,
        "date": "2026-07-23",
        "git_sha": "a" * 40,
        "git_dirty": False,
        "pod_profile": "runpod-a100-x4c-v1",
        "mode": "exact_pod",
        "pod_contacted": True,
        "machine": _x4c_test_machine(),
        "immutable": _x4c_test_immutable(),
        "geometry": geometry,
        "warmup_count_per_variant": 1,
        "measured_candidates_per_variant": 3,
        "child_process_isolation": True,
        "variants": variants,
        "all_accepted": True,
        "hard_stop_before_x4c_online": True,
    }


def _x4c_test_context():
    return {
        "cohort_id": None,
        "fold_round": None,
        "slot_index": None,
        "initial_group_index": None,
        "outer_level": None,
        "segment_index": 0,
    }


def _x4c_test_legacy_record(report):
    events = []
    spans = []
    boundaries = []
    current = _x4c_test_ownership(
        report.X4C_PRODUCTION_FOLD_CODEWORD_BYTES,
        report.X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES,
        borrowed=5,
    )

    def event(track, phase, transition, nesting, ownership, *, pending=False):
        seq = len(boundaries)
        context = _x4c_test_context()
        boundaries.append(
            _x4c_test_boundary(
                seq,
                f"{track}:{phase}:{transition}",
                ownership,
                cuda_pending=pending,
            )
        )
        events.append(
            {
                "schema": 1,
                "track": track,
                "phase": phase,
                "transition": transition,
                "nesting": nesting,
                "context": context,
                "boundary_seq": seq,
            }
        )
        return seq

    def span(track, phase, ownership, end_ownership=None, nested=None):
        pending = phase == "backend_finish_synchronization_boundary"
        start = event(track, phase, "span_start", "top_level", ownership, pending=pending)
        if nested is not None:
            nested_start = event(
                track,
                nested,
                "span_start",
                "nested",
                ownership,
            )
            nested_end = event(track, nested, "span_end", "nested", ownership)
            spans.append(
                {
                    "track": track,
                    "phase": nested,
                    "nesting": "nested",
                    "context": _x4c_test_context(),
                    "start_seq": nested_start,
                    "end_seq": nested_end,
                    "subject_wall_ns": 90,
                    "inclusive_wall_ns": 110,
                    "boundary_probe_wall_ns": 20,
                }
            )
        end = event(
            track,
            phase,
            "span_end",
            "top_level",
            end_ownership if end_ownership is not None else ownership,
        )
        spans.append(
            {
                "track": track,
                "phase": phase,
                "nesting": "top_level",
                "context": _x4c_test_context(),
                "start_seq": start,
                "end_seq": end,
                "subject_wall_ns": (end - start) * 100 - 10,
                "inclusive_wall_ns": (end - start) * 100 + 10,
                "boundary_probe_wall_ns": 20,
            }
        )

    seal_order = [
        "coefficient_clone_allocation",
        "e_ntt",
        "coefficient_oracle_write",
        "flush_sync_data",
        "oracle_reread_n4_inner",
        "n4_outer_levels",
        "full_oracle_comparison",
        "cpu_codeword_cache_clone_back",
        "file_cleanup",
        "directory_cleanup",
        "backend_finish_synchronization_boundary",
    ]
    for phase in seal_order:
        span("legacy_seal", phase, current)

    for phase in (
        "draw_validation_schedule",
        "initial_group_opening",
        "fold_round_opening",
        "schedule_digest_structural_validation",
        "canonical_encode_serialization",
    ):
        span(
            "legacy_opening",
            phase,
            current,
            nested="inner_hashing_path_assembly"
            if phase == "initial_group_opening"
            else None,
        )
    cache_only = _x4c_test_ownership(
        0, report.X4C_PRODUCTION_FOLD_OUTER_CACHE_BYTES, borrowed=5
    )
    zero = _x4c_test_ownership(borrowed=5)
    span("legacy_opening", "destroy_codewords", current, cache_only)
    current = cache_only
    span("legacy_opening", "destroy_outer_cache_levels", current, zero)
    current = zero
    span("legacy_opening", "destroy_remaining_sealed_state", current, zero)
    return {
        "schema": 1,
        "milestone": "X4c-phase2-legacy-causal-diagnostic",
        "phase": 2,
        "pod_profile": "runpod-a100-x4c-v1",
        "git_sha": "b" * 40,
        "git_dirty": False,
        "immutable": _x4c_test_immutable(),
        "machine": _x4c_test_machine(),
        "terminology_correction": {
            "byte_reconciliation_difference_bytes": 49_216,
            "byte_reconciliation_classification": "EXACT_BYTE_RECONCILIATION",
            "reconstructed_wall_residual_ns": 59_601,
            "aggregate_rate_derived_from_same_wall": True,
            "independent_causal_timing_evidence": False,
            "production_host_cause": "OPEN_PENDING_PART4_PROBE",
            "design_depends_on_specific_cause": False,
            "retracted_hypotheses": [
                "pinned_memory_deregistration",
                "unlink_writeback_during_open",
            ],
        },
        "candidates": [
            {
                "ordinal": 0,
                "accepted": True,
                "obstruction_reasons": [],
                "packed_opening_bytes": 2_615_414,
                "pcs_bytes": 2_683_236,
                "response_bytes": 43_953_700,
                "boundaries": boundaries,
                "events": events,
                "spans": spans,
                "zero_expected_controls": {
                    "pinned_memory_deregistrations_during_open": 0,
                    "unlink_calls_during_open": 0,
                    "writeback_bytes_during_open": 0,
                    "sealed_owned_pinned_bytes": 0,
                    "sealed_owned_device_bytes": 0,
                    "sealed_owned_file_backed_bytes": 0,
                },
            }
        ],
        "verdict": "DIAGNOSTIC_COMPLETE — cause remains open",
        "hard_stop": False,
    }


def test_x4c_phase2_lifecycle_probe_validator_is_fail_closed(tmp_path):
    report = load_report_module()
    record = _x4c_test_probe_record()
    assert report._x4c_lifecycle_probe_result_valid(record) is True
    path = tmp_path / "probe.json"
    path.write_text(json.dumps(record))
    assert report.validate_x4c_lifecycle_probe_result(path) is True

    mutations = []
    bad = copy.deepcopy(record)
    bad["geometry"]["populated_bytes"] -= 1
    mutations.append(bad)
    bad = copy.deepcopy(record)
    bad["variants"][0]["measured_candidates"][0]["boundaries"][0]["allocator"].pop(
        "allocator_mapped_bytes"
    )
    mutations.append(bad)
    bad = copy.deepcopy(record)
    bad["variants"][0]["measured_candidates"][1]["child_pid"] = bad["variants"][0][
        "measured_candidates"
    ][0]["child_pid"]
    mutations.append(bad)
    bad = copy.deepcopy(record)
    bad["variants"][1]["measured_candidates"][0]["termination"] = "normal_return"
    mutations.append(bad)
    bad = copy.deepcopy(record)
    bad["variants"][2]["measured_candidates"][0]["boundaries"][2][
        "sealed_ownership"
    ]["fold_outer_cache_bytes"] -= 1
    mutations.append(bad)
    bad = copy.deepcopy(record)
    bad["variants"][3]["measured_candidates"][0]["timing"][
        "backing_release_wall_ns"
    ] = 0
    mutations.append(bad)
    bad = copy.deepcopy(record)
    bad["variants"][0]["selected_upper_median_ordinal"] = 1
    mutations.append(bad)
    bad = copy.deepcopy(record)
    bad["machine"]["local_non_mfs_storage"]["filesystem_type"] = "tmpfs"
    mutations.append(bad)
    bad = copy.deepcopy(record)
    bad["immutable"]["rate"] = "1/4"
    mutations.append(bad)
    for candidate in mutations:
        assert report._x4c_lifecycle_probe_result_valid(candidate) is False


def test_x4c_phase2_legacy_causal_validator_checks_timeline_and_zero_controls(
    tmp_path,
):
    report = load_report_module()
    record = _x4c_test_legacy_record(report)
    assert report._x4c_legacy_causal_result_valid(record) is True
    path = tmp_path / "legacy.json"
    path.write_text(json.dumps(record))
    assert report.validate_x4c_legacy_causal_result(path) is True

    bad = copy.deepcopy(record)
    bad["terminology_correction"]["independent_causal_timing_evidence"] = True
    assert report._x4c_legacy_causal_result_valid(bad) is False
    bad = copy.deepcopy(record)
    finish = next(
        span
        for span in bad["candidates"][0]["spans"]
        if span["phase"] == "backend_finish_synchronization_boundary"
    )
    finish["end_seq"] = len(bad["candidates"][0]["boundaries"]) - 1
    assert report._x4c_legacy_causal_result_valid(bad) is False
    bad = copy.deepcopy(record)
    bad["candidates"][0]["zero_expected_controls"][
        "pinned_memory_deregistrations_during_open"
    ] = 1
    assert report._x4c_legacy_causal_result_valid(bad) is False
    bad["candidates"][0]["accepted"] = False
    bad["candidates"][0]["obstruction_reasons"] = ["unexpected deregistration"]
    bad["verdict"] = "HARD_STOP_OBSTRUCTION — unexpected legacy ownership"
    bad["hard_stop"] = True
    assert report._x4c_legacy_causal_result_valid(bad) is True
    unavailable = copy.deepcopy(record)
    unavailable["candidates"][0]["boundaries"][0]["smaps_rollup"][
        "availability"
    ] = {"available": False, "reason": "kernel denied smaps_rollup"}
    unavailable["candidates"][0]["accepted"] = False
    unavailable["candidates"][0]["obstruction_reasons"] = [
        "required smaps_rollup counter unavailable"
    ]
    unavailable["verdict"] = "HARD_STOP_OBSTRUCTION — missing counter"
    unavailable["hard_stop"] = True
    assert report._x4c_legacy_causal_result_valid(unavailable) is True
    unavailable["candidates"][0]["boundaries"][0]["smaps_rollup"].pop(
        "availability"
    )
    assert report._x4c_legacy_causal_result_valid(unavailable) is False
    bad = copy.deepcopy(record)
    destroy = next(
        event
        for event in bad["candidates"][0]["events"]
        if event["phase"] == "destroy_codewords"
        and event["transition"] == "span_end"
    )
    bad["candidates"][0]["boundaries"][destroy["boundary_seq"]][
        "sealed_ownership"
    ]["fold_codeword_bytes"] = 1
    assert report._x4c_legacy_causal_result_valid(bad) is False


def test_resident_profile_joins_only_same_host_native_anchor_and_keeps_full_accounting():
    report = load_report_module()
    raw = {
        "_mtime": 1.0,
        "_path": "benchmarks/results/resident.json",
        "report_schema_version": 4,
        "milestone": "P7-integrated-resident",
        "git_dirty": False,
        "accepted": True,
        "accelerator_backend": "cuda-resident",
        "cloud": {"instance_id": "a100-record"},
        "t_prefill": 100,
        "n_decode": 50,
        "t_prove_prefill_only_s": 0.1,
        "t_prove_response_s": 1.1,
        "t_prove_decode_marginal_s": 1.0,
        "t_prover_online_accounted_response_s": 1.3,
        "t_prover_online_accounted_decode_marginal_s": 1.2,
        "t_response_session_wall_s": 2.0,
        "t_protocol_closure_exchange_s": 0.02,
        "t_verifier_accounted_s": 0.04,
        "pcs_commit_timing": {"median_s": 0.5},
        "pcs_open_timing": {"median_s": 0.18},
        "pcs_verify_timing": {"median_s": 0.01},
        "closure_prod_claims": 17,
        "closure_zero_claims": 23,
        "closure_prod_scalar_soundness_bits": 123.0,
        "closure_zero_scalar_soundness_bits": 122.5,
        "closure_union_scalar_soundness_bits": 121.75,
        "accelerator_witness": {"measurement_wall_s": 0.03},
        "accelerator_response_witness": {"measurement_wall_s": 0.7},
        "accelerator_proving": {
            "allocation_calls": 7,
            "resident_alloc_requests": 101,
            "resident_reuse_hits": 89,
            "resident_free_requests": 101,
            "physical_free_calls": 2,
        },
        "accelerator_live_device_bytes_after_cleanup": 30,
        "accelerator_workspace_device_bytes_after_cleanup": 10,
        "accelerator_resident_device_bytes_after_cleanup": 0,
        "accelerator_cached_resident_device_bytes_after_cleanup": 20,
        "accelerator_live_device_bytes_after_cache_trim": 10,
        "accelerator_workspace_device_bytes_after_cache_trim": 10,
        "accelerator_resident_device_bytes_after_cache_trim": 0,
        "accelerator_cached_resident_device_bytes_after_cache_trim": 0,
        "pcg_backend": "mock",
        "pcg_setup_comm_bytes": 0,
    }
    resident = report.integrated_resident_profiles([raw])[0]
    assert resident["report_schema_version"] == 4
    assert resident["accelerator_live_device_bytes_after_cleanup"] == 30
    assert resident["accelerator_workspace_device_bytes_after_cleanup"] == 10
    assert resident["accelerator_resident_device_bytes_after_cleanup"] == 0
    assert resident["accelerator_cached_resident_device_bytes_after_cleanup"] == 20
    assert resident["accelerator_cleanup_memory_accounting_ok"] is True
    assert resident["accelerator_live_device_bytes_after_cache_trim"] == 10
    assert resident["accelerator_workspace_device_bytes_after_cache_trim"] == 10
    assert resident["accelerator_resident_device_bytes_after_cache_trim"] == 0
    assert resident["accelerator_cached_resident_device_bytes_after_cache_trim"] == 0
    assert resident["accelerator_cache_trim_memory_accounting_ok"] is True
    assert resident["accelerator_session"] == {
        "allocation_calls": 7,
        "resident_alloc_requests": 101,
        "resident_reuse_hits": 89,
        "resident_free_requests": 101,
        "physical_free_calls": 2,
    }
    assert resident["scalar_closure_soundness"] == {
        "prod_claims": 17,
        "zero_claims": 23,
        "prod_bits": 123.0,
        "zero_bits": 122.5,
        "union_bits": 121.75,
    }

    assert report.resident_run_of_record_eligible(resident) is True
    invalid_schema4 = dict(resident, accelerator_cache_trim_memory_accounting_ok=False)
    assert report.resident_run_of_record_eligible(invalid_schema4) is False
    missing_schema4 = dict(resident)
    missing_schema4.pop("accelerator_cleanup_memory_accounting_ok")
    assert report.resident_run_of_record_eligible(missing_schema4) is False
    historical_schema3 = dict(
        resident,
        report_schema_version=3,
        accelerator_cleanup_memory_accounting_ok=None,
        accelerator_cache_trim_memory_accounting_ok=None,
    )
    assert report.resident_run_of_record_eligible(historical_schema3) is True

    wrong_host = {
        "source": "wrong.json",
        "milestone": "P7-gpu-native-inference",
        "git_dirty": False,
        "cloud": {"instance_id": "other"},
        "prefill_s": 0.02,
        "decode_50_s": 0.6,
    }
    native = {
        "source": "native.json",
        "milestone": "P7-gpu-native-inference",
        "git_dirty": False,
        "cloud": {"instance_id": "a100-record"},
        "prefill_s": 0.02,
        "decode_50_s": 0.6,
    }
    assert report.same_host_native([wrong_host], resident) is None
    assert report.same_host_native([wrong_host, native], resident) is native

    joined = report.integrated_same_host_result(resident, native)
    assert joined["proof_rho"] == {"prefill": 5.0, "decode": 1.0 / 0.6}
    assert joined["target_met"] == {"prefill": True, "decode": True}
    assert joined["online_accounted"]["response_s"] == 1.3
    assert joined["pcs"] == {
        "commit_offline_s": 0.5,
        "open_online_s": 0.18,
        "verify_s": 0.01,
    }
    assert joined["measured_resident_pipeline_s"] == {
        "prefill_inference_plus_protocol_core": 0.13,
        "response_inference_plus_online_accounted": 2.0,
        "response_inference_plus_full_session_wall": 2.7,
    }


def test_p7b_resident_profile_is_separate_and_cannot_replace_closed_p7(tmp_path):
    report = load_report_module()
    historical = {
        "_mtime": 1.0,
        "_path": "benchmarks/results/p7-historical.json",
        "report_schema_version": 3,
        "milestone": "P7-integrated-resident",
        "git_dirty": False,
        "accepted": True,
        "accelerator_backend": "cuda-resident",
    }
    sha = "a" * 40
    repetitions = [
        {
            "repetition": 1,
            "t_prove_prefill_only_s": 9.0,
            "t_prove_decode_marginal_s": 3.0,
            "t_response_session_wall_s": 10.0,
            "p7b_sync_wall_fraction": 0.01,
            "accelerator_session": {
                "timing_method": "wall-only-counters",
                "phase_attribution_available": False,
                "timing_records": 0,
                "timing_elapsed_query_attempts": 0,
                "timing_elapsed_no_write": 0,
                "timing_event_queries": 0,
                "timing_event_api_calls": 0,
                "resident_h2d_host_calls": 100,
                "resident_d2h_host_calls": 4_000,
                "resident_h2d_host_call_s": 0.01,
                "resident_d2h_host_call_s": 0.02,
                "synchronizations": 59_868,
                "synchronization_s": 0.1,
                "h2d_bytes": 90_000_000,
            },
        },
        {
            "repetition": 2,
            "t_prove_prefill_only_s": 10.0,
            "t_prove_decode_marginal_s": 4.0,
            "t_response_session_wall_s": 10.0,
            "p7b_sync_wall_fraction": 0.02,
            "accelerator_session": {
                "timing_method": "wall-only-counters",
                "phase_attribution_available": False,
                "timing_records": 0,
                "timing_elapsed_query_attempts": 0,
                "timing_elapsed_no_write": 0,
                "timing_event_queries": 0,
                "timing_event_api_calls": 0,
                "resident_h2d_host_calls": 100,
                "resident_d2h_host_calls": 5_000,
                "resident_h2d_host_call_s": 0.01,
                "resident_d2h_host_call_s": 0.02,
                "synchronizations": 59_868,
                "synchronization_s": 0.2,
                "h2d_bytes": 100_000_000,
            },
        },
        {
            "repetition": 3,
            "t_prove_prefill_only_s": 11.0,
            "t_prove_decode_marginal_s": 5.0,
            "t_response_session_wall_s": 10.0,
            "p7b_sync_wall_fraction": 0.015,
            "accelerator_session": {
                "timing_method": "wall-only-counters",
                "phase_attribution_available": False,
                "timing_records": 0,
                "timing_elapsed_query_attempts": 0,
                "timing_elapsed_no_write": 0,
                "timing_event_queries": 0,
                "timing_event_api_calls": 0,
                "resident_h2d_host_calls": 100,
                "resident_d2h_host_calls": 4_500,
                "resident_h2d_host_call_s": 0.01,
                "resident_d2h_host_call_s": 0.02,
                "synchronizations": 59_868,
                "synchronization_s": 0.15,
                "h2d_bytes": 95_000_000,
            },
        },
    ]
    p7b = {
        "_mtime": 2.0,
        "_path": "benchmarks/results/p7b-current.json",
        "report_schema_version": 6,
        "milestone": "P7b-integrated-resident",
        "git_sha": sha,
        "git_sha_before_benchmark": sha,
        "git_sha_before_serialization": sha,
        "git_dirty": False,
        "git_dirty_before_benchmark": False,
        "git_dirty_before_serialization": False,
        "accepted": True,
        "accelerator_backend": "cuda-resident",
        "accelerator_cuda_abi_version": 28,
        "resident_timing_policy": "wall-only-counters",
        "p7b_gate_profile": "runpod-a100-v1",
        "threads": 8,
        "cloud": {
            "provider": "RunPod",
            "instance_id": "instance",
            "region": "eur-is-1",
            "image": "Ubuntu 24.04.3 LTS",
            "driver_version": "580.159.04",
            "cuda_version": "12.8",
            "gpu_sku": "NVIDIA A100-SXM4-80GB",
            "cpu_model": "AMD EPYC 7713 64-Core Processor",
            "ram_gib": "1008",
            "vcpus": "255",
        },
        "accelerator_live_device_bytes_after_cleanup": 30,
        "accelerator_workspace_device_bytes_after_cleanup": 10,
        "accelerator_resident_device_bytes_after_cleanup": 0,
        "accelerator_cached_resident_device_bytes_after_cleanup": 20,
        "accelerator_live_device_bytes_after_cache_trim": 10,
        "accelerator_workspace_device_bytes_after_cache_trim": 10,
        "accelerator_resident_device_bytes_after_cache_trim": 0,
        "accelerator_cached_resident_device_bytes_after_cache_trim": 0,
        "benchmark_warmup_repetitions": 1,
        "benchmark_repetitions": 3,
        "repetitions": repetitions,
        "t_prefill": 100,
        "n_decode": 50,
        "pcs_n_queries": 200,
        "golden_decode_checked": True,
        "golden_decode_match": True,
        "curve_last_over_first": 1.1,
        "gate_flat_cost_per_token": True,
        "prove_prefill_timing": {"samples_s": [9.0, 10.0, 11.0], "median_s": 10.0},
        "prove_decode_marginal_timing": {
            "samples_s": [3.0, 4.0, 5.0],
            "median_s": 4.0,
        },
        "p7b_machine_eligible": True,
        "p7b_gate_evaluated": True,
        "p7b_timing_statistic": "upper median across measured repetitions",
        "p7b_counter_statistic": "maximum across measured sessions",
        "p7b_prefill_core_gate_s": 10.0,
        "p7b_decode_marginal_gate_s": 4.0,
        "p7b_sync_count_gate_retired": True,
        "p7b_sync_wall_fraction_gate": 0.02,
        "p7b_h2d_gate_bytes": 100_000_000,
        "p7b_prefill_core_observed_s": 10.0,
        "p7b_decode_marginal_observed_s": 4.0,
        "p7b_sync_observed": 59_868,
        "p7b_sync_wall_fraction_observed": 0.02,
        "p7b_h2d_observed_bytes": 100_000_000,
        "p7b_prefill_core_gate_pass": True,
        "p7b_decode_marginal_gate_pass": True,
        "p7b_sync_wall_fraction_gate_pass": True,
        "p7b_h2d_gate_pass": True,
        "response_communication_envelope_bytes": 200_000_000,
        "response_communication_observed_bytes": 144_820_930,
        "response_communication_invariant_pass": True,
        "p7b_transcript_reference_bytes": 137_413_808,
        "p7b_pcs_opening_reference_bytes": 66_733_504,
        "p7b_packed_logits_reference_bytes": 7_407_122,
        "p7b_packed_response_reference_bytes": 144_820_930,
        "p7b_response_communication_no_growth_pass": True,
        "p7b_all_gates_pass": True,
        "comm_response_bytes": 137_413_808,
        "pcs_opening_bytes_total": 66_733_504,
        "public_logits_packed_bytes": 7_407_122,
        "total_response_download_packed_bytes": 144_820_930,
        "pcg_backend": "mock",
        "pcg_production_ready": False,
    }

    p7_rows = report.integrated_resident_profiles([historical, p7b])
    assert [row["source"] for row in p7_rows] == [historical["_path"]]
    assert report.resident_run_of_record_eligible(p7_rows[0]) is True

    p7b_rows = report.integrated_p7b_resident_profiles([historical, p7b])
    assert [row["source"] for row in p7b_rows] == [p7b["_path"]]
    official = p7b_rows[0]
    assert report.p7b_resident_run_of_record_eligible(official) is True
    raw_path = tmp_path / "p7b-official.json"
    raw_path.write_text(json.dumps(p7b))
    assert report.validate_p7b_official_result(raw_path) is True

    fase_d = copy.deepcopy(p7b)
    fase_d.update(
        {
            "report_schema_version": 7,
            "milestone": "fase-D-G4",
            "p7b_gate_profile": "runpod-a100-realpcg-v1",
            "chunked_accepted": True,
            "comm_response_bytes": 129_119_408,
            "response_communication_observed_bytes": 136_526_530,
            "p7b_transcript_reference_bytes": 129_119_408,
            "p7b_packed_response_reference_bytes": 136_526_530,
            "total_response_download_packed_bytes": 136_526_530,
            "pcg_backend": "real",
            "ggm_prg": "aes128-mmo",
            "pcg_production_ready": True,
            "fase_d_g1_pass": True,
            "pcg_mock_prepass_counters_match": True,
            "pcg_mock_prepass_channel_ledger_digest_match": True,
            "pcg_mock_prepass_allocation_digest_match": True,
            "pcg_allocation_hash_match": True,
            "n_weight_claims": 96,
            "n_embed_claims": 6,
            "pcs_commitments": [{"verified": True} for _ in range(13)],
            "fase_d_setup": {
                "ggm_prg": "aes128-mmo",
                "pcg_production_ready": True,
                "one_connection_base_phase": True,
                "g2_capacity_gate_pass": True,
                "g2_traffic_gate_pass": True,
                "comm": {"total_bytes": 38_000_000},
                "capacity": {"allocatable_stage3": 110_918_718},
            },
            "fase_d_lifecycle": {
                "completed_responses": 5,
                "responses_after_first_repeat_base_ot_bytes": 0,
                "responses_after_first_repeat_ot_extension_bytes": 0,
            },
        }
    )
    fase_d_path = tmp_path / "fase-d-pod-official.json"
    fase_d_path.write_text(json.dumps(fase_d))
    assert report.validate_fase_d_pod_official_result(fase_d_path) is True

    fase_d_v2 = copy.deepcopy(fase_d)
    fase_d_v2["p7b_gate_profile"] = "runpod-a100-realpcg-v2"
    fase_d_v2.pop("p7b_sync_wall_fraction_gate", None)
    fase_d_v2.pop("p7b_sync_wall_fraction_gate_pass", None)
    fase_d_v2["repetitions"][1]["accelerator_session"]["synchronization_s"] = 0.15
    fase_d_v2["repetitions"][1]["p7b_sync_wall_fraction"] = 0.015
    fase_d_v2["p7b_sync_wall_fraction_observed"] = 0.015
    sync_walls = [
        repetition["accelerator_session"]["synchronization_s"]
        for repetition in fase_d_v2["repetitions"]
    ]
    fase_d_v2["p7b_sync_wall_absolute_gate_s"] = 0.150
    fase_d_v2["p7b_sync_wall_absolute_observed_s"] = max(sync_walls)
    fase_d_v2["p7b_sync_wall_absolute_gate_pass"] = True
    fase_d_v2["p7b_all_gates_pass"] = True
    fase_d_v2_path = tmp_path / "fase-d-pod-v2-official.json"
    fase_d_v2_path.write_text(json.dumps(fase_d_v2))
    assert report.validate_fase_d_pod_official_result(fase_d_v2_path) is True

    c3b_pod = copy.deepcopy(fase_d_v2)
    c3b_baseline_samples = [4.896_894_977, 4.911_634, 4.935_140_317]
    c3b_candidate_samples = [4.8, 4.9, 5.0]
    c3b_baseline = 4.911_634
    c3b_candidate = 4.9
    c3b_delta = c3b_candidate - c3b_baseline
    c3b_pod.update(
        {
            "report_schema_version": 9,
            "milestone": "C3b",
            "p7b_gate_profile": "runpod-a100-realpcg-v3",
            "pcs_n_queries": 120,
            "pcs_commitments": [{"verified": True}, {"verified": True}],
            "comm_response_bytes": 105_717_632,
            "comm_response_by_label": {"protocol": 62_443_744, "pcs": 43_273_888},
            "comm_pcs_by_label": {"weights": 37_405_088, "embed": 5_868_800},
            "pcs_opening_bytes_total": 43_273_888,
            "public_logits_bytes": 0,
            "public_logits_packed_bytes": 0,
            "total_response_download_bytes": 105_717_632,
            "total_response_download_packed_bytes": 105_717_632,
            "response_communication_observed_bytes": 105_717_632,
            "p7b_transcript_reference_bytes": 105_717_632,
            "p7b_pcs_opening_reference_bytes": 43_273_888,
            "p7b_packed_logits_reference_bytes": 0,
            "p7b_packed_response_reference_bytes": 105_717_632,
            "c3_packed_response_gate_bytes": 115_000_000,
            "c3b_l4_transcript_bytes": 57_840,
            "c3b_transcript_reference_bytes": 105_717_632,
            "c3b_limb_count": 3,
            "c3b_range_instances": 6,
            "c3b_real_comparisons": 2_512_850,
            "c3b_packed_entries_per_limb": 2_621_440,
            "c3b_packed_entries_total": 7_864_320,
            "c3b_padding_ratio": 2_621_440 / 2_512_850,
            "c3b_l4_emult_instances": 157_705_530.0,
            "c3b_l4_emult_ceiling": 260_000_000.0,
            "c3b_l4_emult_gate_pass": True,
            "emult_instances_total": 2_775_723_398.8,
            "c3b_exact_instance_counter_pass": True,
            "c3b_transcript_category_sum_pass": True,
            "c3b_pcs_category_sum_pass": True,
            "c3b_public_logits_disabled": True,
            "c3b_g1_pass": None,
            "c3b_g4_pass": True,
            "c3b_g2": {
                "timing_policy": (
                    "wall-only+counters; upper median candidate; pinned same-host control"
                ),
                "baseline_source": (
                    "c3b-l4-ablation-diagnostic-2026-07-18-5a2edbe.json; "
                    "pinned rounded median"
                ),
                "baseline_prove_response": {
                    "samples_s": c3b_baseline_samples,
                    "median_s": c3b_baseline,
                },
                "candidate_prove_response": {
                    "samples_s": c3b_candidate_samples,
                    "median_s": c3b_candidate,
                },
                "baseline_s": c3b_baseline,
                "candidate_s": c3b_candidate,
                "delta_s": c3b_delta,
                "delta_percent": c3b_delta / c3b_baseline * 100.0,
                "gate_percent": 15.0,
                "ceiling_s": 5.648_379_1,
                "pass": True,
            },
            "pcg_setup_comm_bytes": 38_000_000,
            "pcg_setup_instances": 1,
            "pcg_setup_wire_count_invariant_pass": True,
            "pcg_response_authorization_burned_before_setup": True,
            "pcg_burn_on_success_or_abort": True,
            "pcg_reconnect_retry_resume_allowed": False,
        }
    )
    c3b_pod["fase_d_setup"].update(
        {
            "correlation_storage": (
                "unlinked-0600-file; connection-scoped; range-read only; "
                "page-cache discarded"
            ),
            "correlation_spool_entries": 110_000_000,
            "correlation_spool_bytes": 4_400_000_000,
            "correlation_spool_chunk_entries": 1 << 16,
            "correlation_spool_resident_raw_entries": 0,
            "correlation_spool_write_wall_s": 1.0,
            "correlation_spool_digest": "a" * 64,
        }
    )
    c3b_pod["fase_d_lifecycle"].update(
        {
            "response_base_ot_bytes": [1024, 0, 0, 0, 0],
            "response_ot_extension_bytes": [2048, 0, 0, 0, 0],
        }
    )
    c3b_pod_path = tmp_path / "c3b-pod-official.json"
    c3b_pod_path.write_text(json.dumps(c3b_pod))
    assert report.validate_c3b_official_result(c3b_pod_path) is True

    c3b_fresh_host = copy.deepcopy(c3b_pod)
    c3b_fresh_host["cloud"].update(
        {
            "region": "provider-recorded-new-region",
            "driver_version": "580.126.16",
            "cpu_model": "AMD EPYC 7742 64-Core Processor",
            "ram_gib": "2004",
            "vcpus": "128",
        }
    )
    c3b_fresh_host_path = tmp_path / "c3b-fresh-host-official.json"
    c3b_fresh_host_path.write_text(json.dumps(c3b_fresh_host))
    assert report.validate_c3b_official_result(c3b_fresh_host_path) is True

    bad_c3b_denominator = copy.deepcopy(c3b_pod)
    bad_c3b_denominator["c3b_g2"]["baseline_s"] += 0.000_001
    bad_c3b_denominator_path = tmp_path / "c3b-bad-denominator.json"
    bad_c3b_denominator_path.write_text(json.dumps(bad_c3b_denominator))
    assert report.validate_c3b_official_result(bad_c3b_denominator_path) is False

    c3b_cpu = copy.deepcopy(c3b_pod)
    cpu_baseline_samples = [10.0, 10.1, 10.2, 10.3, 10.4, 10.5]
    cpu_candidate_samples = [11.0, 11.1, 11.2, 11.3, 11.4, 11.5]
    cpu_baseline = 10.3
    cpu_candidate = 11.3
    cpu_delta = cpu_candidate - cpu_baseline
    c3b_cpu.update(
        {
            "accelerator_backend": "cpu",
            "threads": 4,
            "c3b_g1_pass": True,
            "c3b_g4_pass": None,
            "c3b_g2": {
                "timing_policy": (
                    "same-process ABBA; one paired warmup + three rounds; "
                    "protocol-core prove wall"
                ),
                "baseline_source": (
                    "unchanged fase-D Q=200 public-logit response arm in this record"
                ),
                "baseline_prove_response": {
                    "samples_s": cpu_baseline_samples,
                    "median_s": cpu_baseline,
                },
                "candidate_prove_response": {
                    "samples_s": cpu_candidate_samples,
                    "median_s": cpu_candidate,
                },
                "baseline_s": cpu_baseline,
                "candidate_s": cpu_candidate,
                "delta_s": cpu_delta,
                "delta_percent": cpu_delta / cpu_baseline * 100.0,
                "gate_percent": 15.0,
                "ceiling_s": cpu_baseline * 1.15,
                "pass": True,
            },
        }
    )
    c3b_cpu_path = tmp_path / "c3b-cpu-official.json"
    c3b_cpu_path.write_text(json.dumps(c3b_cpu))
    assert report.validate_c3b_official_result(c3b_cpu_path) is True

    t1_pod = copy.deepcopy(c3b_pod)
    t1_pod.update(
        {
            "report_schema_version": 10,
            "milestone": "T1-G4",
            "p7b_gate_profile": "runpod-a100-realpcg-v4",
            "comm_response_bytes": 84_544_352,
            "comm_response_by_label": {
                "auth_corrections": 38_348_720,
                "t1_eq_round_corrections": 22_176,
                "t1_eq_terminal_correction": 672,
                "t1_q_bridge_correction": 672,
                "pcs": 43_273_888,
                "other": 2_898_224,
            },
            "comm_pcs_by_label": {"weights": 37_405_088, "embed": 5_868_800},
            "pcs_opening_bytes_total": 43_273_888,
            "total_response_download_bytes": 84_544_352,
            "total_response_download_packed_bytes": 84_544_352,
            "response_communication_observed_bytes": 84_544_352,
            "p7b_transcript_reference_bytes": 84_544_352,
            "p7b_pcs_opening_reference_bytes": 43_273_888,
            "p7b_packed_logits_reference_bytes": 0,
            "p7b_packed_response_reference_bytes": 84_544_352,
            "t1_response_gate_bytes": 85_000_000,
            "t1_response_reference_bytes": 84_544_352,
            "t1_auth_correction_gate_bytes": 38_348_720,
            "t1_auth_correction_reference_bytes": 38_348_720,
            "t1_eq_reducer_transcript_bytes": 22_848,
            "t1_q_bridge_correction_bytes": 672,
            "closure_prod_claims": 21_667,
            "closure_zero_claims": 8_170,
            "corr_sub_corrs": 4_793_590,
            "corr_full_corrs": 181_933,
            "emult_instances_total": 2_800_595_736.8,
            "t1_emult_other_total": 114_852_961.2,
            "t1_exact_counter_pass": True,
            "t1_g1_pass": None,
            "t1_g2": None,
            "t1_g3_pass": True,
            "t1_g4_pass": True,
        }
    )
    t1_pod_path = tmp_path / "t1-pod-official.json"
    t1_pod_path.write_text(json.dumps(t1_pod))
    assert report.validate_t1_official_result(t1_pod_path) is True

    t1_cpu = copy.deepcopy(t1_pod)
    t1_baseline_samples = [10.0, 10.1, 10.2, 10.3, 10.4, 10.5]
    t1_candidate_samples = [10.3, 10.4, 10.5, 10.6, 10.7, 10.8]
    t1_baseline = 10.3
    t1_candidate = 10.6
    t1_delta = t1_candidate - t1_baseline
    t1_cpu.update(
        {
            "milestone": "T1-G1",
            "accelerator_backend": "cpu",
            "threads": 4,
            "t1_g1_pass": True,
            "t1_g4_pass": None,
            "t1_g2": {
                "timing_policy": (
                    "same-process ABBA; one paired warmup + three rounds; "
                    "protocol-core prove wall"
                ),
                "baseline_source": (
                    "frozen C3b boundary-authentication control arm in this binary"
                ),
                "baseline_prove_response": {
                    "samples_s": t1_baseline_samples,
                    "median_s": t1_baseline,
                },
                "candidate_prove_response": {
                    "samples_s": t1_candidate_samples,
                    "median_s": t1_candidate,
                },
                "baseline_s": t1_baseline,
                "candidate_s": t1_candidate,
                "delta_s": t1_delta,
                "delta_percent": t1_delta / t1_baseline * 100.0,
                "gate_percent": 5.0,
                "ceiling_s": t1_baseline * 1.05,
                "pass": True,
            },
        }
    )
    t1_cpu_path = tmp_path / "t1-cpu-official.json"
    t1_cpu_path.write_text(json.dumps(t1_cpu))
    assert report.validate_t1_official_result(t1_cpu_path) is True

    bad_t1_auth = copy.deepcopy(t1_cpu)
    bad_t1_auth["t1_auth_correction_reference_bytes"] += 8
    bad_t1_auth_path = tmp_path / "t1-bad-auth.json"
    bad_t1_auth_path.write_text(json.dumps(bad_t1_auth))
    assert report.validate_t1_official_result(bad_t1_auth_path) is False

    def c4_record(profile: str):
        row = copy.deepcopy(t1_pod)
        is_rate8 = profile == "rate8"
        pcs_weights = 32_831_444 if is_rate8 else 37_405_088
        pcs_embed = 5_464_596 if is_rate8 else 5_868_800
        pcs_bytes = pcs_weights + pcs_embed
        response_bytes = 41_270_464 + pcs_bytes
        fixed_non_pcs = 38_348_720 + 22_176 + 672 + 672
        row.update(
            {
                "report_schema_version": 11,
                "milestone": f"C4-G4-{profile}",
                "accelerator_cuda_abi_version": 33,
                "p7b_gate_profile": "runpod-a100-c4-v1",
                "pcs_n_queries": 97 if is_rate8 else 120,
                "comm_response_bytes": response_bytes,
                "comm_response_by_label": {
                    "auth_corrections": 38_348_720,
                    "t1_eq_round_corrections": 22_176,
                    "t1_eq_terminal_correction": 672,
                    "t1_q_bridge_correction": 672,
                    "other": 41_270_464 - fixed_non_pcs,
                    "weights": pcs_weights,
                    "embed": pcs_embed,
                },
                "comm_pcs_by_label": {
                    "weights": pcs_weights,
                    "embed": pcs_embed,
                },
                "pcs_opening_bytes_total": pcs_bytes,
                "total_response_download_bytes": response_bytes,
                "total_response_download_packed_bytes": response_bytes,
                "response_communication_observed_bytes": response_bytes,
                "p7b_transcript_reference_bytes": response_bytes,
                "p7b_pcs_opening_reference_bytes": pcs_bytes,
                "p7b_packed_response_reference_bytes": response_bytes,
                "prove_response_timing": {
                    "samples_s": [4.0, 4.1, 4.2],
                    "median_s": 4.1,
                },
                "response_session_wall_timing": {
                    "samples_s": [5.0, 5.1, 5.2],
                    "median_s": 5.1,
                },
            }
        )
        for repetition in row["repetitions"]:
            repetition["accelerator_session"]["peak_device_bytes"] = 20_000_000_000
        peak = max(
            repetition["accelerator_session"]["peak_device_bytes"]
            for repetition in row["repetitions"]
        )
        row["c4"] = {
            "profile": profile,
            "design_file": "docs/c4-ligero-inline-rate-design.md",
            "design_sha256": (
                "a475379f9a690b76864e98a9a3e7bf60e46c2315bc5c95a347a58e0af41b3b3a"
            ),
            "resource_admission": {
                "selected_gpu": "0",
                "gpu_free_bytes": 60_000_000_000,
                "gpu_free_floor_bytes": 40_000_000_000,
                "host_ram_bytes": 128 * 1024 * 1024 * 1024,
                "host_ram_floor_bytes": 64 * 1024 * 1024 * 1024,
                "local_storage_path": "/local/volta-zk",
                "local_storage_fs_type": "xfs",
                "local_storage_mount_source": "/dev/nvme0n1p1",
                "local_storage_mount_fs_type": "xfs",
                "local_storage_mount_options": "rw,relatime",
                "local_storage_free_bytes": 100_000_000_000,
                "local_storage_floor_bytes": 80_000_000_000,
                "detected_logical_cpus": 32,
                "logical_cpu_floor": 16,
                "rayon_workers": 8,
                "non_fuse_local_storage": True,
                "container_overlay_local_backing_evidence": False,
                "overall_pass": True,
            },
            "weights": report.C4_GEOMETRY[profile]["weights"],
            "embed": report.C4_GEOMETRY[profile]["embed"],
            "non_pcs_transcript_bytes": 41_270_464,
            "expected_pcs_bytes": pcs_bytes,
            "observed_pcs_bytes": pcs_bytes,
            "expected_response_bytes": response_bytes,
            "observed_response_bytes": response_bytes,
            "response_saving_from_anchor_bytes": 4_977_848 if is_rate8 else 0,
            "setup_bytes": 38_371_465,
            "first_exchange_bytes": 117_937_969 if is_rate8 else 122_915_817,
            "encoded_codeword_bytes": 17_246_978_048 if is_rate8 else 8_623_489_024,
            "device_live_gate_bytes": 40_000_000_000,
            "observed_peak_device_bytes": peak,
            "device_live_gate_pass": peak < 40_000_000_000,
            "soundness_floor_bits": 78.809_294_873_916_41,
            "observed_soundness_bits": (
                78.866_516_496_748_67 if is_rate8 else 78.809_294_873_916_41
            ),
            "soundness_gate_pass": True,
            "exact_communication_pass": True,
            "inherited_t1_surface_pass": True,
            "performance_pair_evaluated": False,
            "gate_verdict": False,
        }
        return row

    c4_anchor = c4_record("anchor")
    c4_candidate = c4_record("rate8")
    c4_anchor["fase_d_lifecycle"]["channel_ledger_digest"] = "a" * 64
    c4_candidate["fase_d_lifecycle"]["channel_ledger_digest"] = "b" * 64
    c4_anchor_path = tmp_path / "c4-anchor.json"
    c4_candidate_path = tmp_path / "c4-rate8.json"
    c4_anchor_path.write_text(json.dumps(c4_anchor))
    c4_candidate_path.write_text(json.dumps(c4_candidate))
    assert report.validate_c4_official_result(c4_anchor_path) is True
    assert report.validate_c4_official_result(c4_candidate_path) is True
    c4_pair = report.c4_paired_verdict(c4_anchor_path, c4_candidate_path)
    assert c4_pair is not None
    assert c4_pair["overall_pass"] is True
    assert c4_pair["communication_saving_bytes"] == 4_977_848
    c4_pair_path = tmp_path / "c4-pair.json"
    assert (
        report.write_c4_paired_verdict(
            c4_anchor_path, c4_candidate_path, c4_pair_path
        )
        == c4_pair_path
    )
    assert json.loads(c4_pair_path.read_text())["overall_pass"] is True
    assert (
        report.write_c4_paired_verdict(
            c4_anchor_path, c4_candidate_path, c4_pair_path
        )
        is None
    )

    c4_mutations = [
        ("c4", "profile", "anchor"),
        ("c4", "expected_pcs_bytes", 38_296_041),
        ("c4", "soundness_gate_pass", False),
        ("c4", "device_live_gate_pass", False),
    ]
    for index, (section, key, value) in enumerate(c4_mutations):
        bad = copy.deepcopy(c4_candidate)
        bad[section][key] = value
        path = tmp_path / f"c4-bad-{index}.json"
        path.write_text(json.dumps(bad))
        assert report.validate_c4_official_result(path) is False

    bad_c4_resource = copy.deepcopy(c4_candidate)
    bad_c4_resource["c4"]["resource_admission"]["local_storage_free_bytes"] = 79_999_999_999
    bad_c4_resource_path = tmp_path / "c4-bad-resource.json"
    bad_c4_resource_path.write_text(json.dumps(bad_c4_resource))
    assert report.validate_c4_official_result(bad_c4_resource_path) is False

    c4_overlay = copy.deepcopy(c4_candidate)
    overlay_resource = c4_overlay["c4"]["resource_admission"]
    overlay_resource.update(
        {
            "local_storage_path": "/root/volta-zk",
            "local_storage_fs_type": "overlayfs",
            "local_storage_mount_source": "overlay",
            "local_storage_mount_fs_type": "overlay",
            "local_storage_mount_options": (
                "rw,relatime,"
                "upperdir=/var/lib/docker/100000.100000/overlay2/abc/diff,"
                "workdir=/var/lib/docker/100000.100000/overlay2/abc/work"
            ),
            "container_overlay_local_backing_evidence": True,
        }
    )
    c4_overlay_path = tmp_path / "c4-overlay.json"
    c4_overlay_path.write_text(json.dumps(c4_overlay))
    assert report.validate_c4_official_result(c4_overlay_path) is True

    bad_c4_overlay = copy.deepcopy(c4_overlay)
    bad_c4_overlay["c4"]["resource_admission"]["local_storage_mount_options"] = (
        "rw,relatime,upperdir=/tmp/diff,workdir=/tmp/work"
    )
    bad_c4_overlay_path = tmp_path / "c4-bad-overlay.json"
    bad_c4_overlay_path.write_text(json.dumps(bad_c4_overlay))
    assert report.validate_c4_official_result(bad_c4_overlay_path) is False

    mismatched_pair = copy.deepcopy(c4_candidate)
    mismatched_pair["git_sha"] = "f" * 40
    mismatched_pair["git_sha_before_benchmark"] = "f" * 40
    mismatched_pair["git_sha_before_serialization"] = "f" * 40
    mismatched_path = tmp_path / "c4-mismatched-pair.json"
    mismatched_path.write_text(json.dumps(mismatched_pair))
    assert report.c4_paired_verdict(c4_anchor_path, mismatched_path) is None

    mismatched_gpu = copy.deepcopy(c4_candidate)
    mismatched_gpu["c4"]["resource_admission"]["selected_gpu"] = "1"
    mismatched_gpu_path = tmp_path / "c4-mismatched-gpu.json"
    mismatched_gpu_path.write_text(json.dumps(mismatched_gpu))
    assert report.validate_c4_official_result(mismatched_gpu_path) is True
    assert report.c4_paired_verdict(c4_anchor_path, mismatched_gpu_path) is None

    failed_anchor = copy.deepcopy(c4_anchor)
    failed_anchor["repetitions"][1]["accelerator_session"]["synchronization_s"] = 0.151
    failed_anchor["repetitions"][1]["p7b_sync_wall_fraction"] = 0.0151
    failed_anchor["p7b_sync_wall_fraction_observed"] = 0.0151
    failed_anchor["p7b_sync_wall_absolute_observed_s"] = 0.151
    failed_anchor["p7b_sync_wall_absolute_gate_pass"] = False
    failed_anchor["p7b_all_gates_pass"] = False
    failed_anchor_path = tmp_path / "c4-failed-anchor.json"
    failed_anchor_path.write_text(json.dumps(failed_anchor))
    assert report.validate_c4_official_result(failed_anchor_path) is True
    assert report.c4_paired_verdict(failed_anchor_path, c4_candidate_path) is None

    fase_d_v2["p7b_sync_wall_absolute_gate_s"] = 0.151
    fase_d_v2_path.write_text(json.dumps(fase_d_v2))
    assert report.validate_fase_d_pod_official_result(fase_d_v2_path) is False

    fase_d["fase_d_setup"]["comm"]["total_bytes"] = 40_000_001
    fase_d_path.write_text(json.dumps(fase_d))
    assert report.validate_fase_d_pod_official_result(fase_d_path) is False

    # A performance failure is still a valid measured verdict when its
    # observations, statistics and booleans close exactly.
    valid_failure = copy.deepcopy(official)
    valid_failure["repetitions"][1]["accelerator_session"]["synchronization_s"] = 0.21
    valid_failure["repetitions"][1]["p7b_sync_wall_fraction"] = 0.021
    valid_failure["p7b_sync_wall_fraction_observed"] = 0.021
    valid_failure["p7b_sync_wall_fraction_gate_pass"] = False
    valid_failure["p7b_all_gates_pass"] = False
    assert report.p7b_resident_run_of_record_eligible(valid_failure) is True

    # Every official field is fail-closed. This includes the clean A -> clean
    # B revision-swap case, which dirty-bit-only provenance cannot detect.
    mutations = [
        {"report_schema_version": 7},
        {"report_schema_version": 6.0},
        {"accelerator_cuda_abi_version": 25},
        {"accelerator_cuda_abi_version": 28.0},
        {"resident_timing_policy": "deferred-events"},
        {"p7b_gate_profile": "thunder-v0"},
        {"threads": 27},
        {"git_sha_before_serialization": "b" * 40},
        {"git_sha_before_benchmark": ""},
        {"git_sha": "b" * 40},
        {"p7b_gate_evaluated": False},
        {"pcs_n_queries": 199},
        {"pcs_n_queries": 200.0},
        {"golden_decode_match": False},
        {"flat_cost_gate": False},
        {"p7b_timing_statistic": "median"},
        {"p7b_counter_statistic": "median"},
        {"benchmark_warmup_repetitions": 0},
        {"benchmark_warmup_repetitions": None},
        {"benchmark_repetitions": 2},
        {"p7b_prefill_core_gate_s": 10.1},
        {"p7b_sync_count_gate_retired": False},
        {"p7b_sync_wall_fraction_gate": 0.03},
        {"response_communication_envelope_bytes": 200_000_001},
        {"p7b_response_communication_no_growth_pass": False},
        {"p7b_sync_wall_fraction_gate_pass": False},
        {"p7b_all_gates_pass": None},
        {"accelerator_cleanup_memory_accounting_ok": False},
    ]
    for mutation in mutations:
        candidate = dict(official)
        candidate.update(mutation)
        assert report.p7b_resident_run_of_record_eligible(candidate) is False, mutation

    bad_samples = copy.deepcopy(official)
    bad_samples["prove_prefill_timing"]["median_s"] = 9.0
    assert report.p7b_resident_run_of_record_eligible(bad_samples) is False

    bad_counter = copy.deepcopy(official)
    bad_counter["repetitions"][0]["accelerator_session"]["h2d_bytes"] = 100_000_001
    assert report.p7b_resident_run_of_record_eligible(bad_counter) is False

    bad_sync_fraction = copy.deepcopy(official)
    bad_sync_fraction["repetitions"][0]["p7b_sync_wall_fraction"] = 0.011
    assert report.p7b_resident_run_of_record_eligible(bad_sync_fraction) is False

    bad_timing_phase = copy.deepcopy(official)
    bad_timing_phase["repetitions"][0]["accelerator_session"][
        "phase_attribution_available"
    ] = True
    assert report.p7b_resident_run_of_record_eligible(bad_timing_phase) is False

    bad_timing_call = copy.deepcopy(official)
    bad_timing_call["repetitions"][0]["accelerator_session"]["timing_event_api_calls"] = 1
    assert report.p7b_resident_run_of_record_eligible(bad_timing_call) is False

    missing_host_call_timing = copy.deepcopy(official)
    del missing_host_call_timing["repetitions"][0]["accelerator_session"][
        "resident_d2h_host_call_s"
    ]
    assert report.p7b_resident_run_of_record_eligible(missing_host_call_timing) is False

    bad_communication = copy.deepcopy(official)
    bad_communication["communication"]["response_bytes"] += 1
    assert report.p7b_resident_run_of_record_eligible(bad_communication) is False

    # Defense in depth: even a schema-6 P7b row with the old milestone cannot
    # silently supersede the immutable schema-3 P7 result.
    mislabeled = dict(p7b, milestone="P7-integrated-resident")
    mislabeled_rows = report.integrated_resident_profiles([historical, mislabeled])
    assert report.resident_run_of_record_eligible(mislabeled_rows[-1]) is False
