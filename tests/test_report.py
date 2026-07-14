import copy
import importlib.util
from pathlib import Path


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
        assert row["base_vole"] in {"real", "setup-cost-model"}
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


def test_p7b_resident_profile_is_separate_and_cannot_replace_closed_p7():
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
                "synchronizations": 4_000,
                "h2d_bytes": 90_000_000,
            },
        },
        {
            "repetition": 2,
            "t_prove_prefill_only_s": 10.0,
            "t_prove_decode_marginal_s": 4.0,
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
                "synchronizations": 5_000,
                "h2d_bytes": 100_000_000,
            },
        },
        {
            "repetition": 3,
            "t_prove_prefill_only_s": 11.0,
            "t_prove_decode_marginal_s": 5.0,
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
                "synchronizations": 4_500,
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
        "cloud": {
            "provider": "Thunder Compute",
            "instance_id": "instance",
            "region": "not exposed",
            "image": "ubuntu",
            "driver_version": "610",
            "cuda_version": "13.2",
            "gpu_sku": "NVIDIA A100-SXM4-80GB",
            "cpu_model": "Xeon",
            "ram_gib": "64",
            "vcpus": "8",
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
        "p7b_sync_gate": 5_000,
        "p7b_h2d_gate_bytes": 100_000_000,
        "p7b_prefill_core_observed_s": 10.0,
        "p7b_decode_marginal_observed_s": 4.0,
        "p7b_sync_observed": 5_000,
        "p7b_h2d_observed_bytes": 100_000_000,
        "p7b_prefill_core_gate_pass": True,
        "p7b_decode_marginal_gate_pass": True,
        "p7b_sync_gate_pass": True,
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

    # A performance failure is still a valid measured verdict when its
    # observations, statistics and booleans close exactly.
    valid_failure = copy.deepcopy(official)
    valid_failure["repetitions"][1]["accelerator_session"]["synchronizations"] = 5_001
    valid_failure["p7b_sync_observed"] = 5_001
    valid_failure["p7b_sync_gate_pass"] = False
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
        {"response_communication_envelope_bytes": 200_000_001},
        {"p7b_response_communication_no_growth_pass": False},
        {"p7b_sync_gate_pass": False},
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
