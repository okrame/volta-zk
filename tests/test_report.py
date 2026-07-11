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
    assert data["cloud"] == data["baseline"]["cloud"]
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
    assert native["source"].endswith("p7-gpu-native-inference-2026-07-11-c06f323.json")
    assert native["correctness"] is True
    assert native["golden_match"] is True
    assert native["prefill_s"] == 0.017663136
    assert native["decode_50_s"] == 0.633894507
    assert native["native_gpu_speedup"]["prefill"] == 56.36387892840773
    assert native["native_gpu_speedup"]["decode"] == 2.728360443104455
    prover_targets = data["gpu_native_inference"]["required_prover_gpu_speedup_vs_cpu"]
    assert prover_targets["prefill"] == 115.61633928425845
    assert prover_targets["decode"] == 11.314079219493856
    assert data["gpu_native_inference"]["proof_only_budget"]["prefill_s"] == 0.17663136
    assert data["go_no_go"]["local_recommendation"] == (
        "proceed-to-integrated-gpu-prover-measurement"
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
