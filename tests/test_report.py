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
    assert data["baseline"]["source"].endswith("p6-2026-07-07-382bb56.json")
    assert data["baseline"]["cloud"] is None
    assert data["communication"]["packed_logits_source"].endswith("p6-2026-07-07-382bb56.json")
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
