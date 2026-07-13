#!/usr/bin/env python3
"""P7 report and GPU/communication budget model.

This is intentionally a reporting layer over benchmark JSONs. It does not
change proving parameters, transcript layout, PCS openings, or soundness
assumptions. PCS alternatives are projections from the checked
`MultiOpenProof::bytes()` formula.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import math
import platform
import subprocess
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS = REPO / "benchmarks" / "results"
P7_RHO_TARGETS = {"prefill": 10.0, "decode": 2.0}

LAYER_PARAMS = {
    "rows": 1 << 10,
    "cols": 1 << 14,
    "pad": 512,
    "code_bits": 15,
    "n_queries": 200,
}
EMBED_PARAMS = {
    "rows": 1 << 13,
    "cols": 1 << 14,
    "pad": 512,
    "code_bits": 15,
    "n_queries": 200,
}


def git(args: list[str], default: str = "") -> str:
    try:
        out = subprocess.check_output(["git", *args], cwd=REPO, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return default
    return out.decode().strip()


def git_dirty() -> bool:
    try:
        out = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"],
            cwd=REPO,
            stderr=subprocess.DEVNULL,
        )
    except (OSError, subprocess.CalledProcessError):
        return True
    return bool(out)


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    data["_path"] = str(path.relative_to(REPO))
    data["_mtime"] = path.stat().st_mtime
    return data


def load_results(results_dir: Path) -> list[dict[str, Any]]:
    return [load_json(p) for p in sorted(results_dir.glob("*.json"))]


def p6_shape(data: dict[str, Any]) -> bool:
    return (
        data.get("milestone") == "P6"
        and data.get("accepted") is True
        and data.get("t_prefill") == 100
        and data.get("n_decode") == 50
    )


def select_p6_record(results: list[dict[str, Any]]) -> dict[str, Any]:
    clean = [r for r in results if p6_shape(r) and not r.get("git_dirty", True)]
    if clean:
        return max(clean, key=lambda r: r["_mtime"])
    dirty = [r for r in results if p6_shape(r)]
    if dirty:
        return max(dirty, key=lambda r: r["_mtime"])
    raise SystemExit("no accepted P6 result for prompt 100 + decode 50")


def select_packed_source(results: list[dict[str, Any]], baseline: dict[str, Any]) -> dict[str, Any] | None:
    same_shape = [
        r
        for r in results
        if p6_shape(r)
        and r.get("t_prefill") == baseline.get("t_prefill")
        and r.get("n_decode") == baseline.get("n_decode")
        and "public_logits_packed_bytes" in r
    ]
    return max(same_shape, key=lambda r: r["_mtime"]) if same_shape else None


def msg_len(params: dict[str, int]) -> int:
    return params["cols"] + params["pad"]


def rate(params: dict[str, int]) -> float:
    return msg_len(params) / float(1 << params["code_bits"])


def distance(params: dict[str, int]) -> float:
    return 1.0 - rate(params)


def query_error_bits(params: dict[str, int]) -> float:
    base = 1.0 - distance(params) / 2.0
    return -params["n_queries"] * math.log2(base)


def queries_for_bits(params: dict[str, int], bits: float) -> int:
    base = 1.0 - distance(params) / 2.0
    return math.ceil(bits / -math.log2(base))


def multi_open_breakdown(params: dict[str, int], n_claims: int) -> dict[str, int]:
    rows = params["rows"]
    code_bits = params["code_bits"]
    q = params["n_queries"]
    masks = n_claims + 1
    u_vectors = 16 * msg_len(params) * masks
    corr_ss = 16 * n_claims
    zero_batch = 32  # mask_corr + m_z
    column_indices = 4 * q
    data_columns = 8 * rows * q
    mask_columns = 16 * masks * q
    merkle_paths = 32 * (code_bits + code_bits) * q
    columns = column_indices + data_columns + mask_columns + merkle_paths
    total = 32 + u_vectors + corr_ss + zero_batch + columns
    cached_query_cut = data_columns + 32 * code_bits * q
    return {
        "mask_root": 32,
        "u_vectors": u_vectors,
        "corr_ss": corr_ss,
        "zero_batch": zero_batch,
        "column_indices": column_indices,
        "data_columns": data_columns,
        "mask_columns": mask_columns,
        "merkle_paths": merkle_paths,
        "columns_total": columns,
        "cached_query_cut_bytes": cached_query_cut,
        "total": total,
    }


def with_queries(params: dict[str, int], n_queries: int) -> dict[str, int]:
    out = dict(params)
    out["n_queries"] = n_queries
    return out


def embed_pow2_shape(rows: int) -> dict[str, int]:
    total = 1 << 27
    assert total % rows == 0
    cols = total // rows
    msg = cols + EMBED_PARAMS["pad"]
    return {
        "rows": rows,
        "cols": cols,
        "pad": EMBED_PARAMS["pad"],
        "code_bits": (msg - 1).bit_length(),
        "n_queries": EMBED_PARAMS["n_queries"],
    }


def pcs_total(layer_params: dict[str, int], layer_claims: int, embed_params: dict[str, int], embed_claims: int) -> int:
    return (
        12 * multi_open_breakdown(layer_params, layer_claims)["total"]
        + multi_open_breakdown(embed_params, embed_claims)["total"]
    )


def pcs_cached_total(
    layer_params: dict[str, int],
    layer_claims: int,
    embed_params: dict[str, int],
    embed_claims: int,
) -> int:
    layer = multi_open_breakdown(layer_params, layer_claims)
    embed = multi_open_breakdown(embed_params, embed_claims)
    return 12 * (layer["total"] - layer["cached_query_cut_bytes"]) + (
        embed["total"] - embed["cached_query_cut_bytes"]
    )


def response_total(current_packed: int, current_pcs: int, new_pcs: int) -> int:
    return current_packed - current_pcs + new_pcs


def mb(x: float) -> float:
    return x / 1_000_000.0


def pcs_scenarios(baseline: dict[str, Any], current_packed_download: int) -> list[dict[str, Any]]:
    current_pcs = int(baseline["pcs_opening_bytes_total"])
    q60 = queries_for_bits(LAYER_PARAMS, 60.0)
    layer_q60 = with_queries(LAYER_PARAMS, q60)
    embed_q60 = with_queries(EMBED_PARAMS, q60)
    embed_4096 = embed_pow2_shape(1 << 12)

    rows = [
        (
            "current",
            "measured shape and claims",
            pcs_total(LAYER_PARAMS, 8, EMBED_PARAMS, 6),
            "implemented",
            None,
        ),
        (
            "q60_same_rate",
            f"projection only: Q={q60}, same rate/distance, >=60-bit query error",
            pcs_total(layer_q60, 8, embed_q60, 6),
            "soundness-decision-required",
            {"n_queries": q60, "error_bits": query_error_bits(layer_q60)},
        ),
        (
            "per_tensor_rlc",
            "projection only: layer claims 8->4, embed claims 6->3",
            pcs_total(LAYER_PARAMS, 4, EMBED_PARAMS, 3),
            "protocol-design-required",
            None,
        ),
        (
            "q60_plus_rlc",
            f"projection only: Q={q60} plus per-tensor RLC",
            pcs_total(layer_q60, 4, embed_q60, 3),
            "soundness-and-protocol-design-required",
            {"n_queries": q60, "error_bits": query_error_bits(layer_q60)},
        ),
        (
            "embed_4096_rows",
            "projection only: embed rows=2^12, cols=2^15, code_bits=16",
            pcs_total(LAYER_PARAMS, 8, embed_4096, 6),
            "layout-variant-required",
            {"embed_params": embed_4096, "embed_error_bits": query_error_bits(embed_4096)},
        ),
        (
            "static_query_cache_marginal",
            "projection only: verifier caches data columns and their Merkle paths after setup",
            pcs_cached_total(LAYER_PARAMS, 8, EMBED_PARAMS, 6),
            "stateful-verifier-design-required",
            None,
        ),
        (
            "static_query_cache_plus_rlc_marginal",
            "projection only: static query cache plus per-tensor RLC",
            pcs_cached_total(LAYER_PARAMS, 4, EMBED_PARAMS, 3),
            "stateful-verifier-and-protocol-design-required",
            None,
        ),
    ]

    out = []
    for name, note, pcs_bytes, status, extra in rows:
        row = {
            "name": name,
            "status": status,
            "note": note,
            "pcs_opening_bytes": pcs_bytes,
            "pcs_delta_bytes": pcs_bytes - current_pcs,
            "packed_response_download_bytes": response_total(current_packed_download, current_pcs, pcs_bytes),
        }
        if extra:
            row.update(extra)
        out.append(row)
    return out


def rho_model(baseline: dict[str, Any]) -> dict[str, Any]:
    rho_prefill = float(baseline["rho_prefill"])
    rho_decode = float(baseline["rho_decode"])
    relative = [1.0, 2.0, 2.5, 3.0, 5.0, 8.0, 10.0]
    return {
        "definition": "predicted_gpu_rho = cpu_rho / relative_prover_vs_native_gpu_speedup",
        "targets": P7_RHO_TARGETS,
        "required_relative_prover_vs_native_speedup": {
            phase: rho / P7_RHO_TARGETS[phase]
            for phase, rho in (("prefill", rho_prefill), ("decode", rho_decode))
        },
        "sensitivity": [
            {
                "relative_prover_vs_native_speedup": r,
                "rho_prefill": rho_prefill / r,
                "rho_decode": rho_decode / r,
                "prefill_target_met": rho_prefill / r <= P7_RHO_TARGETS["prefill"],
                "decode_target_met": rho_decode / r <= P7_RHO_TARGETS["decode"],
            }
            for r in relative
        ],
    }


def summarize_rhos(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    keys = [
        "rho_kernel_weighted_layer",
        "rho_blind_total",
        "rho",
        "rho_prefill",
        "rho_decode",
        "rho_cpu_prefill",
        "rho_cpu_decode",
    ]
    rows = []
    for r in results:
        vals = {k: r[k] for k in keys if k in r}
        if vals:
            rows.append(
                {
                    "source": r["_path"],
                    "milestone": r.get("milestone"),
                    "git_dirty": r.get("git_dirty"),
                    **vals,
                }
            )
    return rows


def measured_pcs_profiles(results: list[dict[str, Any]], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    rows_by_shape: dict[tuple[Any, Any, Any, Any], dict[str, Any]] = {}
    seen: set[str] = set()
    candidates = [baseline] + [
        r
        for r in results
        if r.get("accepted") is True
        and r.get("milestone")
        in {
            "P6",
            "P6-quick",
            "P7-integrated-hybrid",
            "P7-integrated-hybrid-quick",
            "P7-integrated-resident",
            "P7-integrated-resident-quick",
        }
        and "pcs_opening_bytes_total" in r
    ]
    for r in candidates:
        source = r["_path"]
        if source in seen:
            continue
        seen.add(source)
        n_queries = int(r.get("pcs_n_queries", 200))
        params = with_queries(LAYER_PARAMS, n_queries)
        packed = r.get("total_response_download_packed_bytes")
        if packed is None and "public_logits_packed_bytes" in r:
            packed = int(r["comm_response_bytes"]) + int(r["public_logits_packed_bytes"])
        row = {
            "_mtime": r["_mtime"],
            "source": source,
            "milestone": r.get("milestone"),
            "git_dirty": r.get("git_dirty"),
            "t_prefill": r.get("t_prefill"),
            "n_decode": r.get("n_decode"),
            "pcs_n_queries": n_queries,
            "pcs_query_error_bits": float(r.get("pcs_query_error_bits", query_error_bits(params))),
            "pcs_opening_bytes_total": int(r["pcs_opening_bytes_total"]),
            "pcs_cached_query_marginal_bytes_total": r.get("pcs_cached_query_marginal_bytes_total"),
            "comm_response_bytes": r.get("comm_response_bytes"),
            "total_response_download_packed_bytes": packed,
        }
        key = (row["milestone"], row["t_prefill"], row["n_decode"], row["pcs_n_queries"])
        prev = rows_by_shape.get(key)
        if prev is None or row["_mtime"] > prev["_mtime"]:
            rows_by_shape[key] = row
    rows = list(rows_by_shape.values())
    for row in rows:
        row.pop("_mtime", None)
    rows.sort(key=lambda x: (x["t_prefill"] or 0, x["n_decode"] or 0, x["pcs_n_queries"], x["source"]))
    return rows


def mock_pcg_lower_bounds(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") != "P7-mock-pcg-lower-bound":
            continue
        rows.append(
            {
                "source": r["_path"],
                "git_dirty": r.get("git_dirty"),
                "is_real_pcg": r.get("is_real_pcg"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "t_total_mock_expansion_s": r.get("t_total_mock_expansion_s"),
                "expanded_prover_bytes": r.get("expanded_prover_bytes"),
                "expanded_verifier_bytes": r.get("expanded_verifier_bytes"),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "note": r.get("note"),
            }
        )
    rows.sort(key=lambda x: x["source"])
    return rows


def real_pcg_phase_a(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") != "P7-real-pcg-phase-a":
            continue
        timings = r.get("phase_a_timings") or {}
        params = r.get("lpn_parameters") or {}
        rows.append(
            {
                "source": r["_path"],
                "git_dirty": r.get("git_dirty"),
                "is_real_pcg": r.get("is_real_pcg"),
                "base_vole": r.get("base_vole"),
                "setup_comm_bytes": r.get("setup_comm_bytes"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "sub_equiv_corrs": (r.get("corr_sub_corrs") or 0)
                + 2 * (r.get("corr_full_corrs") or 0),
                "t_total_real_expansion_s": r.get(
                    "t_total_real_expansion_s", timings.get("t_total_real_expansion_s")
                ),
                "t_setup_stub_s": timings.get("t_setup_stub_s"),
                "t_ggm_pprf_s": timings.get("t_ggm_pprf_s"),
                "t_lpn_expand_s": timings.get("t_lpn_expand_s"),
                "t_consistency_check_s": timings.get("t_consistency_check_s"),
                "sub_equiv_corrs_per_s_joint": r.get("sub_equiv_corrs_per_s_joint"),
                "expanded_prover_bytes": r.get("expanded_prover_bytes"),
                "expanded_verifier_bytes": r.get("expanded_verifier_bytes"),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "lpn_parameters": params,
                "consistency": r.get("consistency"),
                "note": r.get("note"),
            }
        )
    rows.sort(key=lambda x: x["source"])
    return rows


def real_pcg_phase_b(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") != "P7-real-pcg-phase-b":
            continue
        timings = r.get("phase_b_timings") or {}
        setup = r.get("phase_b_setup") or {}
        comm = setup.get("comm") or {}
        rows.append(
            {
                "source": r["_path"],
                "git_dirty": r.get("git_dirty"),
                "is_real_pcg": r.get("is_real_pcg"),
                "base_vole": r.get("base_vole"),
                "production_ready": r.get("production_ready"),
                "setup_comm_bytes": r.get("setup_comm_bytes"),
                "base_ot_bytes": comm.get("base_ot_bytes"),
                "ot_extension_bytes": comm.get("ot_extension_bytes"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "t_total_real_expansion_s": r.get(
                    "t_total_real_expansion_s", timings.get("t_total_setup_and_expansion_s")
                ),
                "t_base_ot_s": timings.get("t_base_ot_s"),
                "t_ot_extension_s": timings.get("t_ot_extension_s"),
                "t_ggm_pprf_s": timings.get("t_ggm_pprf_s"),
                "t_lpn_expand_s": timings.get("t_lpn_expand_s"),
                "t_consistency_check_s": timings.get("t_consistency_check_s"),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "setup": setup,
                "consistency": r.get("consistency"),
                "note": r.get("note"),
            }
        )
    rows.sort(key=lambda x: x["source"])
    return rows


def gpu_roofline_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {"P7-gpu-roofline", "P7-gpu-roofline-quick"}:
            continue
        kernel = r.get("kernel") or {}
        # Early Thunder diagnostics had correct outputs but non-blocking event
        # timings (0 s / impossible bandwidth). Keep the raw JSON append-only,
        # but never promote it into the aggregate roofline profiles.
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        stream = kernel.get("stream") or {}
        chain = kernel.get("chain") or {}
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "device": kernel.get("device"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "stream_gpu_s": stream.get("gpu_s"),
                "stream_gpu_cpu_speedup": stream.get("gpu_cpu_speedup"),
                "stream_gpu_bandwidth_gb_s": stream.get("gpu_bandwidth_gb_s"),
                "chain_gpu_s": chain.get("gpu_s"),
                "chain_gpu_cpu_speedup": chain.get("gpu_cpu_speedup"),
                "chain_gpu_fp2_mul_s": chain.get("gpu_fp2_mul_s"),
                "screening": r.get("screening"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_fused_epilogue_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-fused-epilogue",
            "P7-gpu-fused-epilogue-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "device": kernel.get("device"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "weighted_rho_kernel": kernel.get("weighted_rho_kernel"),
                "gate_weighted_rho_le_1_30": kernel.get("gate_weighted_rho_le_1_30"),
                "shapes": kernel.get("shapes"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_logup_tree_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {"P7-gpu-logup-tree", "P7-gpu-logup-tree-quick"}:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "cpu_s": kernel.get("cpu_s"),
                "gpu_s": kernel.get("gpu_s"),
                "gpu_cpu_speedup": kernel.get("gpu_cpu_speedup"),
                "gate_speedup_ge_5_48": kernel.get("gate_speedup_ge_5_48"),
                "all_layers_checksum": kernel.get("all_layers_checksum"),
                "operation_counts": kernel.get("operation_counts"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_logup_round_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {"P7-gpu-logup-rounds", "P7-gpu-logup-rounds-quick"}:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "cpu_s": kernel.get("cpu_s"),
                "gpu_s": kernel.get("gpu_s"),
                "gpu_cpu_speedup": kernel.get("gpu_cpu_speedup"),
                "gate_speedup_ge_5_48": kernel.get("gate_speedup_ge_5_48"),
                "all_rounds_checksum": kernel.get("all_rounds_checksum"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_logup_blind_round_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-logup-blind-rounds",
            "P7-gpu-logup-blind-rounds-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "blind_corrections_correct": kernel.get("blind_corrections_correct"),
                "timing_sane": kernel.get("timing_sane"),
                "cpu_blind_s": kernel.get("cpu_blind_s"),
                "gpu_blind_s": kernel.get("gpu_blind_s"),
                "gpu_clear_s": kernel.get("gpu_clear_s"),
                "gpu_cpu_speedup": kernel.get("gpu_cpu_speedup"),
                "blind_over_clear": kernel.get("blind_over_clear"),
                "gate_speedup_ge_5_48_and_overhead_le_1_05": kernel.get(
                    "gate_speedup_ge_5_48_and_overhead_le_1_05"
                ),
                "all_rounds_checksum": kernel.get("all_rounds_checksum"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_pcs_arithmetic_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-pcs-arithmetic",
            "P7-gpu-pcs-arithmetic-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if not kernel.get("correctness") or not kernel.get("timing_sane"):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "correctness": kernel.get("correctness"),
                "timing_sane": kernel.get("timing_sane"),
                "gate_each_speedup_ge_5_48": kernel.get("gate_each_speedup_ge_5_48"),
                "ntt": kernel.get("ntt"),
                "combine_rows": kernel.get("combine_rows"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_blake3_merkle_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-blake3-merkle",
            "P7-gpu-blake3-merkle-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        rust = r.get("rust_reference") or {}
        if (
            not kernel.get("host_device_correctness")
            or not kernel.get("timing_sane")
            or not r.get("root_matches_rust_blake3")
        ):
            continue
        gpu_s = kernel.get("gpu_s")
        cpu_s = rust.get("cpu_s")
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "parameters": kernel.get("parameters"),
                "host_device_correctness": kernel.get("host_device_correctness"),
                "root_matches_rust_blake3": r.get("root_matches_rust_blake3"),
                "timing_sane": kernel.get("timing_sane"),
                "root": kernel.get("root"),
                "gpu_s": gpu_s,
                "rust_cpu_s": cpu_s,
                "gpu_cpu_speedup": cpu_s / gpu_s if cpu_s and gpu_s else None,
                "gate_gpu_s_le_0_075": kernel.get("gate_gpu_s_le_0_075"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def gpu_native_inference_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in {
            "P7-gpu-native-inference",
            "P7-gpu-native-inference-quick",
        }:
            continue
        kernel = r.get("kernel") or {}
        if (
            not r.get("correctness")
            or not r.get("golden_match")
            or not kernel.get("deterministic")
            or kernel.get("fixed_point_errors")
        ):
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "baseline": r.get("baseline"),
                "correctness": r.get("correctness"),
                "golden_match": r.get("golden_match"),
                "parameters": kernel.get("parameters"),
                "prefill_s": kernel.get("prefill_s"),
                "decode_50_s": kernel.get("decode_50_s"),
                "prefill_timing": kernel.get("prefill_timing"),
                "decode_50_timing": kernel.get("decode_50_timing"),
                "memory": kernel.get("memory"),
                "prefill_argmax": kernel.get("prefill_argmax"),
                "native_gpu_speedup": r.get("native_gpu_speedup"),
                "report_schema_version": r.get("report_schema_version"),
                "scope": r.get("scope"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def integrated_accelerator_profiles(
    results: list[dict[str, Any]], milestones: set[str], backend: str
) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        if r.get("milestone") not in milestones:
            continue
        if not r.get("accepted") or r.get("accelerator_backend") != backend:
            continue
        rows.append(
            {
                "_mtime": r["_mtime"],
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "cloud": r.get("cloud"),
                "report_schema_version": r.get("report_schema_version"),
                "t_prefill": r.get("t_prefill"),
                "n_decode": r.get("n_decode"),
                "benchmark_warmup_repetitions": r.get("benchmark_warmup_repetitions"),
                "benchmark_repetitions": r.get("benchmark_repetitions"),
                "prove_prefill_s": r.get("t_prove_prefill_only_s"),
                "prove_response_s": r.get("t_prove_response_s"),
                "prove_decode_marginal_s": r.get("t_prove_decode_marginal_s"),
                "prover_online_accounted_response_s": r.get(
                    "t_prover_online_accounted_response_s"
                ),
                "prover_online_accounted_decode_marginal_s": r.get(
                    "t_prover_online_accounted_decode_marginal_s"
                ),
                "response_session_wall_s": r.get("t_response_session_wall_s"),
                "protocol_closure_exchange_s": r.get("t_protocol_closure_exchange_s"),
                "verifier_accounted_s": r.get("t_verifier_accounted_s"),
                "prove_prefill_timing": r.get("prove_prefill_timing"),
                "prove_response_timing": r.get("prove_response_timing"),
                "prove_decode_marginal_timing": r.get("prove_decode_marginal_timing"),
                "prover_online_accounted_response_timing": r.get(
                    "prover_online_accounted_response_timing"
                ),
                "prover_online_accounted_decode_marginal_timing": r.get(
                    "prover_online_accounted_decode_marginal_timing"
                ),
                "response_session_wall_timing": r.get("response_session_wall_timing"),
                "protocol_closure_exchange_timing": r.get(
                    "protocol_closure_exchange_timing"
                ),
                "verifier_accounted_timing": r.get("verifier_accounted_timing"),
                "cpu_relative_rho": {
                    "prefill": r.get("rho_cpu_prefill", r.get("rho_prefill")),
                    "decode": r.get("rho_cpu_decode", r.get("rho_decode")),
                },
                "rho_denominator": r.get("rho_denominator"),
                "golden_decode_checked": r.get("golden_decode_checked"),
                "golden_decode_match": r.get("golden_decode_match"),
                "flat_cost_last_over_first": r.get("curve_last_over_first"),
                "flat_cost_gate": r.get("gate_flat_cost_per_token"),
                "packed_response_bytes": r.get("total_response_download_packed_bytes"),
                "communication": {
                    "prefill_bytes": r.get("comm_prefill_bytes"),
                    "response_bytes": r.get("comm_response_bytes"),
                    "decode_marginal_bytes": r.get("comm_decode_marginal_bytes"),
                    "pcs_opening_bytes": r.get("pcs_opening_bytes_total"),
                    "public_logits_packed_bytes": r.get("public_logits_packed_bytes"),
                    "response_by_label": r.get("comm_response_by_label"),
                    "pcs_by_label": r.get("comm_pcs_by_label"),
                },
                "pcs_commit_timing": r.get("pcs_commit_timing"),
                "pcs_open_timing": r.get("pcs_open_timing"),
                "pcs_verify_timing": r.get("pcs_verify_timing"),
                "verify_response_timing": r.get("verify_response_timing"),
                "accelerator_witness": r.get("accelerator_witness"),
                "accelerator_response_witness": r.get("accelerator_response_witness"),
                "accelerator_prefill": r.get("accelerator_prefill_proving"),
                "accelerator_session": r.get("accelerator_proving"),
                "accelerator_live_device_bytes_after_cleanup": r.get(
                    "accelerator_live_device_bytes_after_cleanup"
                ),
                "accelerator_workspace_device_bytes_after_cleanup": r.get(
                    "accelerator_workspace_device_bytes_after_cleanup"
                ),
                "accelerator_resident_device_bytes_after_cleanup": r.get(
                    "accelerator_resident_device_bytes_after_cleanup"
                ),
                "peak_rss_gb": r.get("peak_rss_gb"),
                "corr_sub_corrs": r.get("corr_sub_corrs"),
                "corr_full_corrs": r.get("corr_full_corrs"),
                "pcg_backend": r.get("pcg_backend"),
                "pcg_setup_comm_bytes": r.get("pcg_setup_comm_bytes"),
                "pcg_real_phase_a_total_s": r.get("pcg_real_phase_a_total_s"),
            }
        )
    rows.sort(key=lambda x: (x["milestone"], x["_mtime"], x["source"]))
    for row in rows:
        row.pop("_mtime", None)
    return rows


def integrated_hybrid_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return integrated_accelerator_profiles(
        results,
        {"P7-integrated-hybrid", "P7-integrated-hybrid-quick"},
        "cuda-hybrid",
    )


def integrated_resident_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return integrated_accelerator_profiles(
        results,
        {"P7-integrated-resident", "P7-integrated-resident-quick"},
        "cuda-resident",
    )


def same_host_native(
    native_profiles: list[dict[str, Any]], integrated: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not integrated:
        return None
    instance_id = (integrated.get("cloud") or {}).get("instance_id")
    if not instance_id:
        return None
    matches = [
        row
        for row in native_profiles
        if row.get("milestone") == "P7-gpu-native-inference"
        and not row.get("git_dirty", True)
        and (row.get("cloud") or {}).get("instance_id") == instance_id
    ]
    return matches[-1] if matches else None


def integrated_same_host_result(
    proof: dict[str, Any] | None, native: dict[str, Any] | None
) -> dict[str, Any] | None:
    if not proof or not native:
        return None
    proof_rho = {
        "prefill": proof["prove_prefill_s"] / native["prefill_s"],
        "decode": proof["prove_decode_marginal_s"] / native["decode_50_s"],
    }
    result: dict[str, Any] = {
        "same_instance": True,
        "native_source": native["source"],
        "proof_source": proof["source"],
        "rho_definition": "protocol-core prover wall / same-host exact native-GPU inference wall",
        "proof_rho": proof_rho,
        "targets": P7_RHO_TARGETS,
        "target_met": {
            phase: proof_rho[phase] <= P7_RHO_TARGETS[phase]
            for phase in ("prefill", "decode")
        },
        "required_speedup_to_target": {
            phase: proof_rho[phase] / P7_RHO_TARGETS[phase]
            for phase in ("prefill", "decode")
        },
        "native_anchor_plus_protocol_core_s": {
            "prefill": native["prefill_s"] + proof["prove_prefill_s"],
            "decode_50": native["decode_50_s"] + proof["prove_decode_marginal_s"],
        },
        "pcs": {
            "commit_offline_s": (proof.get("pcs_commit_timing") or {}).get("median_s"),
            "open_online_s": (proof.get("pcs_open_timing") or {}).get("median_s"),
            "verify_s": (proof.get("pcs_verify_timing") or {}).get("median_s"),
        },
        "pcg": {
            "backend": proof.get("pcg_backend"),
            "setup_offline_s": proof.get("pcg_real_phase_a_total_s"),
            "setup_comm_bytes": proof.get("pcg_setup_comm_bytes"),
            "production_grade": False,
        },
        "verifier_accounted_s": proof.get("verifier_accounted_s"),
        "response_session_wall_s": proof.get("response_session_wall_s"),
    }
    online_response = proof.get("prover_online_accounted_response_s")
    online_decode = proof.get("prover_online_accounted_decode_marginal_s")
    if online_response is not None and online_decode is not None:
        result["online_accounted"] = {
            "definition": "protocol core + PCS opening + final closure exchange; closure contains both local roles",
            "response_s": online_response,
            "decode_marginal_s": online_decode,
            "decode_rho": online_decode / native["decode_50_s"],
        }
    witness_prefill = (proof.get("accelerator_witness") or {}).get("measurement_wall_s")
    witness_response = (proof.get("accelerator_response_witness") or {}).get(
        "measurement_wall_s"
    )
    if witness_prefill is not None and witness_response is not None:
        result["measured_resident_pipeline_s"] = {
            "prefill_inference_plus_protocol_core": witness_prefill
            + proof["prove_prefill_s"],
            "response_inference_plus_online_accounted": (
                witness_response + online_response if online_response is not None else None
            ),
            "response_inference_plus_full_session_wall": (
                witness_response + proof["response_session_wall_s"]
                if proof.get("response_session_wall_s") is not None
                else None
            ),
        }
    return result


def decode_marginal_profiles(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for r in results:
        labels = r.get("comm_decode_marginal_by_label")
        if not labels:
            continue
        top = sorted(labels.items(), key=lambda kv: (-kv[1], kv[0]))[:12]
        rows.append(
            {
                "source": r["_path"],
                "milestone": r.get("milestone"),
                "git_dirty": r.get("git_dirty"),
                "t_prefill": r.get("t_prefill"),
                "n_decode": r.get("n_decode"),
                "comm_decode_marginal_bytes": r.get("comm_decode_marginal_bytes"),
                "comm_decode_bytes_per_token": r.get("comm_decode_bytes_per_token"),
                "label_sum_bytes": sum(labels.values()),
                "top_labels": [{"label": k, "bytes": v} for k, v in top],
            }
        )
    rows.sort(key=lambda x: (x["t_prefill"] or 0, x["n_decode"] or 0, x["source"]))
    return rows


def p7_report(results_dir: Path) -> dict[str, Any]:
    results = load_results(results_dir)
    baseline = select_p6_record(results)
    packed = select_packed_source(results, baseline)

    public_logits_packed = (
        int(packed["public_logits_packed_bytes"])
        if packed and "public_logits_packed_bytes" in packed
        else int(baseline.get("public_logits_packed_bytes", baseline["public_logits_bytes"]))
    )
    current_packed_download = int(baseline["comm_response_bytes"]) + public_logits_packed

    current_formula = pcs_total(LAYER_PARAMS, 8, EMBED_PARAMS, 6)
    current_measured = int(baseline["pcs_opening_bytes_total"])
    formula_matches = current_formula == current_measured
    mock_pcg = mock_pcg_lower_bounds(results)
    real_pcg = real_pcg_phase_a(results)
    real_pcg_b = real_pcg_phase_b(results)
    gpu_rooflines = gpu_roofline_profiles(results)
    full_gpu_rooflines = [r for r in gpu_rooflines if r["milestone"] == "P7-gpu-roofline"]
    gpu_roofline_record = full_gpu_rooflines[-1] if full_gpu_rooflines else None
    gpu_fused = gpu_fused_epilogue_profiles(results)
    full_gpu_fused = [r for r in gpu_fused if r["milestone"] == "P7-gpu-fused-epilogue"]
    gpu_fused_record = full_gpu_fused[-1] if full_gpu_fused else None
    gpu_logup = gpu_logup_tree_profiles(results)
    full_gpu_logup = [r for r in gpu_logup if r["milestone"] == "P7-gpu-logup-tree"]
    gpu_logup_record = full_gpu_logup[-1] if full_gpu_logup else None
    gpu_logup_rounds = gpu_logup_round_profiles(results)
    full_gpu_logup_rounds = [
        r
        for r in gpu_logup_rounds
        if r["milestone"] == "P7-gpu-logup-rounds" and r["gate_speedup_ge_5_48"]
    ]
    gpu_logup_round_record = full_gpu_logup_rounds[-1] if full_gpu_logup_rounds else None
    gpu_logup_blind_rounds = gpu_logup_blind_round_profiles(results)
    full_gpu_logup_blind_rounds = [
        r
        for r in gpu_logup_blind_rounds
        if r["milestone"] == "P7-gpu-logup-blind-rounds"
        and r["gate_speedup_ge_5_48_and_overhead_le_1_05"]
    ]
    gpu_logup_blind_round_record = (
        full_gpu_logup_blind_rounds[-1] if full_gpu_logup_blind_rounds else None
    )
    gpu_pcs = gpu_pcs_arithmetic_profiles(results)
    full_gpu_pcs = [r for r in gpu_pcs if r["milestone"] == "P7-gpu-pcs-arithmetic"]
    gpu_pcs_record = full_gpu_pcs[-1] if full_gpu_pcs else None
    gpu_blake3 = gpu_blake3_merkle_profiles(results)
    full_gpu_blake3 = [r for r in gpu_blake3 if r["milestone"] == "P7-gpu-blake3-merkle"]
    gpu_blake3_record = full_gpu_blake3[-1] if full_gpu_blake3 else None
    gpu_hybrid = integrated_hybrid_profiles(results)
    full_gpu_hybrid = [
        r
        for r in gpu_hybrid
        if r["milestone"] == "P7-integrated-hybrid" and not r.get("git_dirty", True)
    ]
    gpu_hybrid_record = full_gpu_hybrid[-1] if full_gpu_hybrid else None
    gpu_resident = integrated_resident_profiles(results)
    full_gpu_resident = [
        r
        for r in gpu_resident
        if r["milestone"] == "P7-integrated-resident" and not r.get("git_dirty", True)
    ]
    gpu_resident_record = full_gpu_resident[-1] if full_gpu_resident else None
    gpu_native = gpu_native_inference_profiles(results)
    full_gpu_native = [
        r
        for r in gpu_native
        if r["milestone"] == "P7-gpu-native-inference" and not r.get("git_dirty", True)
    ]
    resident_native_record = same_host_native(gpu_native, gpu_resident_record)
    hybrid_native_record = same_host_native(gpu_native, gpu_hybrid_record)
    gpu_native_record = (
        resident_native_record
        or hybrid_native_record
        or (full_gpu_native[-1] if full_gpu_native else None)
    )
    gpu_budget = rho_model(baseline)
    required_prover_gpu_speedup = None
    if gpu_native_record:
        proof_only_budget = {
            "prefill_s": gpu_native_record["prefill_s"] * P7_RHO_TARGETS["prefill"],
            "decode_50_s": gpu_native_record["decode_50_s"] * P7_RHO_TARGETS["decode"],
        }
        if (gpu_native_record.get("baseline") or {}).get("source") == baseline["_path"]:
            relative = gpu_budget["required_relative_prover_vs_native_speedup"]
            native = gpu_native_record["native_gpu_speedup"]
            required_prover_gpu_speedup = {
                phase: relative[phase] * native[phase] for phase in ("prefill", "decode")
            }
    else:
        proof_only_budget = None
    integrated_hybrid_rho = integrated_same_host_result(
        gpu_hybrid_record, hybrid_native_record
    )
    integrated_resident_rho = integrated_same_host_result(
        gpu_resident_record, resident_native_record
    )
    if integrated_hybrid_rho:
        # Preserve the schema consumed by the historical hybrid artifact.
        integrated_hybrid_rho["required_speedup_from_hybrid_to_target"] = (
            integrated_hybrid_rho["required_speedup_to_target"]
        )
        integrated_hybrid_rho["inference_plus_proving_s"] = integrated_hybrid_rho[
            "native_anchor_plus_protocol_core_s"
        ]
    pcg_status = (
        "phase_b_measured_not_production"
        if real_pcg_b
        else "phase_a_measured_mock_stub" if real_pcg else "not_measured_in_local_vm"
    )
    pcg_note = (
        "Real-PCG phase B setup measured, but production_ready is false until WYKW malicious checks and table-derived LPN parameters are closed."
        if real_pcg_b
        else (
        "Real-PCG phase A measured with a mock-stub base VOLE; phase B still needs real base OTs/OT extension/setup communication."
        if real_pcg
        else "P7 final go/no-go still needs a real silent-VOLE setup/expansion measurement for this volume."
        )
    )

    p6_comm = {
        "source": baseline["_path"],
        "packed_logits_source": packed["_path"] if packed else None,
        "comm_prefill_bytes": baseline["comm_prefill_bytes"],
        "comm_decode_marginal_bytes": baseline["comm_decode_marginal_bytes"],
        "comm_decode_bytes_per_token": baseline["comm_decode_bytes_per_token"],
        "pcs_opening_bytes": current_measured,
        "public_logits_raw_bytes": baseline["public_logits_bytes"],
        "public_logits_packed_bytes": public_logits_packed,
        "total_response_download_raw_bytes": int(baseline["comm_response_bytes"])
        + int(baseline["public_logits_bytes"]),
        "total_response_download_packed_bytes": current_packed_download,
    }

    report = {
        "report_schema_version": 3 if gpu_resident_record else 2,
        "milestone": "P7",
        "date": _dt.date.today().isoformat(),
        "git_sha": git(["rev-parse", "--short", "HEAD"]),
        "git_dirty": git_dirty(),
        "machine": f"{platform.system().lower()} {platform.machine()}",
        "cloud": (
            gpu_resident_record.get("cloud")
            if gpu_resident_record
            else gpu_hybrid_record.get("cloud")
            if gpu_hybrid_record
            else baseline.get("cloud")
        ),
        "baseline": {
            "source": baseline["_path"],
            "git_dirty": baseline.get("git_dirty"),
            "cloud": baseline.get("cloud"),
            "accepted": baseline.get("accepted"),
            "t_prefill": baseline.get("t_prefill"),
            "n_decode": baseline.get("n_decode"),
            "rho_prefill_cpu": baseline.get("rho_prefill"),
            "rho_decode_cpu": baseline.get("rho_decode"),
            "prove_response_s": baseline.get("t_prove_response_s"),
            "prove_decode_marginal_s": baseline.get("t_prove_decode_marginal_s"),
            "verify_response_s": baseline.get("t_verify_response_s"),
            "pcs_open_s": baseline.get("pcs_open_total_s"),
            "pcs_verify_s": baseline.get("pcs_verify_total_s"),
            "peak_rss_gb": baseline.get("peak_rss_gb"),
        },
        "rho_history": summarize_rhos(results),
        "communication": p6_comm,
        "measured_pcs_profiles": measured_pcs_profiles(results, baseline),
        "decode_marginal_profiles": decode_marginal_profiles(results),
        "pcs_formula_check": {
            "matches_p6_measured_bytes": formula_matches,
            "formula_total_bytes": current_formula,
            "measured_total_bytes": current_measured,
            "layer_one_opening": multi_open_breakdown(LAYER_PARAMS, 8),
            "embed_opening": multi_open_breakdown(EMBED_PARAMS, 6),
            "rate": rate(LAYER_PARAMS),
            "relative_distance": distance(LAYER_PARAMS),
            "q200_error_bits": query_error_bits(LAYER_PARAMS),
            "q_for_60_bits": queries_for_bits(LAYER_PARAMS, 60.0),
        },
        "pcs_scenarios": pcs_scenarios(baseline, current_packed_download),
        "gpu_budget_model": gpu_budget,
        "gpu_roofline": {
            "status": "measured_screening_pass" if gpu_roofline_record else "not_measured",
            "run_of_record": gpu_roofline_record,
            "profiles": gpu_rooflines,
            "note": "Historical arithmetic screening; full hybrid integration is measured and the device-resident gate remains open.",
        },
        "gpu_fused_epilogue": {
            "status": "measured_gate_pass" if gpu_fused_record else "not_measured",
            "run_of_record": gpu_fused_record,
            "profiles": gpu_fused,
            "note": "Historical P1-equivalent screening; hybrid proving integration landed, resident witness/proving remains open.",
        },
        "gpu_logup_tree": {
            "status": "measured_gate_pass" if gpu_logup_record else "not_measured",
            "run_of_record": gpu_logup_record,
            "profiles": gpu_logup,
            "note": "Historical lookup-tree screening; rounds and hybrid proving integration are now measured separately.",
        },
        "gpu_logup_rounds": {
            "status": "measured_gate_pass" if gpu_logup_round_record else "not_measured",
            "run_of_record": gpu_logup_round_record,
            "profiles": gpu_logup_rounds,
            "note": "Historical clear-round screening; see blind-round and integrated-hybrid sections for correction plumbing and e2e attribution.",
        },
        "gpu_logup_blind_rounds": {
            "status": "measured_gate_pass" if gpu_logup_blind_round_record else "not_measured",
            "run_of_record": gpu_logup_blind_round_record,
            "profiles": gpu_logup_blind_rounds,
            "note": "Historical blind-round screening; aux leaves and corrections are covered by differential/full hybrid integration, resident buffers remain open.",
        },
        "gpu_pcs_arithmetic": {
            "status": "measured_gate_pass" if gpu_pcs_record else "not_measured",
            "run_of_record": gpu_pcs_record,
            "profiles": gpu_pcs,
            "note": "Historical arithmetic screening; mask rows and hybrid proving integration are covered by the integrated gate.",
        },
        "gpu_blake3_merkle": {
            "status": "measured_gate_pass" if gpu_blake3_record else "not_measured",
            "run_of_record": gpu_blake3_record,
            "profiles": gpu_blake3,
            "note": "Historical gather/hash screening; mask rows and hybrid proving integration are covered by the integrated gate.",
        },
        "integrated_hybrid": {
            "status": (
                "measured_attribution_pass_resident_required"
                if integrated_hybrid_rho
                else "measured_without_same_host_native_anchor"
                if gpu_hybrid_record
                else "not_measured"
            ),
            "run_of_record": gpu_hybrid_record,
            "profiles": gpu_hybrid,
            "same_host_result": integrated_hybrid_rho,
            "note": (
                "Full staged integration preserves correctness, transcript, communication and flat-cost gates, "
                "but H2D/D2H plus CPU residual dominate. This is the attribution gate, not the resident paper result."
            ),
        },
        "integrated_resident": {
            "status": (
                "measured_same_host_targets_pass"
                if integrated_resident_rho
                and all(integrated_resident_rho["target_met"].values())
                else "measured_same_host_targets_fail"
                if integrated_resident_rho
                else "measured_without_same_host_native_anchor"
                if gpu_resident_record
                else "not_measured"
            ),
            "run_of_record": gpu_resident_record,
            "profiles": gpu_resident,
            "same_host_result": integrated_resident_rho,
            "note": (
                "Resident forward, witness and proving share persistent device buffers. "
                "The protocol-core rho remains the preregistered gate; PCS/opening, closures, "
                "verifier, offline commitment and mock-PCG limitations are reported separately "
                "and retained in the measured session wall."
            ),
        },
        "gpu_native_inference": {
            "status": "measured_exact_golden_pass" if gpu_native_record else "not_measured",
            "run_of_record": gpu_native_record,
            "profiles": gpu_native,
            "required_prover_gpu_speedup_vs_cpu": required_prover_gpu_speedup,
            "proof_only_budget": proof_only_budget,
            "note": "Exact fixed-point full-model prefill and KV decode anchor paired by instance; weights resident, cache-seeding prefill excluded from decode, per-token logits D2H + argmax included.",
        },
        "real_pcg_spike": {
            "status": pcg_status,
            "corr_sub_corrs": baseline.get("corr_sub_corrs"),
            "corr_full_corrs": baseline.get("corr_full_corrs"),
            "mock_pcg_lower_bounds": mock_pcg,
            "real_pcg_phase_a": real_pcg,
            "real_pcg_phase_b": real_pcg_b,
            "note": pcg_note,
        },
        "go_no_go": {
            "local_recommendation": (
                "resident-gates-pass-build-publication-artifact"
                if integrated_resident_rho
                and all(integrated_resident_rho["target_met"].values())
                else "resident-gates-fail-report-result-without-production-claim"
                if integrated_resident_rho
                else "measure-same-host-native-gpu-anchor-for-resident-run"
                if gpu_resident_record
                else "proceed-to-device-resident-prover-integration"
                if integrated_hybrid_rho
                else "measure-same-host-native-gpu-anchor"
                if gpu_hybrid_record
                else "proceed-to-integrated-gpu-prover-measurement"
                if gpu_native_record
                else "proceed-to-proving-path-integration-and-native-gpu-anchor"
                if gpu_logup_blind_round_record
                else "proceed-to-blind-integration-and-native-gpu-anchor"
                if gpu_blake3_record
                else "proceed-to-blake3-merkle-spike"
                if gpu_pcs_record
                else "proceed-to-pcs-hash-spikes"
                if gpu_logup_round_record
                else "proceed-to-logup-rounds-and-pcs-spikes"
                if gpu_logup_record
                else "proceed-to-logup-pcs-kernel-spikes"
                if gpu_fused_record
                else "proceed-to-fused-kernel-spikes"
                if gpu_roofline_record
                else "conditional-go-to-cloud-spikes-only"
            ),
            "summary": (
                "The clean full resident path has a same-host exact native-GPU denominator; "
                "the report retains protocol-core rho, resident inference+proving, full session wall, "
                "PCS/PCG, verifier, communication and memory as separate measured quantities."
                if integrated_resident_rho
                else "Communication, golden decode, verifier and flat-cost gates pass in the full CUDA-hybrid path. "
                "Same-host attribution shows staged transfers and CPU residual dominate by orders of magnitude; "
                "the preregistered resident witness/proving path is required before the final rho go/no-go."
                if integrated_hybrid_rho
                else "Communication is inside the 150-200 MB envelope, but a final rho decision still requires same-host integrated proving and native GPU measurements."
            ),
            "remaining_before_final_go_no_go": (
                []
                if integrated_resident_rho
                else [
                    "device-resident witness consumed directly by the prover without full host materialization",
                    "resident forward/proving share persistent buffers and transfer only protocol messages",
                    "resident 1-warmup/3-repetition full gate passes rho<=10/<=2 with the existing correctness and communication gates",
                ]
                if integrated_hybrid_rho
                else [
                    "same-host native GPU and integrated proving measurements",
                    "device-resident witness/proving path",
                    "golden decode, flat-cost, anti-replay and communication gates",
                ]
            ),
        },
    }
    return report


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    stem = path.stem
    suffix = path.suffix
    for i in range(1, 1000):
        candidate = path.with_name(f"{stem}-{i}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"could not find unused result path near {path}")


def write_report(report: dict[str, Any], results_dir: Path) -> Path:
    label = f"p7-{report['date']}-{report['git_sha'] or 'unknown'}.json"
    path = unique_path(results_dir / label)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def print_summary(report: dict[str, Any]) -> None:
    comm = report["communication"]
    model = report["gpu_budget_model"]
    print("P7 report")
    print(f"baseline: {report['baseline']['source']} (dirty={report['baseline']['git_dirty']})")
    if comm["packed_logits_source"]:
        print(f"packed logits source: {comm['packed_logits_source']}")
    print()
    print("Communication (MB)")
    print(f"  transcript:          {mb(comm['total_response_download_raw_bytes'] - comm['public_logits_raw_bytes']):8.2f}")
    print(f"  PCS opening:         {mb(comm['pcs_opening_bytes']):8.2f}")
    print(f"  public logits raw:   {mb(comm['public_logits_raw_bytes']):8.2f}")
    print(f"  public logits packed:{mb(comm['public_logits_packed_bytes']):8.2f}")
    print(f"  total raw:           {mb(comm['total_response_download_raw_bytes']):8.2f}")
    print(f"  total packed:        {mb(comm['total_response_download_packed_bytes']):8.2f}")
    print()
    if report.get("measured_pcs_profiles"):
        print("Measured PCS profiles")
        for row in report["measured_pcs_profiles"]:
            packed = row.get("total_response_download_packed_bytes")
            packed_s = f" total={mb(packed):7.2f}" if packed is not None else ""
            print(
                f"  {row['milestone']:<8} Q={row['pcs_n_queries']:<3} "
                f"pcs={mb(row['pcs_opening_bytes_total']):7.2f}{packed_s} "
                f"{row['source']}"
            )
    print()
    pcg = report["real_pcg_spike"].get("mock_pcg_lower_bounds") or []
    if pcg:
        print("Mock-PCG lower bounds")
        for row in pcg:
            print(
                f"  mock total={row['t_total_mock_expansion_s']:.3f}s "
                f"sub={row['corr_sub_corrs']} full={row['corr_full_corrs']} "
                f"{row['source']}"
            )
        print()
    real_pcg = report["real_pcg_spike"].get("real_pcg_phase_a") or []
    if real_pcg:
        print("Real-PCG phase A")
        for row in real_pcg:
            print(
                f"  total={row['t_total_real_expansion_s']:.3f}s "
                f"setup={row['t_setup_stub_s']:.3f}s ggm={row['t_ggm_pprf_s']:.3f}s "
                f"lpn={row['t_lpn_expand_s']:.3f}s check={row['t_consistency_check_s']:.3f}s "
                f"base={row['base_vole']} setup_comm={row['setup_comm_bytes']} B "
                f"{row['source']}"
            )
        print()
    real_pcg_b = report["real_pcg_spike"].get("real_pcg_phase_b") or []
    if real_pcg_b:
        print("Real-PCG phase B")
        for row in real_pcg_b:
            print(
                f"  total={row['t_total_real_expansion_s']:.3f}s "
                f"baseOT={row['t_base_ot_s']:.3f}s otExt={row['t_ot_extension_s']:.3f}s "
                f"ggm={(row['t_ggm_pprf_s'] or 0.0):.3f}s "
                f"lpn={row['t_lpn_expand_s']:.3f}s setup_comm={row['setup_comm_bytes']} B "
                f"production_ready={row['production_ready']} {row['source']}"
            )
        print()
    roofline = report.get("gpu_roofline", {}).get("run_of_record")
    if roofline:
        print("GPU Goldilocks/Fp2 roofline")
        print(
            f"  stream {roofline['stream_gpu_cpu_speedup']:.2f}x, "
            f"{roofline['stream_gpu_bandwidth_gb_s']:.1f} GB/s; "
            f"chain {roofline['chain_gpu_cpu_speedup']:.2f}x, "
            f"{roofline['chain_gpu_fp2_mul_s'] / 1e9:.2f} G Fp2-mul/s "
            f"{roofline['source']}"
        )
        print()
    fused = report.get("gpu_fused_epilogue", {}).get("run_of_record")
    if fused:
        shape_rhos = ", ".join(f"{row['n']}:{row['rho_kernel']:.3f}" for row in fused["shapes"])
        print("GPU fused GEMM-MAC epilogue")
        print(
            f"  weighted rho={fused['weighted_rho_kernel']:.3f}; "
            f"shape rhos [{shape_rhos}] {fused['source']}"
        )
        print()
    logup = report.get("gpu_logup_tree", {}).get("run_of_record")
    if logup:
        print("GPU LogUp fraction-tree build")
        print(
            f"  N={logup['parameters']['n']} CPU={logup['cpu_s']:.3f}s "
            f"GPU={logup['gpu_s']:.4f}s speedup={logup['gpu_cpu_speedup']:.2f}x "
            f"{logup['source']}"
        )
        print()
    logup_rounds = report.get("gpu_logup_rounds", {}).get("run_of_record")
    if logup_rounds:
        print("GPU LogUp general rounds/folds")
        print(
            f"  N={logup_rounds['parameters']['n']} CPU={logup_rounds['cpu_s']:.3f}s "
            f"GPU={logup_rounds['gpu_s']:.4f}s speedup={logup_rounds['gpu_cpu_speedup']:.2f}x "
            f"{logup_rounds['source']}"
        )
        print()
    blind_rounds = report.get("gpu_logup_blind_rounds", {}).get("run_of_record")
    if blind_rounds:
        print("GPU blind LogUp correction plumbing")
        print(
            f"  N={blind_rounds['parameters']['n']} CPU={blind_rounds['cpu_blind_s']:.3f}s "
            f"GPU={blind_rounds['gpu_blind_s']:.4f}s "
            f"speedup={blind_rounds['gpu_cpu_speedup']:.2f}x "
            f"blind/clear={blind_rounds['blind_over_clear']:.3f} "
            f"{blind_rounds['source']}"
        )
        print()
    pcs = report.get("gpu_pcs_arithmetic", {}).get("run_of_record")
    if pcs:
        print("GPU PCS arithmetic")
        print(
            f"  NTT {pcs['ntt']['gpu_cpu_speedup']:.2f}x "
            f"({pcs['ntt']['gpu_s'] * 1e3:.2f} ms); combine_rows "
            f"{pcs['combine_rows']['gpu_cpu_speedup']:.2f}x "
            f"({pcs['combine_rows']['gpu_s'] * 1e3:.2f} ms) {pcs['source']}"
        )
        print()
    blake3 = report.get("gpu_blake3_merkle", {}).get("run_of_record")
    if blake3:
        print("GPU PCS column gather + BLAKE3/Merkle")
        print(
            f"  {blake3['parameters']['rows']}x{blake3['parameters']['cols']} "
            f"Rust={blake3['rust_cpu_s'] * 1e3:.2f} ms "
            f"GPU={blake3['gpu_s'] * 1e3:.2f} ms "
            f"speedup={blake3['gpu_cpu_speedup']:.2f}x {blake3['source']}"
        )
        print()
    native_gpu = report.get("gpu_native_inference", {}).get("run_of_record")
    if native_gpu:
        targets = report["gpu_native_inference"]["required_prover_gpu_speedup_vs_cpu"]
        print("Native fixed-point GPU inference")
        print(
            f"  prefill={native_gpu['prefill_s'] * 1e3:.2f} ms "
            f"({native_gpu['native_gpu_speedup']['prefill']:.2f}x CPU); "
            f"decode50={native_gpu['decode_50_s'] * 1e3:.2f} ms "
            f"({native_gpu['native_gpu_speedup']['decode']:.2f}x CPU) {native_gpu['source']}"
        )
        if targets:
            print(
                f"  required integrated prover speedup vs CPU: "
                f"prefill {targets['prefill']:.2f}x, decode {targets['decode']:.2f}x"
            )
        print()
    hybrid = report.get("integrated_hybrid", {}).get("run_of_record")
    hybrid_rho = report.get("integrated_hybrid", {}).get("same_host_result")
    if hybrid:
        print("Integrated CUDA-hybrid prover")
        print(
            f"  proof prefill={hybrid['prove_prefill_s']:.3f}s; "
            f"decode marginal={hybrid['prove_decode_marginal_s']:.3f}s; "
            f"flat={hybrid['flat_cost_last_over_first']:.3f}; "
            f"packed={mb(hybrid['packed_response_bytes']):.2f} MB {hybrid['source']}"
        )
        if hybrid_rho:
            measured = hybrid_rho["proof_rho"]
            gap = hybrid_rho["required_speedup_from_hybrid_to_target"]
            print(
                f"  same-host proof rho: prefill {measured['prefill']:.2f}, "
                f"decode {measured['decode']:.2f}; resident gap to target "
                f"{gap['prefill']:.2f}x/{gap['decode']:.2f}x"
            )
        print()
    resident = report.get("integrated_resident", {}).get("run_of_record")
    resident_rho = report.get("integrated_resident", {}).get("same_host_result")
    if resident:
        print("Integrated CUDA-resident prover")
        print(
            f"  proof core prefill={resident['prove_prefill_s']:.3f}s; "
            f"decode marginal={resident['prove_decode_marginal_s']:.3f}s; "
            f"online response={resident['prover_online_accounted_response_s']:.3f}s; "
            f"session wall={resident['response_session_wall_s']:.3f}s"
        )
        print(
            f"  flat={resident['flat_cost_last_over_first']:.3f}; "
            f"packed={mb(resident['packed_response_bytes']):.2f} MB; "
            f"workspace after cleanup="
            f"{resident['accelerator_workspace_device_bytes_after_cleanup']} B; "
            f"explicit resident after cleanup="
            f"{resident['accelerator_resident_device_bytes_after_cleanup']} B "
            f"{resident['source']}"
        )
        if resident_rho:
            measured = resident_rho["proof_rho"]
            print(
                f"  same-host proof rho: prefill {measured['prefill']:.3f} "
                f"({'PASS' if resident_rho['target_met']['prefill'] else 'FAIL'}); "
                f"decode {measured['decode']:.3f} "
                f"({'PASS' if resident_rho['target_met']['decode'] else 'FAIL'})"
            )
            pcs = resident_rho["pcs"]
            print(
                f"  PCS commit offline={pcs['commit_offline_s']:.3f}s; "
                f"open online={pcs['open_online_s']:.3f}s; verify={pcs['verify_s']:.3f}s; "
                f"PCG={resident_rho['pcg']['backend']} (production_grade=false)"
            )
        print()
    decode_profiles = report.get("decode_marginal_profiles") or []
    if decode_profiles:
        print("Decode marginal profiles")
        for row in decode_profiles:
            print(
                f"  {row['milestone']:<8} {row['comm_decode_marginal_bytes']} B "
                f"({row['comm_decode_bytes_per_token']} B/token) {row['source']}"
            )
            for item in row["top_labels"][:5]:
                print(f"    {item['label']:<32} {item['bytes']}")
        print()
    print("PCS scenarios (packed response MB)")
    for row in report["pcs_scenarios"]:
        print(
            f"  {row['name']:<36} pcs={mb(row['pcs_opening_bytes']):7.2f} "
            f"total={mb(row['packed_response_download_bytes']):7.2f}  {row['status']}"
        )
    print()
    req = model["required_relative_prover_vs_native_speedup"]
    print("GPU rho sensitivity")
    print(f"  required relative prover/native speedup: prefill {req['prefill']:.2f}x, decode {req['decode']:.2f}x")
    for row in model["sensitivity"]:
        print(
            f"  rel={row['relative_prover_vs_native_speedup']:>4.1f}x "
            f"rho_prefill={row['rho_prefill']:>5.2f} "
            f"rho_decode={row['rho_decode']:>5.2f}"
        )
    print()
    print(f"recommendation: {report['go_no_go']['local_recommendation']}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--results-dir", type=Path, default=DEFAULT_RESULTS)
    ap.add_argument("--write-json", action="store_true", help="write benchmarks/results/p7-*.json")
    args = ap.parse_args()

    report = p7_report(args.results_dir)
    if not report["pcs_formula_check"]["matches_p6_measured_bytes"]:
        raise SystemExit("PCS byte formula does not match the P6 measured opening bytes")
    print_summary(report)
    if args.write_json:
        path = write_report(report, args.results_dir)
        print(f"wrote {path.relative_to(REPO)}")


if __name__ == "__main__":
    main()
