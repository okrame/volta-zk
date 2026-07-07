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
        return clean[-1]
    dirty = [r for r in results if p6_shape(r)]
    if dirty:
        return dirty[-1]
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
    return same_shape[-1] if same_shape else None


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
    target_prefill = 5.0
    target_decode = 2.0
    relative = [1.0, 2.0, 2.5, 3.0, 5.0, 8.0, 10.0]
    return {
        "definition": "predicted_gpu_rho = cpu_rho / relative_prover_vs_native_gpu_speedup",
        "targets": {"prefill": target_prefill, "decode": target_decode},
        "required_relative_prover_vs_native_speedup": {
            "prefill": rho_prefill / target_prefill,
            "decode": rho_decode / target_decode,
        },
        "sensitivity": [
            {
                "relative_prover_vs_native_speedup": r,
                "rho_prefill": rho_prefill / r,
                "rho_decode": rho_decode / r,
                "prefill_target_met": rho_prefill / r <= target_prefill,
                "decode_target_met": rho_decode / r <= target_decode,
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
    rows = []
    seen: set[str] = set()
    candidates = [baseline] + [
        r
        for r in results
        if r.get("accepted") is True
        and r.get("milestone") in {"P6", "P6-quick"}
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
        rows.append(row)
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
        "milestone": "P7",
        "date": _dt.date.today().isoformat(),
        "git_sha": git(["rev-parse", "--short", "HEAD"]),
        "git_dirty": git_dirty(),
        "machine": f"{platform.system().lower()} {platform.machine()}",
        "baseline": {
            "source": baseline["_path"],
            "git_dirty": baseline.get("git_dirty"),
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
        "gpu_budget_model": rho_model(baseline),
        "real_pcg_spike": {
            "status": "not_measured_in_local_vm",
            "corr_sub_corrs": baseline.get("corr_sub_corrs"),
            "corr_full_corrs": baseline.get("corr_full_corrs"),
            "mock_pcg_lower_bounds": mock_pcg,
            "note": "P7 final go/no-go still needs a real silent-VOLE setup/expansion measurement for this volume.",
        },
        "go_no_go": {
            "local_recommendation": "conditional-go-to-cloud-spikes-only",
            "summary": (
                "Communication is inside the 150-200 MB envelope after the shipped logits packing, "
                "and PCS projections show enough headroom without changing the proof path locally. "
                "The rho targets require measured GPU roofline data and the real-PCG spike before a final go/no-go."
            ),
            "do_not_start_full_cuda_until": [
                "real-PCG cost spike is measured or explicitly budgeted",
                "cloud CPU native baseline is re-measured on the target instance",
                "Goldilocks/LogUp/PCS roofline kernels demonstrate the required relative prover-vs-native speedup",
            ],
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
