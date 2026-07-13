#!/usr/bin/env python3
"""P7 synthetic shape/memory sweep; never an end-to-end model claim."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
RESULTS = REPO / "benchmarks" / "results"
WEIGHT_MANIFEST = REPO / "benchmarks" / "weights" / "gpt2s-q.json"
SEQUENCE_LENGTHS = (150, 512, 2048, 8192)
A100_80_GIB = 80 * (1 << 30)
GPT2_LOOKUPS_T150 = 16_944_000


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=REPO, text=True).strip()


def dense_parameter_count(profile: dict[str, Any]) -> int:
    d = profile["d_model"]
    q_dim = profile["n_heads"] * profile["head_dim"]
    kv_dim = profile["n_kv_heads"] * profile["head_dim"]
    attention = d * q_dim + 2 * d * kv_dim + q_dim * d
    ffn = profile["ffn_matrices"] * d * profile["d_ff"]
    embeddings = profile["vocab"] * d * (1 if profile["tied_embeddings"] else 2)
    positions = profile.get("n_positions", 0) * d
    # Norm/bias vectors are included.  They are immaterial to scale but make
    # the synthetic dense count internally complete.
    vectors_per_layer = profile["vectors_per_layer"] * d
    final_vectors = profile["final_vectors"] * d
    return (
        profile["layers"] * (attention + ffn + vectors_per_layer)
        + embeddings
        + positions
        + final_vectors
    )


def profile_rows(gpt2_total_elems: int) -> list[dict[str, Any]]:
    return [
        {
            "name": "gpt2-small",
            "architecture": "dense-mha",
            "status": "measured-e2e-shape",
            "layers": 12,
            "d_model": 768,
            "d_ff": 3072,
            "n_heads": 12,
            "n_kv_heads": 12,
            "head_dim": 64,
            "vocab": 50_257,
            "n_positions": 1024,
            "experts": 1,
            "top_k": 1,
            "total_parameters": gpt2_total_elems,
            "active_parameters": gpt2_total_elems,
            "parameter_source": "frozen gpt2s-q.json total_elems",
        },
        {
            "name": "llama-class-8b-dense-gqa",
            "architecture": "synthetic-dense-gqa",
            "status": "analytic-projection-only",
            "layers": 32,
            "d_model": 4096,
            "d_ff": 14_336,
            "n_heads": 32,
            "n_kv_heads": 8,
            "head_dim": 128,
            "vocab": 128_256,
            "experts": 1,
            "top_k": 1,
            "ffn_matrices": 3,
            "tied_embeddings": False,
            "vectors_per_layer": 2,
            "final_vectors": 1,
            "parameter_source": "closed-form representative Llama-class shape",
        },
        {
            "name": "gpt-oss-20b-moe-active",
            "architecture": "synthetic-moe-gqa",
            "status": "analytic-projection-only",
            "layers": 24,
            "d_model": 2880,
            "n_heads": 64,
            "n_kv_heads": 8,
            "head_dim": 64,
            "vocab": 201_088,
            "experts": 32,
            "top_k": 4,
            "total_parameters": 20_900_000_000,
            "active_parameters": 3_600_000_000,
            "native_weight_bits": 4,
            "parameter_source": "docs/scaling-note.md planning profile",
        },
    ]


def derive_profile(profile: dict[str, Any]) -> dict[str, Any]:
    row = dict(profile)
    if "total_parameters" not in row:
        row["total_parameters"] = dense_parameter_count(row)
        row["active_parameters"] = row["total_parameters"]
    total = row["total_parameters"]
    active = row["active_parameters"]
    ld = row["layers"] * row["d_model"]
    row.update(
        {
            "active_parameter_fraction": active / total,
            "committed_weight_bytes_i16": 2 * total,
            "active_weight_bytes_i16": 2 * active,
            "native_weight_bytes_nominal": total * row.get("native_weight_bits", 16) // 8,
            "correction_driver_layers_times_d": ld,
            "relative_correction_driver_vs_gpt2": ld / (12 * 768),
            "projected_lookup_count_t150": round(GPT2_LOOKUPS_T150 * ld / (12 * 768)),
            "gqa_kv_fraction_vs_mha": row["n_kv_heads"] / row["n_heads"],
        }
    )
    sweep = []
    for sequence_length in SEQUENCE_LENGTHS:
        kv = (
            2
            * row["layers"]
            * sequence_length
            * row["n_kv_heads"]
            * row["head_dim"]
            * 2
        )
        residual_seams = row["layers"] * sequence_length * row["d_model"] * 2
        static_plus_state = row["committed_weight_bytes_i16"] + kv + residual_seams
        sweep.append(
            {
                "sequence_length": sequence_length,
                "kv_cache_bytes_i16": kv,
                "residual_seam_bytes_i16": residual_seams,
                "static_weights_plus_linear_state_bytes_i16": static_plus_state,
                "fits_a100_80gib_before_protocol_workspace": static_plus_state < A100_80_GIB,
            }
        )
    row["sequence_sweep"] = sweep
    for key in (
        "ffn_matrices",
        "tied_embeddings",
        "vectors_per_layer",
        "final_vectors",
        "n_positions",
    ):
        row.pop(key, None)
    return row


def build_report(resident_path: Path, manifest_path: Path = WEIGHT_MANIFEST) -> dict[str, Any]:
    resident = json.loads(resident_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (
        resident.get("milestone") != "P7-integrated-resident"
        or resident.get("git_dirty")
        or not resident.get("accepted")
        or resident.get("t_prefill") != 100
        or resident.get("n_decode") != 50
    ):
        raise ValueError("shape sweep requires a clean accepted full resident result")
    profiles = [derive_profile(p) for p in profile_rows(int(manifest["total_elems"]))]
    gpt2 = profiles[0]
    checks = {
        "gpt2_manifest_elements_match_binary_bytes": (
            manifest_path.with_name("gpt2s-q.bin").stat().st_size
            == 2 * manifest["total_elems"]
        ),
        "gpt2_profile_matches_manifest_shape": (
            gpt2["layers"] == manifest["model"]["L"]
            and gpt2["d_model"] == manifest["model"]["d"]
            and gpt2["d_ff"] == manifest["model"]["d_ff"]
            and gpt2["vocab"] == manifest["model"]["vocab"]
        ),
        "all_linear_state_rows_monotone": all(
            all(
                a["static_weights_plus_linear_state_bytes_i16"]
                < b["static_weights_plus_linear_state_bytes_i16"]
                for a, b in zip(p["sequence_sweep"], p["sequence_sweep"][1:])
            )
            for p in profiles
        ),
        "gqa_reduces_kv_vs_mha": all(
            p["gqa_kv_fraction_vs_mha"] < 1
            for p in profiles
            if "gqa" in p["architecture"]
        ),
        "moe_active_weights_less_than_total": (
            profiles[2]["active_weight_bytes_i16"]
            < profiles[2]["committed_weight_bytes_i16"]
        ),
    }
    if not all(checks.values()):
        raise AssertionError(f"shape/memory validation failed: {checks}")
    return {
        "report_schema_version": 1,
        "milestone": "P7-shape-memory-sweep",
        "date": dt.date.today().isoformat(),
        "git_sha": git("rev-parse", "--short", "HEAD"),
        "git_dirty": bool(git("status", "--porcelain", "--untracked-files=no")),
        "source_resident_result": str(resident_path.relative_to(REPO)),
        "source_resident_peak_device_bytes": resident["accelerator_proving"][
            "peak_device_bytes"
        ],
        "source_resident_workspace_after_cleanup_bytes": resident[
            "accelerator_workspace_device_bytes_after_cleanup"
        ],
        "sequence_lengths": list(SEQUENCE_LENGTHS),
        "profiles": profiles,
        "validation": checks,
        "scope": {
            "synthetic_shape_memory_only": True,
            "non_gpt2_end_to_end": False,
            "non_gpt2_frontends_implemented": False,
            "proof_time_projected": False,
            "proof_peak_memory_projected": False,
            "model_config_api_introduced": False,
            "purpose": "validate linear state and active/total-weight scaling formulas only",
        },
    }


def latest_resident() -> Path:
    rows = []
    for path in RESULTS.glob("p7-integrated-resident-*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if data.get("milestone") == "P7-integrated-resident" and not data.get("git_dirty", True):
            rows.append(path)
    if not rows:
        raise SystemExit("no clean full P7-integrated-resident JSON")
    return max(rows, key=lambda p: p.stat().st_mtime)


def unique_path(label: str, date: str, sha: str) -> Path:
    first = RESULTS / f"{label}-{date}-{sha}.json"
    if not first.exists():
        return first
    for index in range(1, 1000):
        candidate = RESULTS / f"{label}-{date}-{sha}-{index}.json"
        if not candidate.exists():
            return candidate
    raise SystemExit("could not allocate append-only shape/memory result path")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resident-result", type=Path)
    parser.add_argument("--write-json", action="store_true")
    args = parser.parse_args()
    resident = args.resident_result or latest_resident()
    if not resident.is_absolute():
        resident = REPO / resident
    report = build_report(resident.resolve())
    print(json.dumps(report, indent=2, sort_keys=True))
    if args.write_json:
        path = unique_path("p7-shape-memory-sweep", report["date"], report["git_sha"])
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
