#!/usr/bin/env python3
"""Regenerate P7 paper tables and dependency-free SVG figures from raw JSON."""

from __future__ import annotations

import argparse
import html
import importlib.util
import math
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
OUTPUT = REPO / "artifact" / "p7" / "generated"


def report_module():
    path = REPO / "scripts" / "report.py"
    spec = importlib.util.spec_from_file_location("p7_report_for_artifact", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def f(value: float, digits: int = 3) -> str:
    return f"{value:.{digits}f}"


def results_markdown(report: dict[str, Any]) -> str:
    resident = report["integrated_resident"]["run_of_record"]
    joined = report["integrated_resident"]["same_host_result"]
    native = report["gpu_native_inference"]["run_of_record"]
    if not resident or not joined or not native:
        raise ValueError("clean same-host resident/native result is required")
    gates = [
        ("Golden decode", resident["golden_decode_match"], "bit-exact"),
        ("Verifier", True, "accepted"),
        ("Flat decode cost", resident["flat_cost_gate"], f(resident["flat_cost_last_over_first"])),
        ("Packed response <=200 MB", resident["packed_response_bytes"] <= 200_000_000, str(resident["packed_response_bytes"])),
        ("Explicit device buffers after cleanup", resident["accelerator_resident_device_bytes_after_cleanup"] == 0, str(resident["accelerator_resident_device_bytes_after_cleanup"])),
        ("rho proof prefill <=10", joined["target_met"]["prefill"], f(joined["proof_rho"]["prefill"])),
        ("rho proof decode <=2", joined["target_met"]["decode"], f(joined["proof_rho"]["decode"])),
    ]
    timing_rows = [
        ("Native GPU prefill", native["prefill_s"], native["prefill_timing"]["mad_s"]),
        ("Native GPU decode50", native["decode_50_s"], native["decode_50_timing"]["mad_s"]),
        ("Resident witness prefill", resident["accelerator_witness"]["measurement_wall_s"], None),
        ("Resident witness response", resident["accelerator_response_witness"]["measurement_wall_s"], None),
        ("Proof core prefill", resident["prove_prefill_s"], resident["prove_prefill_timing"]["mad_s"]),
        ("Proof core response", resident["prove_response_s"], resident["prove_response_timing"]["mad_s"]),
        ("Proof core decode marginal", resident["prove_decode_marginal_s"], resident["prove_decode_marginal_timing"]["mad_s"]),
        ("Online-accounted response", resident["prover_online_accounted_response_s"], resident["prover_online_accounted_response_timing"]["mad_s"]),
        ("Full local response-session wall", resident["response_session_wall_s"], resident["response_session_wall_timing"]["mad_s"]),
        ("PCS commit (offline)", resident["pcs_commit_timing"]["median_s"], resident["pcs_commit_timing"]["mad_s"]),
        ("PCS open (online)", resident["pcs_open_timing"]["median_s"], resident["pcs_open_timing"]["mad_s"]),
        ("Accounted verifier", resident["verifier_accounted_s"], resident["verifier_accounted_timing"]["mad_s"]),
    ]
    lines = [
        "# P7 generated result tables",
        "",
        f"Resident source: `{resident['source']}`  ",
        f"Native source: `{native['source']}`",
        "",
        "## Gates",
        "",
        "| Gate | Verdict | Value |",
        "| --- | --- | ---: |",
    ]
    lines.extend(
        f"| {name} | {'PASS' if passed else 'FAIL'} | {value} |"
        for name, passed, value in gates
    )
    lines.extend(
        [
            "",
            "## Timings",
            "",
            "| Component | Median (s) | MAD (s) |",
            "| --- | ---: | ---: |",
        ]
    )
    lines.extend(
        f"| {name} | {f(median, 6)} | {f(mad, 6) if mad is not None else 'n/a'} |"
        for name, median, mad in timing_rows
    )
    comm = resident["communication"]
    lines.extend(
        [
            "",
            "## Communication and memory",
            "",
            "| Quantity | Bytes |",
            "| --- | ---: |",
            f"| Response transcript | {comm['response_bytes']} |",
            f"| PCS opening (included above) | {comm['pcs_opening_bytes']} |",
            f"| Packed public logits | {comm['public_logits_packed_bytes']} |",
            f"| Packed response total | {resident['packed_response_bytes']} |",
            f"| Representative peak device | {resident['accelerator_session']['peak_device_bytes']} |",
            f"| Workspace after cleanup | {resident['accelerator_workspace_device_bytes_after_cleanup']} |",
            f"| Explicit resident after cleanup | {resident['accelerator_resident_device_bytes_after_cleanup']} |",
            "",
            "Mock-PCG is the measured baseline and is not production-grade.",
            "",
        ]
    )
    return "\n".join(lines)


def svg_document(title: str, body: str, width: int, height: int) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">\n'
        '<style>text{font-family:system-ui,sans-serif;fill:#1f2937}.label{font-size:14px}'
        '.small{font-size:12px}.title{font-size:18px;font-weight:600}</style>\n'
        f'<rect width="100%" height="100%" fill="white"/>\n'
        f'<text class="title" x="20" y="28">{html.escape(title)}</text>\n{body}\n</svg>\n'
    )


def rho_svg(report: dict[str, Any]) -> str:
    joined = report["integrated_resident"]["same_host_result"]
    rows = [
        ("Prefill", joined["proof_rho"]["prefill"], joined["targets"]["prefill"]),
        ("Decode", joined["proof_rho"]["decode"], joined["targets"]["decode"]),
    ]
    max_log = max(math.log10(value) for _, value, _ in rows)
    body = []
    for index, (label, value, target) in enumerate(rows):
        y = 65 + index * 70
        width = 500 * math.log10(value) / max_log
        target_x = 170 + 500 * math.log10(target) / max_log
        body.extend(
            [
                f'<text class="label" x="20" y="{y + 18}">{label}</text>',
                f'<rect x="170" y="{y}" width="{width:.1f}" height="24" fill="#c2410c"/>',
                f'<line x1="{target_x:.1f}" y1="{y - 6}" x2="{target_x:.1f}" y2="{y + 30}" stroke="#166534" stroke-width="3"/>',
                f'<text class="small" x="{170 + width + 8:.1f}" y="{y + 17}">{value:.2f} (target {target:g})</text>',
            ]
        )
    body.append('<text class="small" x="170" y="205">Bar length is log10(rho); green line is the preregistered target.</text>')
    return svg_document("Resident proof rho — both targets fail", "\n".join(body), 820, 230)


def attribution_svg(report: dict[str, Any]) -> str:
    session = report["integrated_resident"]["run_of_record"]["accelerator_session"]
    parts = [
        ("CUDA kernels", session["kernel_s"], "#2563eb"),
        ("H2D", session["h2d_s"], "#7c3aed"),
        ("D2H", session["d2h_s"], "#db2777"),
        ("CPU residual", session["cpu_residual_s"], "#c2410c"),
    ]
    total = sum(value for _, value, _ in parts)
    x = 30.0
    body = []
    for label, value, color in parts:
        width = 740 * value / total
        body.append(f'<rect x="{x:.1f}" y="60" width="{width:.1f}" height="38" fill="{color}"/>')
        x += width
    for index, (label, value, color) in enumerate(parts):
        y = 130 + index * 24
        body.extend(
            [
                f'<rect x="30" y="{y - 12}" width="14" height="14" fill="{color}"/>',
                f'<text class="label" x="52" y="{y}">{label}: {value:.3f} s</text>',
            ]
        )
    body.append(
        f'<text class="small" x="30" y="240">Measurement wall {session["measurement_wall_s"]:.3f} s; '
        f'{session["synchronizations"]} synchronizations ({session["synchronization_s"]:.3f} s, included in CPU residual).</text>'
    )
    return svg_document("Representative resident response attribution", "\n".join(body), 820, 265)


def shape_csv(report: dict[str, Any]) -> str:
    sweep = report["shape_memory_sweep"]["run_of_record"]
    lines = [
        "model,status,total_parameters,active_parameters,committed_i16_bytes,active_i16_bytes,gqa_kv_fraction"
    ]
    for profile in sweep["profiles"]:
        lines.append(
            ",".join(
                str(value)
                for value in (
                    profile["name"],
                    profile["status"],
                    profile["total_parameters"],
                    profile["active_parameters"],
                    profile["committed_weight_bytes_i16"],
                    profile["active_weight_bytes_i16"],
                    profile["gqa_kv_fraction_vs_mha"],
                )
            )
        )
    return "\n".join(lines) + "\n"


def generated_outputs() -> dict[Path, str]:
    module = report_module()
    report = module.p7_report(module.DEFAULT_RESULTS)
    return {
        OUTPUT / "results.md": results_markdown(report),
        OUTPUT / "rho.svg": rho_svg(report),
        OUTPUT / "response-attribution.svg": attribution_svg(report),
        OUTPUT / "shape-memory.csv": shape_csv(report),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    outputs = generated_outputs()
    if args.check:
        stale = [path for path, value in outputs.items() if not path.exists() or path.read_text() != value]
        if stale:
            raise SystemExit("stale generated artifact outputs: " + ", ".join(str(p) for p in stale))
        print("P7 artifact outputs are current")
        return 0
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for path, value in outputs.items():
        path.write_text(value, encoding="utf-8")
        print(f"wrote {path.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
