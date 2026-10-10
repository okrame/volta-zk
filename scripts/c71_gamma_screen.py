#!/usr/bin/env python3
"""Bounded public Gamma/RMS screen; no weights, inference, tables or admission.

Prepare eight-recipe inputs, compile each with c71_calibration rms-programs
under the local per-invocation limits, then summarize the original compiler.
"""
import argparse
from collections import Counter
import copy
import hashlib
import json
from pathlib import Path
import subprocess

import c7_1_gemma_plan as plan
import c71_gkr_screen as gkr

ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "artifact/c7.1-pod/h100-components-20261009T194100Z/gamma-inputs"
OPS = ("and", "xor", "copy")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("x") as sink:
        json.dump(value, sink, indent=2, sort_keys=True)
        sink.write("\n")


def inputs(bundle):
    transfers = json.loads((bundle / "transfer-manifest.json").read_text())
    for entry in transfers:
        path = bundle / entry["path"]
        if path.stat().st_size != entry["bytes"] or sha(path) != entry["sha256"]:
            raise ValueError(f"retained Gamma input identity differs: {entry['path']}")
    documents = {name: json.loads((bundle / name).read_text()) for name in (
        "candidate.json", "oracle-plan-original.json", "recipes-original.json",
        "ledger-original.json", "admission.json", "ingest-original.json")}
    evidence = {e["path"]: e["sha256"] for e in documents["admission.json"]["evidence"]}
    for entry in transfers:
        if entry["source"] in evidence and evidence[entry["source"]] != entry["sha256"]:
            raise ValueError("Gamma transfer disagrees with original admission")
    candidate = documents["candidate.json"]
    ledger = documents["ledger-original.json"]
    recipes = documents["recipes-original.json"]
    if not documents["admission.json"]["gamma_admitted"]:
        raise ValueError("baseline Gamma not admitted")
    if ledger["candidate_sha256"] != sha(bundle / "candidate.json"):
        raise ValueError("ledger candidate identity differs")
    if ledger["table_sha256"] != sha(bundle / "tables.bin"):
        raise ValueError("ledger table identity differs")
    if ledger["recipe_digest"] != recipes["recipe_digest"]:
        raise ValueError("ledger recipes differ")
    if candidate["weight_exponents_by_tensor"] != documents["ingest-original.json"]["weight_exponents_by_tensor"]:
        raise ValueError("baseline weight scale identity differs")
    return documents, transfers


def norms_and_keys(candidate, oracle):
    norms = [step for step in oracle["steps"] if step["kind"] == "norm"]
    weights = {row["id"]: row["name"] for row in oracle["weights"]}
    a, w = candidate["activation_exponents_by_source"], candidate["weight_exponents_by_tensor"]
    keys = []
    for norm in norms:
        p = norm["parameters"]
        ew = 0 if p["weight"] is None else w[weights[p["weight"]]]
        keys.append((p["columns"], a[str(norm["inputs"][0])], ew,
                     a[str(norm["outputs"][-1])], p["weight"] is not None))
    return norms, keys


def candidates(baseline, oracle):
    norms, _ = norms_and_keys(baseline, oracle)
    ins = {str(n["inputs"][0]) for n in norms}
    outs = {str(n["outputs"][-1]) for n in norms}
    fixed = {"0"} | {str(s["parameters"]["probability"])
                     for s in oracle["steps"] if s["kind"] == "softmax"}
    result = {"admitted": copy.deepcopy(baseline)}
    for name, ids, change in (
        ("rms-output-finer-one", outs, lambda e: e - 1),
        ("rms-even-finer", ins | outs, lambda e: e - e % 2),
        ("rms-even-coarser", ins | outs, lambda e: e + e % 2),
        ("rms-output-coarser-control", outs, lambda e: e + 1),
    ):
        trial = copy.deepcopy(baseline)
        for source in ids - fixed:
            trial["activation_exponents_by_source"][source] = change(
                trial["activation_exponents_by_source"][source])
        assert trial["weight_exponents_by_tensor"] == baseline["weight_exponents_by_tensor"]
        assert all(trial["activation_exponents_by_source"][s] == baseline["activation_exponents_by_source"][s]
                   for s in fixed)
        result[name] = trial
    return result


def public_recipe(key):
    return {"columns": key[0], "exponents": list(key[1:4]), "weighted": key[4]}


def recipe_key(row):
    return (row["columns"], *row["exponents"], row["weighted"])


def prepare(bundle, output):
    docs, provenance = inputs(bundle)
    baseline = docs["candidate.json"]
    oracle = docs["oracle-plan-original.json"]["contexts"][0]
    _, original = norms_and_keys(baseline, oracle)
    assert [list(k[1:4]) for k in original] == docs["recipes-original.json"]["rms"]
    variants = candidates(baseline, oracle)
    output.mkdir()
    (output / "candidates").mkdir()
    (output / "programs").mkdir()
    all_keys = set()
    for name, variant in variants.items():
        candidate_path = output / "candidates" / f"{name}.json"
        if name == "admitted":
            with candidate_path.open("xb") as sink:
                sink.write((bundle / "candidate.json").read_bytes())
        else:
            write(candidate_path, variant)
        all_keys.update(norms_and_keys(variant, oracle)[1])
    ordered = sorted(all_keys)
    batches = []
    for ordinal, start in enumerate(range(0, len(ordered), 8)):
        name = f"programs/batch-{ordinal:03}.input.json"
        write(output / name, [public_recipe(k) for k in ordered[start:start + 8]])
        batches.append({"input": name, "sha256": sha(output / name),
                        "output": name.replace(".input.", ".output.")})
    write(output / "manifest.json", {"schema": "volta-c71-gamma-screen-inputs-v1",
        "credit": False, "gamma_admitted": False, "baseline_admitted": True,
        "retained_inputs": provenance, "bundle": str(bundle.relative_to(ROOT)),
        "baseline_candidate_sha256": sha(bundle / "candidate.json"),
        "batches": batches, "unique_recipes": len(ordered),
        "candidates": {name: {"path": f"candidates/{name}.json",
            "sha256": sha(output / "candidates" / f"{name}.json")} for name in variants}})


def aggregate(keys, blueprints, baseline_rms):
    cohorts = plan.gemma_weight_cohorts(plan.pinned_private_tensors())
    norms = plan.rms_statistic_cohorts(cohorts)
    assert len(norms) == len(keys) == 421
    profiles = list(dict.fromkeys(keys))
    profile_of = [profiles.index(k) for k in keys]
    shapes = [(n["statistic_rows"], n["columns"]) for n in norms]
    cells = sum(r * c for r, c in shapes)
    padded = 1 << (cells - 1).bit_length()
    assert cells == baseline_rms["live_cells"] and padded == baseline_rms["padded_cells"]
    intervals = [[] for _ in profiles]
    for tensor, _, _, rows, cols, offset in plan.dyadic_weight_layout(shapes):
        intervals[profile_of[tensor]].append((offset, offset + rows * cols))
    intervals = [gkr.merge(v) for v in intervals]
    depth = max(blueprints[k]["depth"] for k in profiles)
    totals = []
    widths = [128]
    layer_counts = []
    for k in profiles:
        rows = blueprints[k]["layers"]
        totals.append({op: sum(row[op] for row in rows) +
                       (depth - len(rows) if op == "copy" else 0) for op in OPS})
    for d in range(depth):
        rows = [blueprints[k]["layers"][d] if d < blueprints[k]["depth"]
                else {"width": 1, "and": 0, "xor": 0, "copy": 1} for k in profiles]
        width = max(row["width"] for row in rows)
        widths.append(1 << (width - 1).bit_length())
        layer_counts.append({op: sum(row[op] for row in rows) for op in OPS})
    ops, first, pairs_all = Counter(), Counter(), 0
    supports = []
    for r in range(padded.bit_length() - 1):
        half = padded >> (r + 1)
        pairs = [gkr.modulo_union_length(spans, half) for spans in intervals]
        supports.append(pairs)
        pairs_all += sum(pairs)
        for p, count in enumerate(pairs):
            for op in OPS:
                ops[op] += count * totals[p][op]
                if r == 0:
                    first[op] += count * totals[p][op]
    arithmetic = gkr.factored_arithmetic(ops, depth * pairs_all)
    saved = 7 * (first["and"] + first["xor"]) + 2 * first["copy"]
    selected = dict(arithmetic)
    selected["Fp3_mul"] -= saved
    selected["Fp3_add"] += 5 * first["and"] + 2 * first["copy"]
    selected["Fp3_sub"] += first["and"] - first["xor"]
    selected["Fp3_neg"] -= first["xor"]
    cell_bits = padded.bit_length() - 1
    rows = sum(4 * cell_bits + 6 * (w.bit_length() - 1) + 3 for w in widths[:-1]) + 1
    return {"programs": len(profiles), "depth": depth, "live_cells": cells,
        "padded_cells": padded, "joint_widths": widths,
        "arithmetic_bits_min_max": [min(blueprints[k]["arithmetic_bits"] for k in profiles),
                                   max(blueprints[k]["arithmetic_bits"] for k in profiles)],
        "original_frame_callbacks": cells * cell_bits * depth,
        "coefficient_core_before_first_round_Fp3": arithmetic,
        "selected_coefficient_core_Fp3": selected, "Boolean_first_round_products_saved": saved,
        "compiled_program_owned_bytes": sum(blueprints[k]["compiled_program_owned_bytes"] for k in profiles),
        "maximum_compiled_single_program_owned_bytes": max(blueprints[k]["compiled_program_owned_bytes"] for k in profiles),
        "maximum_layer_edges_logical_bytes": 48 * max(sum(v.values()) for v in layer_counts),
        "RMS_checkpoint_original_PYS_bytes": baseline_rms["compact_original_PYS_candidate"]["payload_and_metadata_bytes"],
        "GKR_correlation_rows_only": rows, "complete_rms_rows": None,
        "full_A_reconstructions": 512, "A_flat_dimension": 34,
        "supports": supports, "layer_counts": layer_counts}


def numerical_fixture(base_keys, trial_keys):
    checked, rejected, changed, maximum_error = 0, 0, 0, 0.0
    for base, trial in zip(base_keys, trial_keys):
        d, ex, ew, ey, weighted = base
        source = [4 * ((i % 17) - 8) for i in range(d)]
        weights = [1 + i % 3 for i in range(d)] if weighted else [1] * d
        delta = trial[1] - ex
        inputs = [x // (1 << delta) if delta >= 0 else x * (1 << -delta) for x in source]
        assert all(x * 2.0 ** ex == y * 2.0 ** trial[1] for x, y in zip(source, inputs))
        s0, s1 = sum(x * x for x in source), sum(x * x for x in inputs)
        for i in (0, d // 2, d - 1):
            try:
                y0 = plan.rms_rne_i16(source[i] * weights[i], s0, d, ex, ew, ey)
                y1 = plan.rms_rne_i16(inputs[i] * weights[i], s1, d, *trial[1:4])
            except ValueError:
                rejected += 1
                continue
            checked += 1
            difference = abs(y0 * 2.0 ** ey - y1 * 2.0 ** trial[3])
            maximum_error = max(maximum_error, difference)
            changed += difference != 0
            # Fixed physical inputs and W imply the same real RMS result;
            # independent exact RNE may differ by at most half of each step.
            assert difference <= 0.5 * (2.0 ** ey + 2.0 ** trial[3])
    return {"scope": "synthetic exact-dyadic physical input; Python integer RMS only",
        "checked_outputs": checked, "overflow_rejections": rejected,
        "changed_dequantized_outputs": changed, "max_abs_dequantized_difference": maximum_error,
        "RNE_error_bound_checked": True, "real_weights": False,
        "token_quality_checked": False, "admission_credit": False}


def summarize(bundle, directory, output):
    docs, _ = inputs(bundle)
    manifest = json.loads((directory / "manifest.json").read_text())
    blueprints = {}
    for batch in manifest["batches"]:
        if sha(directory / batch["input"]) != batch["sha256"]:
            raise ValueError("public program batch mutated")
        expected = json.loads((directory / batch["input"]).read_text())
        result = json.loads((directory / batch["output"]).read_text())
        assert result["credit"] is False and result["gamma_admitted"] is False
        assert [recipe_key(row) for row in result["programs"]] == [recipe_key(row) for row in expected]
        for row in result["programs"]:
            key = recipe_key(row)
            assert key not in blueprints
            assert [int(v) for v in row["coefficients"]] == list(plan.rms_integer_coefficients(*key[:4]))
            blueprints[key] = row
    oracle = docs["oracle-plan-original.json"]["contexts"][0]
    baseline = docs["candidate.json"]
    base_keys = norms_and_keys(baseline, oracle)[1]
    historical = docs["ledger-original.json"]["contexts"][0]
    rows = {}
    for name, entry in manifest["candidates"].items():
        path = directory / entry["path"]
        assert sha(path) == entry["sha256"]
        candidate = json.loads(path.read_text())
        assert candidate["weight_exponents_by_tensor"] == baseline["weight_exponents_by_tensor"]
        keys = norms_and_keys(candidate, oracle)[1]
        row = aggregate(keys, blueprints, historical["rms"])
        if name == "admitted":
            assert row["supports"] == historical["rms"]["public_supported_pairs_by_round_and_profile"]
            assert row["layer_counts"] == [{op: l[op] for op in OPS} for l in historical["rms"]["layers"]]
            assert row["coefficient_core_before_first_round_Fp3"] == historical["rms_structural_support"]["factored_arithmetic_after_structural_support_pruning"]
        row.pop("supports")
        row.pop("layer_counts")
        row["candidate_sha256"] = entry["sha256"]
        row["changed_activation_scales"] = sum(
            candidate["activation_exponents_by_source"][k] != e
            for k, e in baseline["activation_exponents_by_source"].items())
        row["numerical_fixture"] = numerical_fixture(base_keys, keys)
        rows[name] = row
    denominator = rows["admitted"]["selected_coefficient_core_Fp3"]["Fp3_mul"]
    for row in rows.values():
        row["selected_coefficient_core_mul_reduction_fraction"] = 1 - row["selected_coefficient_core_Fp3"]["Fp3_mul"] / denominator
    ranking = sorted((name for name in rows if name != "admitted"),
                     key=lambda name: rows[name]["selected_coefficient_core_Fp3"]["Fp3_mul"])
    write(output, {"schema": "volta-c71-gamma-screen-v1", "credit": False,
        "gamma_admitted": False, "complete_work": False, "complete_physical_peak": False,
        "gpu_execution": False, "classification": "public compiler and reduced numeric screening",
        "source_git_sha": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "git_dirty": bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT)),
        "input_manifest_sha256": sha(directory / "manifest.json"),
        "program_outputs_sha256": {b["output"]: sha(directory / b["output"]) for b in manifest["batches"]},
        "baseline_identity_preserved": sha(bundle / "candidate.json") == manifest["baseline_candidate_sha256"],
        "candidate_ranking_by_selected_partial_RMS_multiplications": ranking, "candidates": rows,
        "invariants": {"W_exponents_and_bytes": "unchanged target; packed absent locally",
            "architecture_workload_numeric_recipes": "fixed; activation scales change relation",
            "A_layout_and_byte_lengths": [13154672538, 14334320538, 15513968538],
            "A_domain": 34, "W_domain": 35, "initial_A_reconstructions": 512,
            "PCS_configuration_and_byte_codec": "unchanged; no per-token proof or PCS",
            "RMS_checkpoint_PYS_bytes": 2023511878},
        "remaining_validation": ["complete compiler recipes/aliases in all three contexts",
            "certified tables for changed recipes; unchanged bodies may be reused only by exact recipe identity",
            "real-weight overflow and numerical drift on fixed teacher-forced inputs in O=0/150/300",
            "dequantized layer RMS/max error, attention and logits compared with admitted Gamma and binary64 reference",
            "nonzero/saturation fractions and argmax margins; predeclare acceptable quality thresholds before admission",
            "two complete integer replays, independent exact trace comparison, final KV and all five admission checks",
            "generated tokens may change; no inherited admission, security-bound recalculation if public program envelope changes",
            "recompute complete correlation reservation and composed public security/resource bounds",
            "hardware proof time, PCG reservation, complete host/device peak and packed replay capacities"]})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "summarize"))
    parser.add_argument("--bundle", type=Path, default=BUNDLE)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.mode == "prepare":
        prepare(args.bundle, args.directory)
    else:
        if args.output is None:
            parser.error("summarize requires --output")
        summarize(args.bundle, args.directory, args.output)
