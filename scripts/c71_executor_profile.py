#!/usr/bin/env python3
"""Public executor operation census; no weights, CUDA, replay or timing credit."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path


ADMITTED_PLAN_SHA256 = "a26a68972307e17b85086791a1c4870ae66b90a905922472a391267574a8fdf5"


def context_census(context):
    sources, steps = context["sources"], context["steps"]
    if [source["id"] for source in sources] != list(range(3471)) or len(steps) != 2328:
        raise ValueError("admitted source/producer census differs")
    histograms = {step["parameters"]["histogram"] for step in steps
                  if step["kind"] in ("gelu", "softmax", "softcap")}
    cuts = {source["id"] for source in sources
            if source["name"] == "X/global/embedding_scale"
            or source["name"].startswith("X/") and source["name"].endswith("/layer_scalar_mul")}
    frozen = histograms | cuts | set(context["kv_sources"])
    scores = {step["outputs"][0] for step in steps if step["kind"] == "qk"}

    def multiplicity(step):
        score_rne = step["kind"] == "rne" and step["inputs"][0] in scores
        return 32 if step["kind"] in ("qk", "softmax") or score_rne else 1

    inference = Counter()
    replay = Counter()
    replay_histograms = set()
    # scan_inner targets every A source. Thus each unfrozen producer output
    # selects its producer; dependency traversal cannot add an omitted step
    # because all of that step's outputs would already belong to frozen.
    for step in steps:
        kind = step["kind"]
        output = sources[step["outputs"][-1] if kind == "norm" else step["outputs"][0]]
        rows = 50 if kind in ("argmax", "softcap") or output["rows"] == 50 else min(150, output["rows"])
        if kind != "embedding":
            inference[kind] += rows * multiplicity(step)
        if any(source not in frozen for source in step["outputs"]):
            if kind != "embedding":
                replay[kind] += multiplicity(step)
            if kind in ("gelu", "softcap", "softmax"):
                replay_histograms.add(step["parameters"]["histogram"])
    # padding_word admits only the seven attention/softmax rectangles. U8/I16
    # padding uploads have no flag; i64 raw score/E/Z use one pointwise call
    # per head. Other flattened RMS C/S source rows are never query padding.
    padded_i64 = scores | {step["parameters"][key] for step in steps
                          if step["kind"] == "softmax" for key in ("exponential", "denominator")}
    padding_flags = sum((sources[source]["rows"] + 255) // 256
                        for source in padded_i64 if source not in frozen)
    inference_flags = sum(inference.values()) + len(histograms)
    replay_flags = sum(replay.values()) + len(replay_histograms) + padding_flags
    assert (len(cuts), len(histograms), len(frozen)) == (61, 121, 302)
    assert (inference_flags, replay_flags, padding_flags) == (1185770, 13667, 5760)
    return {
        "old_tokens": context["old_tokens"],
        "inference_numeric_calls_by_kind": dict(sorted(inference.items())),
        "inference_histogram_seals": len(histograms),
        "inference_numeric_flag_uses": inference_flags,
        "inference_numeric_launches": inference_flags + 50,
        "inference_flag_and_token_d2h_bytes": inference_flags * 4 + 50 * 4,
        "all_targets_replay_numeric_calls_by_kind": dict(sorted(replay.items())),
        "all_targets_replay_histogram_seals": len(replay_histograms),
        "all_targets_replay_public_padding_numeric_calls": padding_flags,
        "all_targets_replay_numeric_flag_uses": replay_flags,
        "all_targets_replay_removed_flag_allocations_after_warmup": replay_flags,
        "initial_a_reconstructions": 512,
        "initial_a_all_targets_replay_flag_uses": 512 * replay_flags,
        "frozen_sources": len(frozen),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("oracle_plan", type=Path)
    args = parser.parse_args()
    body = args.oracle_plan.read_bytes()
    digest = hashlib.sha256(body).hexdigest()
    if digest != ADMITTED_PLAN_SHA256:
        raise ValueError("oracle plan is not the verified archived admitted-Gamma plan")
    plan = json.loads(body)
    result = {
        "schema": "c71-executor-operation-census-v1",
        "oracle_plan_sha256": digest,
        "credit": False, "gpu_execution": False, "analytic_only": True,
        "contexts": [context_census(context) for context in plan["contexts"]],
        "retained_numeric_flag_capacity_bytes": 256,
        "added_host_owner_bytes": 8,
        "numeric_flag_registry_slots": 1,
        "required_numeric_completion_fences_and_flag_downloads_unchanged": True,
        "inference_removed_flag_allocations_from_fresh_owner": 1185769,
        "scope": "Admitted-Gamma scalar generation and a scan requesting all A sources; partial consumers have their own pruned DAG. Counts are not CUDA timings or a complete proof measure.",
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
