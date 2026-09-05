from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "scripts" / "c7_d126_gemma_qspec_dag.py"
MANIFEST = ROOT / "manifests" / "c7-d126-gemma31b-qspec-dag-v1.json"


def load_module():
    spec = importlib.util.spec_from_file_location("c7_d126_gemma_qspec_dag", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def rejected(module, manifest: dict) -> None:
    try:
        module.compile_manifest(manifest)
    except module.DagManifestError:
        return
    raise AssertionError("invalid Gemma-31B QSPEC/DAG manifest was accepted")


def test_exact_operator_tensor_flow_expands_with_cross_execution_edges() -> None:
    module = load_module()
    manifest = load_manifest()
    report = module.compile_manifest(manifest)
    executions = module._expand_schedule(manifest["workload_schedule"])
    nodes = module.expand_dag(manifest, executions)

    assert report["status"] == "BLOCKED"
    assert report["classification"] == "operator-tensor-flow-dag"
    assert report["census"] == module.EXPECTED_CENSUS
    assert report["census"]["norm_weighted_element_equations"] == 313_344_000
    assert report["census"]["final_norm_weighted_element_equations"] == 801_024
    assert len(nodes) == 79_963
    assert sum(len(node.dependencies) for node in nodes) == 101_322
    assert all(dependency < node.id for node in nodes for dependency in node.dependencies)

    by_key = {(node.execution, node.layer, node.operation): node for node in nodes}
    assert by_key[(0, None, "token_input")].dependencies == ()
    assert by_key[(0, None, "token_input")].public_inputs == (
        "prompt_token_ids/workload_sha256/"
        "70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b",
    )
    for execution in range(1, 51):
        assert by_key[(execution, None, "token_input")].dependencies == (
            by_key[(execution - 1, None, "argmax")].id,
        )
    for layer in range(60):
        assert len(by_key[(0, layer, "kv_cache_append")].dependencies) == 2
        for execution in range(1, 51):
            current = by_key[(execution, layer, "kv_cache_append")]
            previous = by_key[(execution - 1, layer, "kv_cache_append")]
            assert current.dependencies[-1] == previous.id

    global_v = by_key[(0, 5, "v_source")]
    assert global_v.dependencies == (by_key[(0, 5, "k_proj")].id,)
    assert global_v.weight_terminal is None
    assert global_v.activation_scale_owner is None
    local_v = by_key[(0, 4, "v_source")]
    assert local_v.weight_terminal == "weight/layer/4/v_proj"
    assert local_v.activation_scale_owner == "layer/4/v_source"

    last_row = by_key[(0, None, "last_row_select")]
    assert last_row.dependencies == (by_key[(0, None, "final_rms")].id,)
    assert by_key[(0, None, "lm_head")].dependencies == (last_row.id,)
    assert by_key[(0, None, "embedding_scale")].public_inputs == (
        "embedding_scale/bf16/0x4293=147/2",
    )
    assert by_key[(0, 4, "q_rope")].public_inputs == ("position_ids/execution/0",)
    assert by_key[(0, 4, "attention_mask_add")].public_inputs == (
        "attention_mask/sliding_attention/execution/0",
    )
    assert by_key[(0, 5, "attention_mask_add")].public_inputs == (
        "attention_mask/full_attention/execution/0",
    )
    assert by_key[(0, 4, "layer_scalar_mul")].public_inputs == (
        "model.language_model.layers.4.layer_scalar",
    )
    terminal_owners = frozenset(node.weight_terminal for node in nodes if node.weight_terminal)
    assert terminal_owners == module._canonical_weight_terminal_owners()


def test_quantization_and_no_pruning_guards_reject_drift() -> None:
    module = load_module()
    manifest = load_manifest()

    wrong_rounding = copy.deepcopy(manifest)
    wrong_rounding["quantization"]["rounding"] = "round-half-away-from-zero"
    rejected(module, wrong_rounding)

    witness_scale = copy.deepcopy(manifest)
    witness_scale["quantization"]["activation_exponents_by_operation"] = {}
    rejected(module, witness_scale)

    pruned_mask = copy.deepcopy(manifest)
    pruned_mask["mathematical_semantics"]["attention_mask"] = "skip forbidden cells"
    rejected(module, pruned_mask)

    lost_cache_edge = copy.deepcopy(manifest)
    lost_cache_edge["compact_program"]["layer"][9][2] = "k_rope+v_norm"
    rejected(module, lost_cache_edge)

    for path, value in (
        (("identity", "text_only"), False),
        (("model_config", "attention_bias"), True),
        (("quantization", "rounding_definition"), "nearest"),
        (("compact_program", "record_columns"), []),
        (("workload_schedule", "logits_to_keep_per_decision"), 0),
    ):
        drift = copy.deepcopy(manifest)
        drift[path[0]][path[1]] = value
        rejected(module, drift)

    malformed_program = copy.deepcopy(manifest)
    malformed_program["compact_program"]["layer"].append("ignored-by-old-validator")
    rejected(module, malformed_program)

    blocker_drift = copy.deepcopy(manifest)
    blocker_drift["blockers"][5] += "."
    rejected(module, blocker_drift)


def test_manifest_sha256_sidecar_is_canonical() -> None:
    module = load_module()
    digest = hashlib.sha256(MANIFEST.read_bytes()).hexdigest()
    assert MANIFEST.with_suffix(".sha256").read_text(encoding="ascii") == (
        f"{digest}  {MANIFEST.name}\n"
    )
    try:
        module._json_no_duplicates(b'{"same":1,"same":1}')
    except module.DagManifestError:
        pass
    else:
        raise AssertionError("duplicate JSON keys were accepted")
