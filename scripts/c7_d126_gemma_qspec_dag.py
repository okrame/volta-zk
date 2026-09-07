#!/usr/bin/env python3
"""Compile the compact Gemma-31B quantization and semantic-DAG declaration."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifests" / "c7-d126-gemma31b-qspec-dag-v1.json"
MANIFEST_SHA256 = MANIFEST.with_suffix(".sha256")
TERMINAL_MANIFEST = ROOT / "manifests" / "c7-d126-gemma31b-terminals-v1.csv"
TERMINAL_MANIFEST_SHA256 = "a9f4bc9db356c4f40c8f34d1af11367329532ffea53796dfbe2877177c6a9dfa"

LAYER_PROGRAM = (
    ("input_rms", 1, "layer_input", "norm_bundle", "layer"),
    ("q_proj", 1, "input_rms", "matrix", "layer"),
    ("q_norm", 1, "q_proj", "norm_bundle", "layer"),
    ("q_rope", 1, "q_norm", "none", "layer"),
    ("k_proj", 1, "input_rms", "matrix", "layer"),
    ("k_norm", 1, "k_proj", "norm_bundle", "layer"),
    ("k_rope", 1, "k_norm", "none", "layer"),
    ("v_source", 1, "local:input_rms;global:k_proj-alias", "matrix-local-only", "layer-local-only"),
    ("v_norm", 1, "v_source;parameter-free", "none", "layer"),
    ("kv_cache_append", 2, "k_rope+v_norm[+same-layer-prior-execution-kv_cache_append]", "none", "none"),
    ("qk_matmul", 2, "q_rope+kv_cache_append", "none", "layer"),
    ("attention_mask_add", 1, "qk_matmul;reuse-qk-scale", "none", "none"),
    ("softmax", 1, "attention_mask_add", "none", "layer"),
    ("pv_matmul", 2, "softmax+kv_cache_append", "none", "layer"),
    ("o_proj", 1, "pv_matmul", "matrix", "layer"),
    ("post_attention_rms", 1, "o_proj", "norm_bundle", "layer"),
    ("attention_residual_add", 2, "layer_input+post_attention_rms", "none", "layer"),
    ("pre_ffw_rms", 1, "attention_residual_add", "norm_bundle", "layer"),
    ("gate_proj", 1, "pre_ffw_rms", "matrix", "layer"),
    ("gelu_tanh", 1, "gate_proj", "none", "layer"),
    ("up_proj", 1, "pre_ffw_rms", "matrix", "layer"),
    ("gate_up_mul", 2, "gelu_tanh+up_proj", "none", "layer"),
    ("down_proj", 1, "gate_up_mul", "matrix", "layer"),
    ("post_ffw_rms", 1, "down_proj", "norm_bundle", "layer"),
    ("ffw_residual_add", 2, "attention_residual_add+post_ffw_rms", "none", "layer"),
    ("layer_scalar_mul", 1, "ffw_residual_add;public-layer-scalar", "none", "layer"),
)
PREFIX_PROGRAM = (
    ("token_input", 0, "root-for-prefill;previous-argmax-after-prefill", "none", "none"),
    ("embedding_lookup", 1, "token_input", "tied_embedding", "none"),
    ("embedding_scale", 1, "embedding_lookup", "none", "global"),
)
SUFFIX_PROGRAM = (
    ("final_rms", 1, "last-layer-scalar", "final_norm", "global"),
    ("last_row_select", 1, "final_rms;select the last query row", "none", "none"),
    ("lm_head", 1, "last_row_select", "tied_embedding", "global"),
    ("final_tanh_softcap", 1, "lm_head", "none", "global"),
    ("argmax", 1, "final_tanh_softcap", "none", "none"),
)
EXPECTED_CENSUS = {
    "executions": 51,
    "operator_tensor_flow_nodes": 79_963,
    "tensor_dependency_edges": 101_322,
    "layer_private_matrix_invocations": 20_910,
    "total_private_matrix_invocations": 20_960,
    "weight_terminal_linked_op_invocations": 39_421,
    "fixed_activation_scale_owners": 1_434,
    "eager_nonpruned_score_cells": 31_248_000,
    "qk_macs": 9_332_736_000,
    "pv_macs": 9_332_736_000,
    "dense_learned_matrix_macs": 4_463_473_459_200,
    "norm_weighted_element_equations": 313_344_000,
    "final_norm_weighted_element_equations": 801_024,
    "weight_terminal_coverage": 472,
    "full_attention_prefill_shape": [100, 100],
    "output_pruned_algorithm_or_theorem": False,
}


class DagManifestError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class DagNode:
    id: int
    execution: int
    layer: int | None
    operation: str
    dependencies: tuple[int, ...]
    weight_terminal: str | None
    activation_scale_owner: str | None
    public_inputs: tuple[str, ...]


def _keys(value: object, expected: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise DagManifestError(f"{label}: fields differ")
    return value


def _json_no_duplicates(body: bytes) -> dict:
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise DagManifestError(f"manifest: duplicate JSON key {key!r}")
            result[key] = value
        return result

    return json.loads(body.decode("utf-8"), object_pairs_hook=pairs)


def _equal(actual: object, expected: object, label: str) -> None:
    if type(actual) is not type(expected) or actual != expected:
        raise DagManifestError(f"{label}: value differs")


def _program(actual: object, expected: tuple[tuple[object, ...], ...], label: str) -> None:
    if (
        type(actual) is not list
        or any(type(row) is not list for row in actual)
        or [tuple(row) for row in actual] != list(expected)
    ):
        raise DagManifestError(f"{label}: compact operation program differs")


def _expand_schedule(schedule: dict) -> list[dict[str, int | bool | str]]:
    phases = schedule["phases"]
    expected = (
        ("prefill-decision", 0, 1, 100, 0, 100, True),
        ("decode-decision", 1, 49, 1, 100, 101, True),
        ("terminal-absorb", 50, 1, 1, 149, 150, False),
    )
    rows: list[dict[str, int | bool | str]] = []
    if type(phases) is not list or len(phases) != len(expected):
        raise DagManifestError("workload_schedule.phases: value differs")
    fields = {
        "kind",
        "first_execution",
        "count",
        "query_tokens",
        "cache_before_first",
        "cache_after_first",
        "emit_decision",
    }
    for phase, want in zip(phases, expected, strict=True):
        _keys(phase, fields, "workload phase")
        named = (
            phase["kind"],
            phase["first_execution"],
            phase["count"],
            phase["query_tokens"],
            phase["cache_before_first"],
            phase["cache_after_first"],
            phase["emit_decision"],
        )
        if any(type(got) is not type(expected_value) for got, expected_value in zip(named, want, strict=True)) or named != want:
            raise DagManifestError("workload phase: value differs")
        for offset in range(phase["count"]):
            rows.append(
                {
                    "kind": phase["kind"],
                    "execution": phase["first_execution"] + offset,
                    "query_tokens": phase["query_tokens"],
                    "cache_before": phase["cache_before_first"] + offset,
                    "cache_after": phase["cache_after_first"] + offset,
                    "emit_decision": phase["emit_decision"],
                }
            )
    if [row["execution"] for row in rows] != list(range(51)):
        raise DagManifestError("workload executions are not contiguous")
    return rows


def _weight_terminal(layer: int | None, operation: str) -> str | None:
    if layer is None:
        return {"embedding_lookup": "weight/tied_embedding", "final_rms": "weight/final_norm", "lm_head": "weight/tied_embedding"}.get(operation)
    if operation in {
        "input_rms",
        "q_norm",
        "k_norm",
        "post_attention_rms",
        "pre_ffw_rms",
        "post_ffw_rms",
    }:
        return f"weight/layer/{layer}/norm_bundle"
    if operation in {"q_proj", "o_proj", "gate_proj", "up_proj", "down_proj"}:
        return f"weight/layer/{layer}/{operation}"
    if operation == "k_proj":
        role = "k_eq_v_proj" if layer % 6 == 5 else "k_proj"
        return f"weight/layer/{layer}/{role}"
    if operation == "v_source" and layer % 6 != 5:
        return f"weight/layer/{layer}/v_proj"
    return None


def _scale_owner(layer: int | None, operation: str, scope: str) -> str | None:
    if scope == "none" or (scope == "layer-local-only" and layer is not None and layer % 6 == 5):
        return None
    if scope in {"layer", "layer-local-only"} and layer is not None:
        return f"layer/{layer}/{operation}"
    if scope == "global":
        return f"model/{operation}"
    raise DagManifestError(f"invalid activation scale scope {scope!r}")


def _public_inputs(execution: int, layer: int | None, operation: str) -> tuple[str, ...]:
    if execution == 0 and layer is None and operation == "token_input":
        return (
            "prompt_token_ids/workload_sha256/"
            "70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b",
        )
    if operation == "embedding_scale":
        return ("embedding_scale/bf16/0x4293=147/2",)
    if layer is not None and operation in {"q_rope", "k_rope"}:
        return (f"position_ids/execution/{execution}",)
    if layer is not None and operation == "attention_mask_add":
        attention = "full_attention" if layer % 6 == 5 else "sliding_attention"
        return (f"attention_mask/{attention}/execution/{execution}",)
    if layer is not None and operation == "layer_scalar_mul":
        return (f"model.language_model.layers.{layer}.layer_scalar",)
    return ()


def _canonical_weight_terminal_owners() -> frozenset[str]:
    try:
        body = TERMINAL_MANIFEST.read_bytes()
    except OSError as error:
        raise DagManifestError("canonical terminal manifest is unavailable") from error
    if hashlib.sha256(body).hexdigest() != TERMINAL_MANIFEST_SHA256:
        raise DagManifestError("canonical terminal manifest SHA-256 differs")
    try:
        lines = body.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise DagManifestError("canonical terminal manifest is not UTF-8") from error
    records = [line for line in lines if line and not line.startswith("@")]
    if len(records) != 480:
        raise DagManifestError("canonical terminal manifest does not contain 480 records")
    owners: list[str] = []
    for ordinal, line in enumerate(records):
        fields = line.split(",")
        if len(fields) != 6 or fields[0] != str(ordinal) or fields[3] != "1":
            raise DagManifestError(f"canonical terminal record {ordinal} differs")
        if fields[1] == "W":
            owners.append(fields[2])
    if len(owners) != 472 or len(set(owners)) != 472:
        raise DagManifestError("canonical W-terminal owner set differs")
    return frozenset(owners)


def expand_dag(manifest: dict, executions: list[dict[str, int | bool | str]]) -> list[DagNode]:
    """Expand all 79,963 operator tensor-flow records."""
    nodes: list[DagNode] = []
    prior_cache: list[int | None] = [None] * manifest["model_config"]["layers"]
    previous_argmax: int | None = None

    def add(execution: int, layer: int | None, operation: str, dependencies: tuple[int, ...], weight: str, scale: str) -> int:
        node_id = len(nodes)
        if any(type(dep) is not int or dep < 0 or dep >= node_id for dep in dependencies):
            raise DagManifestError(f"node {node_id} has a non-topological dependency")
        nodes.append(
            DagNode(
                id=node_id,
                execution=execution,
                layer=layer,
                operation=operation,
                dependencies=dependencies,
                weight_terminal=_weight_terminal(layer, operation) if weight != "none" else None,
                activation_scale_owner=_scale_owner(layer, operation, scale),
                public_inputs=_public_inputs(execution, layer, operation),
            )
        )
        return node_id

    for execution_row in executions:
        execution = int(execution_row["execution"])
        token_dependencies = () if execution == 0 else (previous_argmax,)
        if execution > 0 and previous_argmax is None:
            raise DagManifestError("decode token input is not linked to the previous argmax")
        token_input = add(execution, None, "token_input", token_dependencies, "none", "none")
        embedding = add(execution, None, "embedding_lookup", (token_input,), "tied_embedding", "none")
        layer_input = add(execution, None, "embedding_scale", (embedding,), "none", "global")

        for layer in range(manifest["model_config"]["layers"]):
            ids: dict[str, int] = {}
            for operation, _arity, _rule, weight, scale in LAYER_PROGRAM:
                if operation == "input_rms":
                    dependencies = (layer_input,)
                elif operation == "q_proj":
                    dependencies = (ids["input_rms"],)
                elif operation == "q_norm":
                    dependencies = (ids["q_proj"],)
                elif operation == "q_rope":
                    dependencies = (ids["q_norm"],)
                elif operation == "k_proj":
                    dependencies = (ids["input_rms"],)
                elif operation == "k_norm":
                    dependencies = (ids["k_proj"],)
                elif operation == "k_rope":
                    dependencies = (ids["k_norm"],)
                elif operation == "v_source":
                    dependencies = (ids["k_proj"],) if layer % 6 == 5 else (ids["input_rms"],)
                elif operation == "v_norm":
                    dependencies = (ids["v_source"],)
                elif operation == "kv_cache_append":
                    dependencies = (ids["k_rope"], ids["v_norm"])
                    if prior_cache[layer] is not None:
                        dependencies += (prior_cache[layer],)
                elif operation == "qk_matmul":
                    dependencies = (ids["q_rope"], ids["kv_cache_append"])
                elif operation == "attention_mask_add":
                    dependencies = (ids["qk_matmul"],)
                elif operation == "softmax":
                    dependencies = (ids["attention_mask_add"],)
                elif operation == "pv_matmul":
                    dependencies = (ids["softmax"], ids["kv_cache_append"])
                elif operation == "o_proj":
                    dependencies = (ids["pv_matmul"],)
                elif operation == "post_attention_rms":
                    dependencies = (ids["o_proj"],)
                elif operation == "attention_residual_add":
                    dependencies = (layer_input, ids["post_attention_rms"])
                elif operation == "pre_ffw_rms":
                    dependencies = (ids["attention_residual_add"],)
                elif operation == "gate_proj":
                    dependencies = (ids["pre_ffw_rms"],)
                elif operation == "gelu_tanh":
                    dependencies = (ids["gate_proj"],)
                elif operation == "up_proj":
                    dependencies = (ids["pre_ffw_rms"],)
                elif operation == "gate_up_mul":
                    dependencies = (ids["gelu_tanh"], ids["up_proj"])
                elif operation == "down_proj":
                    dependencies = (ids["gate_up_mul"],)
                elif operation == "post_ffw_rms":
                    dependencies = (ids["down_proj"],)
                elif operation == "ffw_residual_add":
                    dependencies = (ids["attention_residual_add"], ids["post_ffw_rms"])
                elif operation == "layer_scalar_mul":
                    dependencies = (ids["ffw_residual_add"],)
                else:  # pragma: no cover - the frozen program is validated before expansion.
                    raise DagManifestError(f"unknown layer operation {operation!r}")
                if len(dependencies) != _arity + (operation == "kv_cache_append" and execution > 0):
                    raise DagManifestError(f"dependency arity differs for {operation}")
                ids[operation] = add(execution, layer, operation, dependencies, weight, scale)
            prior_cache[layer] = ids["kv_cache_append"]
            layer_input = ids["layer_scalar_mul"]

        if bool(execution_row["emit_decision"]):
            final_rms = add(execution, None, "final_rms", (layer_input,), "final_norm", "global")
            last_row = add(execution, None, "last_row_select", (final_rms,), "none", "none")
            lm_head = add(execution, None, "lm_head", (last_row,), "tied_embedding", "global")
            softcap = add(execution, None, "final_tanh_softcap", (lm_head,), "none", "global")
            previous_argmax = add(execution, None, "argmax", (softcap,), "none", "none")

    if len(nodes) != EXPECTED_CENSUS["operator_tensor_flow_nodes"]:
        raise DagManifestError("expanded operator tensor-flow node count differs")
    if sum(len(node.dependencies) for node in nodes) != EXPECTED_CENSUS["tensor_dependency_edges"]:
        raise DagManifestError("expanded tensor dependency edge count differs")
    return nodes


def compile_manifest(manifest: dict) -> dict:
    _keys(
        manifest,
        {
            "schema",
            "classification",
            "identity",
            "official_sources",
            "model_config",
            "workload_schedule",
            "quantization",
            "mathematical_semantics",
            "compact_program",
            "expected_census",
            "blockers",
        },
        "manifest",
    )
    _equal(manifest["schema"], "volta-c7-d126-gemma31b-qspec-dag-v1", "schema")
    _equal(
        manifest["classification"],
        {
            "kind": "operator-tensor-flow-dag",
            "exact_declared_operator_invocation_census": True,
            "node_shapes_dtypes_padding_present": False,
            "complete_semantic_dag": False,
            "dependency_edge_definition": "tensor-output dependencies only; named public_inputs are excluded",
            "base_gkr_circuit": False,
            "base_gkr_credit": False,
            "prover_certificate_or_hardware_credit": False,
        },
        "classification",
    )

    identity = manifest["identity"]
    _equal(
        identity,
        {
            "model": "google/gemma-4-31B",
            "revision": "5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89",
            "text_only": True,
            "config_sha256": "6a81841cad2b6ba06841e23c6afb5f0a27827bc12c64328ffa6338831a21267e",
            "source_metadata_sha256": "1ddce0cc399d636488728f663fb756804a07e6b3ad14d43f527c7ad746e27ce2",
            "workload_sha256": "70875c659be2b2bc0079a954233da639fe1584136c17f8fb353b589454a5d62b",
            "terminal_manifest_sha256": TERMINAL_MANIFEST_SHA256,
            "terminal_manifest_blake3": "c90c41afaaac0c8da4a3c6e4781cd95dab026477999d6e20f565580db82bda25",
        },
        "identity",
    )

    sources = manifest["official_sources"]
    _keys(
        sources,
        {
            "dependency_closure",
            "runtime_repository",
            "runtime_commit",
            "files",
            "corroborating_repository",
            "corroborating_commit",
            "corroborating_files",
            "open_runtime_dependency_closure",
        },
        "official_sources",
    )
    _equal(sources["dependency_closure"], "partial", "source dependency closure")
    _equal(sources["runtime_repository"], "https://github.com/huggingface/transformers", "runtime repository")
    _equal(sources["runtime_commit"], "c1c34249fa27deefbd4a377dfbf883a39baf5c6d", "runtime commit")
    _equal(
        sources["files"],
        [
            ["src/transformers/models/gemma4/configuration_gemma4.py", "3eb1d90bffeb0caf9bd51ab5007bac8696e54109a8f43ea8919cdd83319a1401"],
            ["src/transformers/models/gemma4/modeling_gemma4.py", "6a86e03348df5ec104703e7161de9a911137cba500a0be0f133e2850ef0bf935"],
            ["src/transformers/activations.py", "b39db15a53d1ce29b99ddbc335b56102d26f65db0b288941cf78cbdd0daa7e67"],
            ["src/transformers/modeling_rope_utils.py", "d8c3c0696a10e8041f31037116e35289d66c1629b8d134d5ca9629c3ac115c3c"],
            ["src/transformers/masking_utils.py", "7fd2bf34f3abc87953a500c0d53e3e633e5efba10aebcc4dc11422e5769092dd"],
            ["src/transformers/cache_utils.py", "7935a009f4131f1c21b53fb731f06813bcbaf8a34fe216cb9e83707aaafcf949"],
        ],
        "official runtime source files",
    )
    _equal(sources["corroborating_repository"], "https://github.com/google-deepmind/gemma", "corroborating repository")
    _equal(sources["corroborating_commit"], "7b785991bd78626c73b317eb43fdbb6c292f7b9c", "corroborating commit")
    _equal(
        sources["corroborating_files"],
        [
            ["gemma/gm/nn/gemma4/_gemma4.py", "67cf8c06eed95cbea613e1014f8dd23aade95edf5fb415d875118fe5c1605c4f"],
            ["gemma/gm/nn/gemma4/_modules.py", "aa422c5904a07e11b9076d91b7648fcd175354dea80c6410c92dc3d67574c17f"],
            ["gemma/gm/nn/gemma4/_layers.py", "55643c31628bd66e94d72bd035910635a4c5bbf2e5a131ce8fb663ddb28b405c"],
            ["gemma/gm/nn/gemma4/_transformer.py", "301ae29c9acf9d102f85f63322cf35d96216b16a80334885207c13e7832e3dda"],
            ["gemma/gm/nn/gemma4/_config.py", "6c72fdb786cc676130a753cac5e49c51fbab0bf785213e84facd64026a8cdc25"],
            ["gemma/gm/math/_positional_embeddings.py", "6f4814d3554dbb4c67bba794e9fb13a2ae39ea7c77dc4a040527d1536fcb0c92"],
        ],
        "corroborating source files",
    )
    _equal(
        sources["open_runtime_dependency_closure"],
        "transitive helpers and kernels imported by the pinned runtime files",
        "open runtime dependency closure",
    )

    config = manifest["model_config"]
    _keys(
        config,
        {
            "hidden_size",
            "intermediate_size",
            "vocab_size",
            "layers",
            "local_layers",
            "global_layers",
            "global_layer_rule",
            "query_heads",
            "local_kv_heads",
            "global_kv_heads",
            "local_head_dim",
            "global_head_dim",
            "attention_k_eq_v",
            "attention_scaling",
            "attention_bias",
            "attention_dropout",
            "sliding_window",
            "rms_epsilon",
            "hidden_activation",
            "final_logit_softcap",
            "tie_word_embeddings",
            "embedding_scale_bf16_bits",
            "embedding_scale_exact",
            "context_capacity",
            "num_kv_shared_layers",
            "hidden_size_per_layer_input",
            "enable_moe_block",
            "use_double_wide_mlp",
        },
        "model_config",
    )
    required_config = {
        "hidden_size": 5_376,
        "intermediate_size": 21_504,
        "vocab_size": 262_144,
        "layers": 60,
        "local_layers": 50,
        "global_layers": 10,
        "query_heads": 32,
        "local_kv_heads": 16,
        "global_kv_heads": 4,
        "local_head_dim": 256,
        "global_head_dim": 512,
        "sliding_window": 1_024,
        "context_capacity": 4_096,
    }
    for field, expected in required_config.items():
        _equal(config[field], expected, f"model_config.{field}")
    for field, expected in {
        "attention_k_eq_v": True,
        "attention_scaling": "1",
        "attention_bias": False,
        "attention_dropout": "0",
        "global_layer_rule": "layer-index-mod-6-equals-5",
        "hidden_activation": "gelu_pytorch_tanh",
        "final_logit_softcap": "30",
        "rms_epsilon": "1/1000000",
        "tie_word_embeddings": True,
        "embedding_scale_bf16_bits": 17_043,
        "embedding_scale_exact": "147/2",
        "num_kv_shared_layers": 0,
        "hidden_size_per_layer_input": 0,
        "enable_moe_block": False,
        "use_double_wide_mlp": False,
    }.items():
        _equal(config[field], expected, f"model_config.{field}")

    quant = manifest["quantization"]
    _keys(
        quant,
        {
            "name",
            "status",
            "real_encoding",
            "integer_dtype",
            "zero_point",
            "integer_min",
            "integer_max",
            "rounding",
            "rounding_definition",
            "overflow",
            "saturation",
            "accumulator_dtype",
            "max_dot_k",
            "max_abs_dot",
            "goldilocks_modulus",
            "max_abs_dot_is_below_modulus_half",
            "weight_exponent_rule",
            "exponent_binding",
            "weight_exponents_by_tensor",
            "activation_exponents_by_operation",
            "nonlinear_tables_by_operation",
            "calibration_manifest_sha256",
            "golden_manifest_sha256",
            "packed_weights_sha256",
        },
        "quantization",
    )
    required_quant = {
        "name": "GemmaQuantV1",
        "status": "BLOCKED",
        "real_encoding": "real=int*2^e",
        "integer_dtype": "i16",
        "zero_point": 0,
        "integer_min": -32_767,
        "integer_max": 32_767,
        "rounding": "round-to-nearest-ties-to-even",
        "rounding_definition": "choose n minimizing abs(x-n); at an exact half choose the even n",
        "overflow": "reject",
        "saturation": "none",
        "accumulator_dtype": "i64",
        "max_dot_k": 21_504,
        "max_abs_dot": 23_088_334_918_656,
        "goldilocks_modulus": 18_446_744_069_414_584_321,
        "max_abs_dot_is_below_modulus_half": True,
        "weight_exponent_rule": "for each nonzero tensor choose the minimum integer e such that every exact finite BF16 value x maps by RNE(x*2^(-e)) into [-32767,32767]; for an all-zero tensor choose e=0",
        "exponent_binding": "all weight and activation exponents are frozen before the proof; calibration may propose activation exponents but no exponent may depend on witness values or vary across the 51 executions",
    }
    for field, expected in required_quant.items():
        _equal(quant[field], expected, f"quantization.{field}")
    if quant["max_abs_dot"] != quant["max_dot_k"] * quant["integer_max"] ** 2:
        raise DagManifestError("dot-product bound is not K*32767^2")
    if not quant["max_abs_dot"] < quant["goldilocks_modulus"] // 2:
        raise DagManifestError("dot-product bound is not below p/2")
    for field in (
        "weight_exponents_by_tensor",
        "activation_exponents_by_operation",
        "nonlinear_tables_by_operation",
        "calibration_manifest_sha256",
        "golden_manifest_sha256",
        "packed_weights_sha256",
    ):
        _equal(quant[field], None, f"quantization.{field}")

    semantics = manifest["mathematical_semantics"]
    _equal(
        semantics,
        {
            "scope": "exact-real-reference-before-GemmaQuantV1-table-instantiation",
            "rmsnorm_with_scale": "y_i=x_i*w_i*(1/1000000+(sum_j x_j^2)/d)^(-1/2)",
            "rmsnorm_without_scale": "y_i=x_i*(1/1000000+(sum_j x_j^2)/d)^(-1/2)",
            "gelu_pytorch_tanh": "gelu(x)=x/2*(1+tanh(sqrt(2/pi)*(x+44715/1000000*x^3)))",
            "softmax": "softmax(s)_j=exp(s_j-max_allowed(s))/sum_allowed_k exp(s_k-max_allowed(s))",
            "attention_mask": "eager materializes every declared rectangular score cell, then adds 0 when k<=q and (full_attention or q-k<1024), otherwise -infinity; excluding forbidden softmax terms is mathematical equivalence only and grants no pruning credit",
            "local_rope": "inv[j]=10000^(-2*j/256),0<=j<128; rope(x)=x*cos(pos*inv||pos*inv)+rotate_half(x)*sin(pos*inv||pos*inv)",
            "global_rope": "inv[j]=1000000^(-2*j/512),0<=j<64; inv[j]=0,64<=j<256; use the same rope equation",
            "rotate_half": "rotate_half(x[0:d/2]||x[d/2:d])=(-x[d/2:d])||x[0:d/2]",
            "attention": "scores=Q*K^T with scale 1; output=softmax(mask(scores))*V after KV-head repetition",
            "embedding_scale": "embedding[token_id] is multiplied by the exact BF16 dyadic 147/2 (bits 0x4293)",
            "layer_scalar": "each layer output is multiplied by that layer's exact public BF16 dyadic from manifests/c7-d126-gemma31b-layer-scalars-v1.csv",
            "final_tanh_softcap": "softcap(z)=30*tanh(z/30)",
            "selection": "greedy argmax; choose the lowest token id on a tie",
        },
        "mathematical semantics",
    )

    schedule = manifest["workload_schedule"]
    _keys(
        schedule,
        {
            "executions",
            "phases",
            "decisions",
            "logits_to_keep_per_decision",
            "final_cache_tokens",
            "terminal_absorb_skips",
        },
        "workload_schedule",
    )
    executions = _expand_schedule(schedule)
    _equal(schedule["executions"], 51, "workload_schedule.executions")
    _equal(schedule["decisions"], 50, "workload_schedule.decisions")
    _equal(schedule["logits_to_keep_per_decision"], 1, "workload_schedule.logits_to_keep_per_decision")
    _equal(schedule["final_cache_tokens"], 150, "workload_schedule.final_cache_tokens")
    _equal(schedule["terminal_absorb_skips"], [row[0] for row in SUFFIX_PROGRAM], "terminal absorb")

    program = manifest["compact_program"]
    _keys(program, {"prefix", "layer", "decision_suffix", "record_columns"}, "compact_program")
    _program(program["prefix"], PREFIX_PROGRAM, "prefix")
    _program(program["layer"], LAYER_PROGRAM, "layer")
    _program(program["decision_suffix"], SUFFIX_PROGRAM, "decision suffix")
    _equal(
        program["record_columns"],
        ["operation", "base_dependencies", "dependency_rule", "weight_link", "activation_scale_scope"],
        "compact_program.record_columns",
    )

    decision_count = sum(bool(row["emit_decision"]) for row in executions)
    dag = expand_dag(manifest, executions)
    layer_matrix_operations = {"q_proj", "k_proj", "v_source", "o_proj", "gate_proj", "up_proj", "down_proj"}
    layer_matrix_invocations = sum(
        node.layer is not None and node.operation in layer_matrix_operations and node.weight_terminal is not None
        for node in dag
    )
    total_matrix_invocations = layer_matrix_invocations + sum(node.operation == "lm_head" for node in dag)
    w_linked = sum(node.weight_terminal is not None for node in dag)
    scale_owners = len({node.activation_scale_owner for node in dag if node.activation_scale_owner is not None})
    terminal_owners = frozenset(node.weight_terminal for node in dag if node.weight_terminal is not None)
    if terminal_owners != _canonical_weight_terminal_owners():
        raise DagManifestError("compiled W-terminal owners differ from the canonical terminal manifest")

    score_cells = 0
    qk_macs = 0
    head_dim_total = (
        config["local_layers"] * config["local_head_dim"]
        + config["global_layers"] * config["global_head_dim"]
    )
    for row in executions:
        cells_per_layer = config["query_heads"] * row["query_tokens"] * row["cache_after"]
        score_cells += config["layers"] * cells_per_layer
        qk_macs += cells_per_layer * head_dim_total
    token_rows = sum(row["query_tokens"] for row in executions)
    local_norm_elements = (
        4 * config["hidden_size"]
        + config["local_kv_heads"] * config["local_head_dim"]
        + config["query_heads"] * config["local_head_dim"]
    )
    global_norm_elements = (
        4 * config["hidden_size"]
        + config["global_kv_heads"] * config["global_head_dim"]
        + config["query_heads"] * config["global_head_dim"]
    )
    norm_equations = token_rows * (
        config["local_layers"] * local_norm_elements
        + config["global_layers"] * global_norm_elements
    )
    final_norm_rows = sum(
        row["query_tokens"] for row in executions if row["emit_decision"]
    )
    layer_matrix_scalars = 50 * 478_937_088 + 10 * 533_987_328
    dense_macs = token_rows * layer_matrix_scalars + decision_count * 1_409_286_144

    census = {
        "executions": len(executions),
        "operator_tensor_flow_nodes": len(dag),
        "tensor_dependency_edges": sum(len(node.dependencies) for node in dag),
        "layer_private_matrix_invocations": layer_matrix_invocations,
        "total_private_matrix_invocations": total_matrix_invocations,
        "weight_terminal_linked_op_invocations": w_linked,
        "fixed_activation_scale_owners": scale_owners,
        "eager_nonpruned_score_cells": score_cells,
        "qk_macs": qk_macs,
        "pv_macs": qk_macs,
        "dense_learned_matrix_macs": dense_macs,
        "norm_weighted_element_equations": norm_equations,
        "final_norm_weighted_element_equations": final_norm_rows * config["hidden_size"],
        "weight_terminal_coverage": len(terminal_owners),
        "full_attention_prefill_shape": [100, 100],
        "output_pruned_algorithm_or_theorem": False,
    }
    _equal(manifest["expected_census"], EXPECTED_CENSUS, "declared census")
    _equal(census, EXPECTED_CENSUS, "compiled census")
    blockers = manifest["blockers"]
    _equal(
        blockers,
        [
            "weight_exponents_by_tensor: require exactly 772 canonical private tensor keys with integer exponents",
            "activation_exponents_by_operation: require exactly 1434 fixed owner keys with integer exponents",
            "nonlinear_tables_by_operation: require canonical RMS/GELU/softmax/RoPE/final-tanh table map and digests",
            "runtime_weights: require both pinned shards and the exact packed i16 digest",
            "decode_ids_and_goldens: require 50 generated token ids and Python-Rust bit equality",
            "integer_lowering: require exact requantization points, operand exponent alignment, finite attention-mask sentinel and an accumulator bound for every operation kind",
            "base_gkr_lowering: require exact rows, wires and a matching Lean relation",
        ],
        "blockers",
    )
    return {
        "schema": manifest["schema"],
        "classification": manifest["classification"]["kind"],
        "status": "BLOCKED",
        "census": census,
        "blockers": blockers,
    }


def load_and_compile(path: Path = MANIFEST) -> dict:
    try:
        body = path.read_bytes()
        manifest = _json_no_duplicates(body)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DagManifestError("manifest is unavailable or invalid JSON") from error
    if path == MANIFEST:
        expected_sidecar = f"{hashlib.sha256(body).hexdigest()}  {path.name}\n"
        try:
            sidecar = MANIFEST_SHA256.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError) as error:
            raise DagManifestError("manifest SHA-256 sidecar is unavailable or invalid") from error
        if sidecar != expected_sidecar:
            raise DagManifestError("manifest SHA-256 sidecar differs")
    return compile_manifest(manifest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    args = parser.parse_args()
    try:
        report = load_and_compile(args.manifest)
    except DagManifestError as error:
        print(json.dumps({"status": "INVALID", "error": str(error)}))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2  # The tensor-flow census is exact; GemmaQuantV1 is intentionally BLOCKED.


if __name__ == "__main__":
    raise SystemExit(main())
