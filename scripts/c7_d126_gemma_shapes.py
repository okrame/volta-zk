#!/usr/bin/env python3
"""Compile Gemma logical tensor shapes without weights or expanded scalar wires.

The input is the current, digest-bound Gemma DAG. This adds logical ports and
views, not an integer circuit or a CUDA allocation trace. No tensor payload is
allocated. Cache views describe one arena; keeping old views is not a copy.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from dataclasses import asdict, dataclass

import c7_d126_gemma_qspec_dag as dag
import c7_d126_gemma_weight_ingest as ingest
import budget_c7_d126_gemma_static as budget


class ShapeError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Port:
    name: str
    shape: tuple[int, ...]
    value_kind: str  # token-id or real-valued; concrete QSPEC dtype is still open
    storage: str  # owned, alias, or kv-arena-view; logical plan only
    alias_node: int | None = None
    offset_elements: int = 0

    @property
    def elements(self) -> int:
        return math.prod(self.shape)


@dataclass(frozen=True, slots=True)
class ShapeRow:
    node_id: int
    execution: int
    layer: int | None
    operation: str
    outputs: tuple[Port, ...]
    input_ports: tuple[tuple[int, str], ...]
    weight_keys: tuple[str, ...]
    last_direct_consumer: int
    dot_width: int | None
    dot_products: int
    gqa_repeat: int | None
    allowed_score_cells: int
    masked_score_cells: int


def allowed_keys(query_position: int, key_length: int, window: int | None) -> range:
    """Causal keys, with a strict distance < window for sliding attention."""
    if (type(query_position) is not int or type(key_length) is not int
            or query_position < 0 or key_length < 0
            or (window is not None and (type(window) is not int or window <= 0))):
        raise ShapeError("invalid attention interval")
    start = 0 if window is None else max(0, query_position - window + 1)
    return range(start, max(start, min(query_position + 1, key_length)))


def kv_head(query_head: int, query_heads: int, kv_heads: int) -> int:
    """Indexed GQA view. This function does not materialize repeated K/V."""
    if (any(type(x) is not int for x in (query_head, query_heads, kv_heads))
            or kv_heads <= 0 or query_heads <= 0 or query_heads % kv_heads
            or not 0 <= query_head < query_heads):
        raise ShapeError("invalid grouped-query head geometry")
    return query_head // (query_heads // kv_heads)


def compile_shapes(manifest: dict, nodes: list[dag.DagNode] | None = None) -> tuple[list[ShapeRow], dict]:
    base = dag.compile_manifest(manifest)
    schedule = dag._expand_schedule(manifest["workload_schedule"])
    canonical = dag.expand_dag(manifest, schedule)
    # A count-only guard cannot detect a same-sized rewiring or wrong KV parent.
    if nodes is None:
        nodes = canonical
    elif nodes != canonical:
        raise ShapeError("DAG nodes, edges or owner bindings differ from the frozen compiler")
    del canonical

    metadata = ingest.load_metadata()
    weights = {t["name"]: tuple(t["shape"]) for t in metadata["tensors"]
               if t["disposition"] == "private_text"}
    owners = {}
    terminal_bytes = ingest.TERMINALS.read_bytes()
    if hashlib.sha256(terminal_bytes).hexdigest() != ingest.TERMINALS_SHA256:
        raise ShapeError("terminal manifest digest differs")
    for line in terminal_bytes.decode("ascii").splitlines():
        if line.startswith("@"):
            continue
        fields = line.split(",")
        if fields[1] == "W":
            owners[fields[2]] = tuple(fields[4].split(";"))

    cfg = manifest["model_config"]
    hidden, ffw, vocab = cfg["hidden_size"], cfg["intermediate_size"], cfg["vocab_size"]
    heads = cfg["query_heads"]
    last = list(range(len(nodes)))
    for node in nodes:
        for dependency in node.dependencies:
            last[dependency] = max(last[dependency], node.id)
    rows: list[ShapeRow] = []
    used_weights: set[str] = set()
    role_key = {
        "input_rms": "input_layernorm", "post_attention_rms": "post_attention_layernorm",
        "pre_ffw_rms": "pre_feedforward_layernorm", "post_ffw_rms": "post_feedforward_layernorm",
        "q_norm": "self_attn.q_norm", "k_norm": "self_attn.k_norm",
    }
    for node in nodes:
        phase = schedule[node.execution]
        t, s, old = phase["query_tokens"], phase["cache_after"], phase["cache_before"]
        global_layer = node.layer is not None and node.layer % 6 == 5
        hd = cfg["global_head_dim" if global_layer else "local_head_dim"]
        kh = cfg["global_kv_heads" if global_layer else "local_kv_heads"]
        op = node.operation
        inp = tuple((d, "value") for d in node.dependencies)
        outputs: tuple[Port, ...]
        keys = owners.get(node.weight_terminal, ())
        dot_width, dot_products, repeat = None, 0, None
        allowed, masked = 0, 0
        shape = (1, t, hidden)
        kind, storage, alias, offset = "real-valued", "owned", None, 0

        def expect(index: int, expected: tuple[int, ...], port: str = "value") -> None:
            source = rows[node.dependencies[index]]
            matches = [p for p in source.outputs if p.name == port]
            if len(matches) != 1 or matches[0].shape != expected:
                raise ShapeError(f"node {node.id} {op}: input {index}/{port} shape differs")

        if op == "token_input":
            shape, kind = (1, t), "token-id"
            if node.execution:
                expect(0, (1, 1))
                storage, alias = "alias", node.dependencies[0]
        elif op == "embedding_lookup":
            expect(0, (1, t))
            if len(keys) != 1 or weights[keys[0]] != (vocab, hidden):
                raise ShapeError("embedding source shape differs")
        elif op in {"q_proj", "k_proj", "v_source", "o_proj", "gate_proj", "up_proj", "down_proj", "lm_head"}:
            if op == "v_source" and global_layer:
                shape = (1, t, kh * hd)
                expect(0, shape)
                storage, alias = "alias", node.dependencies[0]
            else:
                input_width = ffw if op == "down_proj" else heads * hd if op == "o_proj" else hidden
                output_width = (heads * hd if op == "q_proj" else kh * hd if op in {"k_proj", "v_source"}
                                else ffw if op in {"gate_proj", "up_proj"} else vocab if op == "lm_head" else hidden)
                active_rows = 1 if op == "lm_head" else t
                expect(0, (1, t, heads, hd) if op == "o_proj" else (1, active_rows, input_width))
                if len(keys) != 1 or weights[keys[0]] != (output_width, input_width):
                    raise ShapeError(f"node {node.id}: private matrix shape differs")
                shape = (1, active_rows, output_width)
                dot_width, dot_products = input_width, active_rows * output_width
        elif op in {"q_norm", "k_norm", "v_norm"}:
            count = heads if op == "q_norm" else kh
            expect(0, (1, t, count * hd))
            shape = (1, t, count, hd)
        elif op in {"q_rope", "k_rope"}:
            shape = (1, t, heads if op == "q_rope" else kh, hd)
            expect(0, shape)
        elif op == "kv_cache_append":
            expect(0, (1, t, kh, hd))
            expect(1, (1, t, kh, hd))
            inp = ((node.dependencies[0], "value"), (node.dependencies[1], "value"))
            if old:
                expect(2, (1, old, kh, hd), "k")
                expect(2, (1, old, kh, hd), "v")
                inp += ((node.dependencies[2], "k"), (node.dependencies[2], "v"))
            shape, storage = (1, s, kh, hd), "kv-arena-view"
        elif op == "qk_matmul":
            expect(0, (1, t, heads, hd))
            expect(1, (1, s, kh, hd), "k")
            inp = ((node.dependencies[0], "value"), (node.dependencies[1], "k"))
            shape, dot_width, dot_products, repeat = (1, heads, t, s), hd, heads * t * s, heads // kh
            window = None if global_layer else cfg["sliding_window"]
            allowed = heads * sum(len(allowed_keys(position, s, window)) for position in range(old, old + t))
            masked = dot_products - allowed
        elif op in {"attention_mask_add", "softmax"}:
            shape = (1, heads, t, s)
            expect(0, shape)
        elif op == "pv_matmul":
            expect(0, (1, heads, t, s))
            expect(1, (1, s, kh, hd), "v")
            inp = ((node.dependencies[0], "value"), (node.dependencies[1], "v"))
            shape, dot_width, dot_products, repeat = (1, t, heads, hd), s, t * heads * hd, heads // kh
        elif op in {"gelu_tanh", "gate_up_mul"}:
            shape = (1, t, ffw)
            for index in range(len(node.dependencies)):
                expect(index, shape)
        elif op == "last_row_select":
            expect(0, (1, t, hidden))
            shape, storage, alias, offset = (1, 1, hidden), "alias", node.dependencies[0], (t - 1) * hidden
        elif op == "final_tanh_softcap":
            shape = (1, 1, vocab)
            expect(0, shape)
        elif op == "argmax":
            expect(0, (1, 1, vocab))
            shape, kind = (1, 1), "token-id"
        elif op in {"embedding_scale", "input_rms", "post_attention_rms", "attention_residual_add",
                    "pre_ffw_rms", "post_ffw_rms", "ffw_residual_add", "layer_scalar_mul", "final_rms"}:
            for index in range(len(node.dependencies)):
                expect(index, shape)
        else:
            raise ShapeError(f"unsupported operation {op!r}")

        if op in role_key:
            key = f"model.language_model.layers.{node.layer}.{role_key[op]}.weight"
            if key not in keys or weights[key] != (shape[-1],):
                raise ShapeError(f"node {node.id}: norm source shape differs")
            keys = (key,)
        elif op == "final_rms":
            if len(keys) != 1 or weights[keys[0]] != (hidden,):
                raise ShapeError("final norm source shape differs")
        used_weights.update(keys)
        if op == "kv_cache_append":
            outputs = (Port("k", shape, kind, storage), Port("v", shape, kind, storage))
        else:
            outputs = (Port("value", shape, kind, storage, alias, offset),)
        if alias is not None:
            source = rows[alias].outputs[0]
            if offset < 0 or offset + math.prod(shape) > source.elements:
                raise ShapeError("alias extends beyond source storage")
        rows.append(ShapeRow(node.id, node.execution, node.layer, op, outputs, inp, keys,
                             last[node.id], dot_width, dot_products, repeat, allowed, masked))

    if used_weights != set(weights):
        raise ShapeError("shaped operations do not cover exactly the 772 private sources")
    macs = Counter()
    for row in rows:
        if row.dot_width is not None:
            macs[row.operation] += row.dot_width * row.dot_products
    dense_macs = sum(value for op, value in macs.items() if op not in {"qk_matmul", "pv_matmul"})
    if (dense_macs != base["census"]["dense_learned_matrix_macs"]
            or macs["qk_matmul"] != base["census"]["qk_macs"]
            or macs["pv_matmul"] != base["census"]["pv_macs"]):
        raise ShapeError("independent shape-derived MAC census differs")
    ports = [p for row in rows for p in row.outputs]
    digest = hashlib.sha256()
    for row in rows:
        digest.update((json.dumps(asdict(row), sort_keys=True, separators=(",", ":")) + "\n").encode())
    owned_real_elements = sum(p.elements for p in ports if p.storage == "owned" and p.value_kind == "real-valued")
    subtotal = (budget.PACKED_W_BYTES + budget.KV_VALUES_PER_TOKEN * 2 * cfg["context_capacity"]
                + budget.ROWFOLD_TOTAL_ARENA_CAP_BYTES + budget.STAGING_BYTES + 480 * 24)
    representations = {}
    for name, width in (("i16", 2), ("Fp", 8), ("Fp3", 24)):
        total = subtotal + owned_real_elements * width
        representations[name] = {
            "owned_output_bytes": owned_real_elements * width,
            "conditional_subtotal_plus_outputs_bytes": total,
            "conditional_headroom_bytes": budget.H100_CAP_BYTES - total,
            "status": "NO-GO_IF_SIMULTANEOUS" if total >= budget.H100_CAP_BYTES else "BLOCKED",
        }
    report = {
        "schema": "volta-c7-d126-gemma31b-logical-shapes-v1",
        "status": "BLOCKED", "logical_shapes": "PASS", "admission_credit": False,
        "source_metadata_sha256": ingest.METADATA_SHA256,
        "qspec_dag_sha256": hashlib.sha256(dag.MANIFEST.read_bytes()).hexdigest(),
        "workload_sha256": manifest["identity"]["workload_sha256"],
        "terminal_manifest_sha256": ingest.TERMINALS_SHA256,
        "canonical_rows_sha256": digest.hexdigest(),
        "nodes": len(rows), "tensor_output_ports": len(ports),
        "tensor_input_port_edges": sum(len(row.input_ports) for row in rows),
        "private_tensor_coverage": len(used_weights),
        "dot_macs_by_operation": dict(sorted(macs.items())),
        "allowed_score_cells": sum(row.allowed_score_cells for row in rows),
        "masked_score_cells": sum(row.masked_score_cells for row in rows),
        "logical_alias_ports": sum(p.storage == "alias" for p in ports),
        "kv_arena_view_ports": sum(p.storage == "kv-arena-view" for p in ports),
        "owned_real_output_elements": owned_real_elements,
        "max_private_tensor_scratch_bytes": max(t["nbytes"] for t in metadata["tensors"] if t["disposition"] == "private_text"),
        "representation_screens": {
            "assumption": "all logical owned real outputs retained simultaneously beside W, KV, ROWFOLD, staging and v",
            "not_included": ["integer lowering temporaries", "B", "masks", "chains", "GKR scratch", "CUDA/runtime", "allocator reserve"],
            "physical_allocation_or_dtype_credit": False,
            "cases": representations,
        },
        "max_dot_width": max(row.dot_width or 0 for row in rows),
        "persistent_padding_elements": 0,
        "gkr_domain_padding": None, "device_lane_padding": None,
        "integer_wire_count": None, "physical_peak_bytes": None,
        "blockers": [
            "integer dtype/exponents, requantization and nonlinear lowering",
            "GKR/PCS rows, domains, common points, transcript and ROM refinements",
            "runtime source dependency closure and bit-exact Gemma witness generation",
            "proof retention and CUDA allocation/fence/workspace inventory",
        ],
    }
    return rows, report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--records", action="store_true", help="stream canonical shape rows as JSONL")
    args = parser.parse_args()
    try:
        dag.load_and_compile()
        rows, report = compile_shapes(dag._json_no_duplicates(dag.MANIFEST.read_bytes()))
    except (ShapeError, dag.DagManifestError, ingest.IngestError, ingest.BlockedError) as error:
        print(json.dumps({"status": "INVALID", "error": str(error)}))
        return 1
    if args.records:
        for row in rows:
            print(json.dumps(asdict(row), sort_keys=True, separators=(",", ":")))
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 2  # Logical shapes alone do not admit the protocol or hardware.


if __name__ == "__main__":
    raise SystemExit(main())
