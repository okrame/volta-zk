#!/usr/bin/env python3
"""Pinned Gemma4 SDPA comparison only; no integer/proof/quality admission credit."""
import argparse
import hashlib
import json
import math
from pathlib import Path
import time

ROOT = Path(__file__).resolve().parents[1]


def histories(document, prompt):
    responses = document["responses"]
    if [r["old_tokens"] for r in responses] != [0, 150, 300]:
        raise ValueError("admitted history contexts differ")
    for response in responses:
        tokens = response["tokens"]
        if len(tokens) != 150 or tokens[:100] != prompt:
            raise ValueError("admitted prompt or response length differs")
        if any(type(t) is not int or not 0 <= t < 262144 for t in tokens):
            raise ValueError("invalid token ID")
    return responses


def weight_layout(oracle, exponents):
    weights = oracle["contexts"][0]["weights"]
    ordered = sorted(weights, key=lambda row: row["packed_offset"])
    end = 0
    for row in ordered:
        if row["packed_offset"] != end or row["name"] not in exponents:
            raise ValueError("packed layout or scale identity differs")
        end += row["rows"] * row["columns"]
    if 2 * end != 61_394_690_560 or len(ordered) != 772:
        raise ValueError("pinned text weight census differs")
    return {row["name"].replace("model.language_model.", "model.", 1): row for row in weights}


def schedule(prompt, response):
    # Final generated token is consumed into KV, even though its logits are unused.
    yield prompt
    for token in response[100:]:
        yield [token]


def run(campaign, history_path, output, precision):
    import numpy as np
    import torch
    import transformers
    from safetensors import safe_open
    from transformers import Gemma4ForCausalLM, Gemma4TextConfig
    from transformers.cache_utils import DynamicCache
    from transformers.models.gemma4.modeling_gemma4 import Gemma4TextRotaryEmbedding

    output.mkdir(mode=0o700)
    events = (output / "events.jsonl").open("x")

    def record(event):
        event["monotonic_ns"] = time.monotonic_ns()
        events.write(json.dumps(event) + "\n")
        events.flush()

    workload_path = ROOT / "manifests/c7-d126-gemma31b-workload-v1.json"
    workload = json.loads(workload_path.read_text())
    prompt = workload["prompt"]["token_ids"]
    history_document = json.loads(history_path.read_text())
    admitted = histories(history_document, prompt)
    receipt = json.loads((campaign / "packed-reuse-identity.json").read_text())
    if not receipt["passed"] or not receipt["full_source_bodies_verified"]:
        raise ValueError("verified campaign W inputs required")
    config_bytes = (campaign / "model-config.json").read_bytes()
    metadata = json.loads((ROOT / "manifests/c7-d126-gemma31b-source-metadata-v1.json").read_text())
    if hashlib.sha256(config_bytes).hexdigest() != metadata["config"]["sha256"]:
        raise ValueError("pinned model configuration differs")
    candidate_bytes = (campaign / "gamma-inputs/candidate.json").read_bytes()
    candidate = json.loads(candidate_bytes)
    if history_document["packed_sha256"] != receipt["packed_sha256"] or (
            history_document["candidate_sha256"] != hashlib.sha256(candidate_bytes).hexdigest()):
        raise ValueError("history belongs to different W or Gamma")
    oracle = json.loads((campaign / "gamma-inputs/oracle-plan-original.json").read_text())
    layout = weight_layout(oracle, candidate["weight_exponents_by_tensor"])
    cfg = Gemma4TextConfig(**json.loads(config_bytes)["text_config"])
    cfg._attn_implementation = "sdpa"
    if cfg.num_hidden_layers != 60 or cfg.hidden_size_per_layer_input != 0 or cfg.enable_moe_block:
        raise ValueError("unsupported pinned architecture")
    if not torch.cuda.is_available() or torch.cuda.device_count() != 1:
        raise RuntimeError("explicit single CUDA device required")
    torch.set_num_threads(1)
    torch.backends.cuda.matmul.allow_tf32 = False
    record({"stage": "load_start", "precision": precision})
    load_start = time.perf_counter_ns()
    previous_dtype = torch.get_default_dtype()
    try:
        torch.set_default_dtype(torch.bfloat16)
        with torch.device("meta"):
            model = Gemma4ForCausalLM(cfg)
    finally:
        torch.set_default_dtype(previous_dtype)
    model.to_empty(device="cuda")
    model.tie_weights()
    model.eval()
    sources = {}
    handles = []
    for shard in sorted((campaign / "weights/shards").glob("*.safetensors")):
        if shard.stat().st_mtime > receipt["checked_epoch"]:
            raise ValueError("source shard changed after verification")
        handle = safe_open(shard, framework="pt", device="cpu")
        handles.append(handle)
        for name in handle.keys():
            if name.startswith("model.language_model."):
                sources[name.replace("model.language_model.", "model.", 1)] = (handle, name)
    packed = campaign / "weights/shards" / (
        "gemma-4-31b-5bbc2fb1c1b2c611d06e3d9f23c170ba21659d89.packed.i16")
    if packed.stat().st_size != receipt["packed_bytes"] or packed.stat().st_mtime > receipt["checked_epoch"]:
        raise ValueError("packed changed after verification")
    mapped = np.memmap(packed, dtype="<i2", mode="r") if precision == "i16-dequant-bf16" else None
    with torch.inference_mode():
        for name, parameter in model.named_parameters():
            if name not in sources or name not in layout:
                raise ValueError(f"missing pinned parameter: {name}")
            source, original_name = sources[name]
            row = layout[name]
            if parameter.numel() != row["rows"] * row["columns"]:
                raise ValueError(f"parameter shape differs: {name}")
            if mapped is None:
                tensor = source.get_tensor(original_name)
            else:
                first = row["packed_offset"]
                array = mapped[first:first + parameter.numel()].astype(np.float32)
                tensor = torch.from_numpy(array).reshape(parameter.shape)
                tensor.mul_(math.ldexp(1.0, candidate["weight_exponents_by_tensor"][original_name]))
            if tuple(tensor.shape) != tuple(parameter.shape) or not torch.isfinite(tensor).all().item():
                raise ValueError(f"nonfinite or malformed weight: {name}")
            parameter.copy_(tensor)
            del tensor
        for i, layer in enumerate(model.model.layers):
            key = f"model.layers.{i}.layer_scalar"
            source, original_name = sources[key]
            scalar = source.get_tensor(original_name)
            public = metadata['public_layer_scalars'][i]
            if (public['layer'] != i or public['name'] != original_name
                    or scalar.dtype != torch.bfloat16 or list(scalar.shape) != public['shape']
                    or scalar.numel() != 1
                    or (int(scalar.view(torch.int16).item()) & 0xffff) != public['bf16_bits']):
                raise ValueError("pinned public layer scalar bits differ")
            layer.layer_scalar.copy_(scalar)
        model.model.embed_tokens.embed_scale.fill_(model.model.embed_tokens.scalar_embed_scale)
    model.model.rotary_emb = Gemma4TextRotaryEmbedding(cfg, device="cuda")
    if any(not torch.isfinite(buffer).all().item() for buffer in model.buffers()):
        raise ValueError("nonfinite model buffer")
    torch.cuda.synchronize()
    load_ns = time.perf_counter_ns() - load_start
    del handles, sources, mapped
    torch.cuda.empty_cache()
    raw_head_checks = 0
    raw_head_dtypes = set()

    def check_raw_head(_module, _inputs, value):
        nonlocal raw_head_checks
        if not torch.isfinite(value).all().item():
            raise ValueError('nonfinite raw logits before softcap')
        raw_head_checks += 1
        raw_head_dtypes.add(str(value.dtype))

    model.lm_head.register_forward_hook(check_raw_head)
    record({"stage": "load_end", "wall_ns": load_ns,
            "allocated_bytes": torch.cuda.memory_allocated(), "reserved_bytes": torch.cuda.memory_reserved()})
    passes = []
    with torch.inference_mode():
        for mode in ("warmup", "teacher_forcing", "free_generation"):
            cache = DynamicCache(config=cfg)
            rows = []
            contexts = admitted[:1] if mode == "warmup" else admitted
            for reference in contexts:
                old = reference["old_tokens"]
                if cache.get_seq_length() != old:
                    raise ValueError("KV continuation length differs")
                torch.cuda.synchronize()
                response_started = time.perf_counter_ns()
                tokens = list(prompt)
                decisions = []
                durations = []
                # All prompt logits are computed, matching the integer executor's head work.
                for step, current in enumerate(schedule(prompt, reference["tokens"])):
                    if mode == "free_generation" and step:
                        current = [tokens[-1]]
                    ids = torch.tensor([current], dtype=torch.long, device="cuda")
                    mask = torch.ones((1, old + len(tokens)), dtype=torch.long, device="cuda")
                    torch.cuda.synchronize()
                    started = time.perf_counter_ns()
                    result = model(input_ids=ids, attention_mask=mask, past_key_values=cache,
                                   use_cache=True, logits_to_keep=0)
                    if not torch.isfinite(result.logits).all().item():
                        raise ValueError("nonfinite logits")
                    if step < 50:
                        selected = int(result.logits[0, -1].argmax().item())
                        decisions.append(selected)
                        tokens.append(reference["tokens"][100 + step] if mode != "free_generation" else selected)
                    torch.cuda.synchronize()
                    durations.append(time.perf_counter_ns() - started)
                    del result
                if len(tokens) != 150 or cache.get_seq_length() != old + 150:
                    raise ValueError("final generated token was not consumed into KV")
                row = {"old_tokens": old, "tokens": tokens, "selected_tokens": decisions,
                       "agreements_with_admitted_next_token": sum(a == b for a, b in zip(decisions, reference["tokens"][100:])),
                       "prefill_ns": durations[0], "decode_including_final_kv_ns": sum(durations[1:]),
                       "response_total_ns": time.perf_counter_ns() - response_started,
                       "forward_ns": sum(durations), "forward_calls": 51,
                       "final_kv_tokens": cache.get_seq_length(),
                       "gpu_allocated_bytes": torch.cuda.memory_allocated(),
                       "gpu_reserved_bytes": torch.cuda.memory_reserved()}
                rows.append(row)
                record({"stage": mode, "old_tokens": old, "forward_ns": row["forward_ns"],
                        "final_kv_tokens": row["final_kv_tokens"]})
            passes.append({"mode": mode, "responses": rows})
            del cache
    if raw_head_checks != 357:
        raise ValueError('raw head finite-check coverage differs from the 357 forwards')
    report = {"credit": False, "readiness": False, "complete_comparison": True,
              "scope": "SDPA floating inference only; no integer parity, proof or Gamma admission",
              "precision": precision, "torch": torch.__version__, "transformers": transformers.__version__,
              "attention_backend": "sdpa", "tf32": False, "batch_size": 1,
              "bf16_reduced_precision_reduction": torch.backends.cuda.matmul.allow_bf16_reduced_precision_reduction,
              "config_sha256": hashlib.sha256(config_bytes).hexdigest(),
              "history_sha256": hashlib.sha256(history_path.read_bytes()).hexdigest(),
              "workload_sha256": hashlib.sha256(workload_path.read_bytes()).hexdigest(),
              "packed_sha256": receipt["packed_sha256"], "load_wall_ns": load_ns,
              "maximum_gpu_allocated_bytes": torch.cuda.max_memory_allocated(),
              "maximum_gpu_reserved_bytes": torch.cuda.max_memory_reserved(), "passes": passes,
              "raw_head_finite_checks": raw_head_checks, "raw_head_dtypes": sorted(raw_head_dtypes),
              "timing_scope": "Forward intervals synchronize CUDA and include finite checks/greedy decisions. Response total also includes input/mask preparation. All 50 generated tokens consumed into KV; W load and warmup separate."}
    with (output / "report.json").open("x") as sink:
        json.dump(report, sink, indent=2)
        sink.write("\n")
    record({"stage": "complete"})
    events.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("campaign", type=Path)
    parser.add_argument("history", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("precision", choices=("bf16-source", "i16-dequant-bf16"))
    args = parser.parse_args()
    run(args.campaign, args.history, args.output, args.precision)


if __name__ == "__main__":
    main()
