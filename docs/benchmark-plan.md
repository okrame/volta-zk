# Benchmark Plan

## Primary Metric

Report the prover/native ratio instead of only absolute latency:

```text
rho = prover_wall_time / native_inference_wall_time
```

The headline target is at least 10x improvement versus NanoZK-style proving on
the same model, precision, sequence length, and hardware class.

## Workloads

Initial workloads:

- GPT-2 scale, prefill at sequence lengths 128, 512, 1024
- GPT-2 scale, autoregressive decoding with authenticated KV cache
- one 7B-class quantized model once the prototype is stable

## Baselines To Track

- native quantized inference
- NanoZK-style public proof, from reported numbers and any reproducible code
- zkGPT
- zkLLM
- Mystique and later VOLE-based zkML systems where comparable
- GKR/LogUp prototype without VOLE-MAC opening, if implementable

## Measurements

For each run:

- native inference wall time
- witness/prover wall time
- verifier wall time
- communication bytes
- preprocessing time and bytes
- PCG expansion throughput
- lookup count by operator
- boundary tensor count and bytes
- GPU memory peak
- end-to-end token/sec for decoding

## Kill Benchmark

The most important benchmark is long decoding:

```text
verified_tokens_per_second / native_tokens_per_second
```

with an append-only authenticated KV cache. The goal is to show that the proof
cost per new token scales with the new decoding work rather than reproving the
whole prompt.
