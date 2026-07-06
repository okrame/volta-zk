# Benchmark Plan (phase P conventions)

Fixes the *definitions*; live numbers live in `docs/prototype-status.md`
(ledger) and `benchmarks/results/*.json`. Updated 2026-07-06 (was a
placeholder; pre-phase workloads and GPU-only metrics pruned — 7B-class model,
long sequence lengths, GPU memory, and PCG expansion throughput return with
the P7 extrapolation / the pre-P7 real-PCG spike).

## Primary metric

```text
rho = prover_wall_time / native_inference_wall_time
```

Native = our own fixed-point Rust forward with proving off — the only
apples-to-apples denominator on CPU. Timing on this VM uses ABBA paired
interleaving (`time_paired`), never sequential A-then-B (frequency drift).
CPU ρ is architectural; the ρ targets (≤2 decode, ≤5 prefill) are GPU targets
decided by P7's extrapolation.

## Workloads of record

- P5: GPT-2 small (124M), prefill T=100, causal, real HF weights, 4-core CPU.
- P6: prompt 100 tokens + 50 decode steps, authenticated KV cache.

## Per-run JSON schema (`benchmarks/results/<milestone>-<date>-<sha>.json`)

- machine, shapes, git sha + `git_dirty` flag (a dirty run's sha names the
  parent commit — prefer clean-tree runs of record)
- wall times: native, witness generation, prover, verifier
- counts: lookups by table, boundary tensors, E-mults, correlations consumed
- communication bytes, broken down: auth corrections, sumcheck/LogUp
  transcripts, multiplicity vectors, **PCS opening bytes** (from P5)
- **total communication per response** — first-class number from P5 (product
  constraint, ballpark ~55 MB to confirm or kill)
- peak RSS (11 GB VM constraint)

Never overwrite old runs.

## Kill benchmark (P6)

```text
verified_tokens_per_second / native_tokens_per_second
```

with an append-only authenticated KV cache. Per-token proof cost must scale
with the new decoding work (O(seq·d), flat per token) — PCS claims *and*
lookup instances batched cross-token, never per-token fixed cost.

## Comparisons (P7 report context, not gates)

Native quantized inference; NanoZK-style public proving; zkGPT / zkLLM /
Mystique-lineage from reported numbers. Headline target: ≥10× vs NanoZK-style
proving at the same model, precision, and hardware class.
