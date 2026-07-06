# Quantization Spec (P0, frozen for the CPU prototype; P5 amendments 2026-07-06)

This is the exact arithmetic the witness generation must reproduce. The Rust
fixed-point forward pass in `rust/volta-gpt2` *is* the witness generator; the
numpy reference in `scripts/` must match it bit-for-bit on the golden prompt.

## Domains

| Object | Domain | Notes |
| --- | --- | --- |
| Quantized values (weights, activations, LUT in/out) | `i16`, symmetric, zero-point 0 | 16-bit heritage from NanoZK LUTs (ΔPPL = 0.00%) |
| GEMM accumulators | `i64` | max `K = 3072`: |acc| ≤ 3072·2^15·2^15 < 2^42 — **no modular reduction inside the kernel** |
| Field plaintexts | Goldilocks `F_p`, p = 2^64 − 2^32 + 1 | embed `x: i16` as `x mod p` |
| MAC tags, keys, Δ, challenges | `E = F_p²` | ~2^124 statistical soundness per opening |

## Scales

- Per-tensor symmetric scales, **powers of two** (`s = 2^e`), chosen offline by
  `scripts/export_gpt2.py` from the f32 weight/activation ranges (calibration on
  the golden prompt).
- Requantization after every GEMM / nonlinear op: `y = clamp(round(acc / 2^e), -2^15, 2^15-1)`,
  implemented in-circuit as a 16-bit LUT (`requant_*` in the budget); in the
  kernel it is a shift+round+clamp (must match the LUT exactly).

## Nonlinearities (16-bit LUTs, NanoZK-style)

`exp` (softmax numerator), `softmax_recip` (1/Σ), `gelu`, `ln_rsqrt`
(1/√(var+ε)), plus the `requant_*` tables. Tables generated once by
`scripts/export_gpt2.py`; identical tables used by the numpy reference, the
Rust witness generator, and the LogUp prover.

LayerNorm mean/variance are computed in `i64` from the `i16` inputs
(exact integer sums), then normalized via `ln_rsqrt` LUT + requant.

## P5 amendments (real weights — ledger 2026-07-06)

- **Stable softmax**: the exp LUT is base-e and is looked up on the shifted
  score `s' = s − c_row`, where `c_row` is defined as the max of the causal
  row of requantized scores. The LUT is faithful on `x ≤ 0` only (its proved
  table content is the nonpositive domain — membership doubles as the range
  check); soundness of `c_row = max` comes from `s' ≤ 0` plus a per-row
  product-zero check `Π_j s'_j = 0` (Π_Prod).
- **Embedding requant**: `wte`/`wpe` are quantized at their own scale
  `f_wte`; `embed_out = round_half_up((wte[tok] + wpe[pos]) / 2^shift_embed)`
  lands on the residual-stream scale — one extra 13th LUT (`requant_embed`),
  T·d lookups per prefill. `wte` is tied: the last-position logits row is the
  `i64` accumulator `final_ln_out · wteᵀ` with **no requant** (budget counts
  its MACs, no lookups).
- **Biases**: all GEMM biases and LN gains/biases are quantized at the
  OUTPUT scale of their op and folded into the accumulator before requant
  (`acc += b << shift_op`). They are public verifier inputs (the private
  tensors are the four projection matrices and wte/wpe, committed via PCS).
- **Residual-stream scales are per layer** (`f_res[l]`, monotone
  non-increasing — GPT-2 outlier channels make a global scale destroy early
  layers, measured 2026-07-06): segment `l` covers `x_in(l)`,
  `attn_block_out(l)`, `ffn_block_out(l)`; between layers a **seam requant**
  `x_in(l+1) = round_half_up(ffn_block_out(l) / 2^{seam_shift[l]})`
  (shift 0 = identity, free). Everything not facing the residual (LN path,
  qkv, scores, softmax, gelu tables) keeps ONE global shift/LUT set — the
  `ln_rsqrt` table is scale-free in the input scale by construction. Weight
  exponents are per tensor-type.
- **Chained requant**: any requant with shift `s > 16` is DEFINED as the
  two-stage `requant(requant(acc, s−16), 16)` (double rounding), so no
  remainder range table exceeds 2^16.
- All scales remain powers of two; the frozen real tables, shifts and prompt
  live in `benchmarks/weights/gpt2s-q.{bin,json,params}` produced by
  `scripts/export_gpt2.py`.

## Corrections and bandwidth (M5 honesty note)

Π_Auth corrections are typed `F_p` = **8 bytes/value** — this is what the M5
Lean theorem (`sub_correction_uniform`) covers: the subfield of `E = F_p²` is
`F_p` itself, masks sampled uniform in `F_p`, correction `δ = x − r` uniform
in `F_p`.

The concept-note claim of 16-bit (2-byte) corrections is **not** covered by
M5: `[0, 2^16)` is not subtraction-closed in `F_p`, so a mod-2^16 correction
breaks MAC linearity by a carry; fixing it costs one authenticated carry bit
per value. Tracked as an open optimization in the ledger — the prototype
ships 8-byte corrections and reports honest byte counts.

## What gets authenticated (fused-block design)

Per layer: attention block output, FFN block output, K, V (each `T×d`).
Globally: embedding output, final-LN output at the sampled position.
Everything else (Q, attention scores, exp outputs, softmax weights, FFN-up
activations, GELU in/out) is an internal wire of a fused GKR block, proved via
LogUp — never authenticated, never communicated.
