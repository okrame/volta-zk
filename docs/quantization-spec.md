# Quantization Spec (P0, frozen for the CPU prototype)

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
