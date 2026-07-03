# VOLTA-ZK — project instructions

Designated-verifier proving system for transformer inference (VOLE-MAC blind
GKR). Formal phase M1–M8 is CLOSED (Lean theorems in `lean/`, see
`docs/protocol-sketch.md`). Current phase: **P — CPU prototype**, GPT-2 small,
prefill 100 tokens. Plan of record: `~/.claude/plans/streamed-hugging-bunny.md`.

## State ledger — read this first

`docs/prototype-status.md` is the single source of truth for milestone status,
gates, key numbers, and the deviations log. **Update it at every milestone
boundary and whenever a measured number lands or a decision deviates from the
plan.** Raw bench runs go to `benchmarks/results/<milestone>-<date>-<sha>.json`
(schema: machine, shapes, times, counts, bytes — never overwrite old runs).

## Build / test / bench

- Rust toolchain via rustup: `source ~/.cargo/env` (not on default PATH).
- Workspace: `cd rust && cargo test --workspace` | `cargo bench -p volta-bench`.
- Release flags are set in `rust/Cargo.toml` (`lto`, `codegen-units=1`); benches
  must run `--release` (criterion does).
- Python: `.venv` in repo root; `pytest` is a global uv tool. Budget:
  `python3 scripts/budget_p0.py`.
- Lean (frozen, only touch if protocol changes): `export PATH="$HOME/.elan/bin:$PATH"; cd lean && lake build`.

## Conventions

- Quantization semantics are frozen in `docs/quantization-spec.md`; the Rust
  fixed-point forward is the witness generator and must match the numpy
  reference bit-for-bit.
- Protocol code mirrors the Lean theorems (M2 ZeroBatch, M3 blind sumcheck,
  M4 KV-cache domain separation, M5 F_p-typed corrections, M7/M8 Π_Prod);
  when implementation needs something the theorems don't cover, log it in the
  ledger's deviations section — don't silently assume.
- Corrections are 8 bytes (F_p), not 16-bit — see ledger deviation 2026-07-03.
- Correlations are mock-PCG (shared ChaCha seed, Δ verifier-only), one-time
  use, domain-separated indices (session, layer, head, position, tensor_tag);
  every consumption is counted.
- Milestone end = commit checkpoint + ledger update + session-memory update.
