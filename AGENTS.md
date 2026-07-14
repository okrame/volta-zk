# VOLTA-ZK — agent instructions

Designated-verifier proving system for transformer inference (VOLE-MAC blind
GKR), GPT-2 small fixed-point. Formal phase M1–M9 is CLOSED (Lean theorems in
`lean/`, frozen). Prototype milestones P0–P7 are CLOSED. Current phase:
**P7b iteration 2** — resident-A100 orchestration and prover optimization on
RunPod. The official `runpod-a100-v1` profile and current gates are
pre-registered in the 2026-07-14 provider-migration ledger deviation. P7b is
in progress; no checkpoint or projection is itself a gate verdict.

**Read `docs/p7-handoff-spec.md` first**, including its P7b override — it and
the ledger are the plan of record: state and numbers of record, quantified
levers, invariants, and known traps.

## State ledger — single source of truth

`docs/prototype-status.md`: milestone status, gates, key numbers, deviations
log. Update it at every milestone boundary, whenever a measured number lands,
and whenever a decision deviates from plan — never silently assume. Raw bench
runs go to `benchmarks/results/<milestone>-<date>-<gitsha>.json` (never
overwrite old runs; runs of record need a clean tree, `git_dirty: false`).

## Build / test / bench

- Rust via rustup, not on default PATH: `source ~/.cargo/env`.
- `cd rust && cargo test --workspace` | `cargo bench -p volta-bench`.
- Milestone reports: `cargo run --release -p volta-bench --bin p6_report
  [--quick]` (likewise `p5_report`, …). One-command e2e:
  `scripts/run_prefill.sh`, `scripts/run_decode.sh`.
- Weights/golden artifacts in `benchmarks/weights/` are generated, not
  committed: `.venv/bin/python scripts/export_gpt2.py` then
  `.venv/bin/python scripts/dump_golden.py --gen 50`.
- Python: repo-root `.venv`; `pytest` is a global uv tool. Analytic budget:
  `python3 scripts/budget_p0.py`.
- Lean (frozen, only touch if the protocol changes):
  `export PATH="$HOME/.elan/bin:$PATH"; cd lean && lake build`.
- `rust/.cargo/config.toml` pins `target-cpu=native`: benches are
  machine-specific; on a new machine, re-measure the native baseline (ABBA
  paired timing, `time_paired`) before quoting any ρ.

## Non-negotiable conventions

- Quantization semantics are frozen in `docs/quantization-spec.md`; the Rust
  fixed-point forward is the witness generator and must match
  `scripts/gpt2_fixed.py` bit-for-bit (golden checks are load-bearing gates).
- Prover time may be bought with verifier time, **never with final proof
  size / communication** (the binding product constraint: ≤150–200 MB per
  response).
- Never per-token proof instances or per-token PCS claims; decode proving is
  deferred and stacked.
- PCS openings resolve into VOLE-authenticated values — never cleartext
  W̃(r); one batched opening per response.
- Corrections are 8 bytes (F_p). Correlations are mock-PCG, one-time use,
  domain-separated, every consumption counted.
- Protocol code mirrors the Lean theorems (M2–M8); anything the theorems
  don't cover goes in the ledger's deviations log first.
- Milestone end = commit checkpoint + ledger update.
