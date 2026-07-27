# VOLTA-ZK — agent instructions

Designated-verifier proving system for transformer inference (VOLE-MAC blind
GKR), GPT-2 small fixed-point. Formal milestones M1–M11 are CLOSED (Lean
theorems in `lean/`, frozen). Prototype milestones P0–P7b, fase-D and X1–X3
are CLOSED.
X4/X4d is suspended with immutable history. Current phase: **C4 Ligero inline
rate reduction** — same-build A100 comparison of the unchanged T1
`rate=1/4,Q=120` anchor and the `rate=1/8,Q=97` candidate. Phase 1 is locally
complete. The first Phase-2 campaign is **fail-closed at anchor resource
admission with no workload, performance record or gate verdict**: the selected
pod exposed 13.6 cgroup CPUs, conservatively admitted as 13 against the frozen
minimum of 16. The candidate was not started and the pod is stopped. Owner
Amendment 1 is locally complete: the future floor is 13 effective CPUs, backed
by the immutable green T1 A100 record at 13 CPUs / 8 Rayon; 12 still rejects.
Another pod contact or production pair requires a new explicit owner GO.

**Read `docs/prototype-status.md` first**, then the current task-specific
design named by its latest ledger entry. For C4, that is
`docs/c4-ligero-inline-rate-design.md`. The ledger and current design are the
plan of record; historical runbooks and designs do not override them.

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
- Corrections are 8 bytes (F_p). Correlations are connection-scoped,
  one-time use and domain-separated; every consumption is counted.
- Production correlations use the real/AES PCG; mock PCG is diagnostic and
  test-only. Production records are fail-closed and may not fall back to CPU.
- Protocol code mirrors the Lean theorems (M2–M11 as applicable); anything
  the theorems don't cover goes in the ledger's deviations log first.
- Milestone end = commit checkpoint + ledger update.
- Pod/provider contact requires an explicit owner GO after the local
  checkpoint. Production runs use create-new append-only records and permit
  no selective retry unless separately authorized.
