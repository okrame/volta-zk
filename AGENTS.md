# VOLTA-ZK — project instructions

Designated-verifier proving system for fixed-point transformer inference using
VOLE-MAC blind GKR.  Formal milestones M1–M11 are closed and frozen in
`lean/`.  Prototype history is append-only; this file contains durable working
rules, not a second state ledger.

## Authority and orientation

Before acting, read in this order:

1. `docs/prototype-status.md` — the single source of truth for the active
   milestone, gates, measured values, credits, hard stops and deviations;
2. the current task-specific design named by that ledger entry.

The ledger and its active design override historical designs, runbooks and
this file's examples.  Do not infer the active milestone from an old commit or
from this file.  A ledger/design **HARD STOP** is terminal for that line of
work: do not substitute an unproved relation, claim component evidence as a
full result, or contact a provider/pod until the recorded unblock and any
required owner GO exist.

The `## Active authority — read first` capsule at the top of
`docs/prototype-status.md` is the required short-form orientation.  Update it
in the same commit as every active-milestone or active-status change.  Keep it
at **250 words or fewer, excluding its heading**; it must state the active
milestone/design, hard stop and authorization, completed evidence versus
credit, current checks, and exact resume conditions.  The append-only material
below it is supporting history, not competing authority.

## Records and milestone discipline

- Update `docs/prototype-status.md` at every milestone boundary, whenever a
  measured value lands, or whenever a decision deviates from the plan.
- Raw benchmark runs are new files under
  `benchmarks/results/<milestone>-<date>-<gitsha>.json`; never overwrite an
  old run.  A run of record requires a clean tree and `git_dirty: false`.
- A milestone end requires a scoped commit checkpoint and ledger update.
- Preserve unrelated dirty work.  Do not fold user files or historical
  artifacts into a protocol commit.
- Production/provider work needs the explicit owner GO required by the active
  ledger.  Production records are create-new and append-only; no selective
  retry is allowed unless separately authorized.

## Build, test and generated artifacts

- Rust is installed through rustup, not the default `PATH`:
  `source ~/.cargo/env`; then use `cd rust && cargo test --workspace`.
- All local Cargo commands, including standalone third-party manifests, share
  the canonical `rust/target`. Do not create top-level, per-crate or
  per-experiment target directories. Set `CARGO_INCREMENTAL=0` for broad
  checks. After a milestone checkpoint, and before leaving a working session,
  remove the canonical target and any ignored nested targets; retaining a
  build cache requires owner approval.
- Use the narrowest relevant test first; run the full workspace before a
  milestone checkpoint when resources permit.  `rust/.cargo/config.toml`
  pins `target-cpu=native`, so timing results are machine-specific.  Re-measure
  the native baseline with the registered paired method before quoting a new
  rate on another machine.
- Milestone reports are `cargo run --release -p volta-bench --bin <report>`;
  the active design names the applicable report and any e2e scripts.
- Python uses the repository `.venv`; `pytest` is the global uv tool.  Use the
  active budget script named by the design, not an historical budget by
  default.
- Weights and golden artifacts in `benchmarks/weights/` are generated, not
  committed.  Generate them only through the registered export/dump scripts.
- Lean is frozen unless the protocol statement changes:
  `export PATH="$HOME/.elan/bin:$PATH"; cd lean && lake build`. If Lean is
  opened, remove `lean/.lake` after the checkpoint unless explicitly retained.
- Before a broad local build, check guest free space and confirm that the host
  has at least 60 GiB free. Heavy benchmarks and every end-to-end run belong
  on the owner-provided pod, never on the local VM.

## Research documents

- The owner permanently preauthorizes AnyDoc conversion for relevant PDFs
  found online. Save each PDF and its same-stem Markdown under
  `/home/okrame/projects/volta-zk/sota`, read the Markdown rather than the PDF,
  and never overwrite an existing artifact. No per-PDF confirmation is
  required under this standing authorization.

## Non-negotiable protocol conventions

- `docs/quantization-spec.md` is frozen.  The Rust fixed-point forward is the
  witness generator and must remain bit-for-bit aligned with
  `scripts/gpt2_fixed.py`; golden checks are load-bearing.
- Do not buy prover time with certificate bytes or communication.  The active
  ledger/design supplies the binding byte, setup, prover, verifier and memory
  gates; all certificate framing counts.
- Never introduce per-token proof instances or per-token PCS claims.  Decode
  proving is deferred and stacked as specified by the active design.
- PCS openings resolve into VOLE-authenticated values, never cleartext
  `W̃(r)`.  Batch only as the active statement authorizes.
- Corrections are 8-byte `F_p` values.  Correlations are connection-scoped,
  one-time and domain-separated; account for every consumption.
- Production correlations use the real/AES PCG.  Mock PCG is diagnostic only;
  production paths fail closed and may not silently fall back to CPU.
- Protocol code must mirror the applicable Lean theorems.  Record any
  uncovered assumption in the ledger deviations log before relying on it.
- Distinguish executable seams, analytic screens and measured full-chain
  results.  Never promote a `credit:false` screen to proof-size, timing,
  memory, session or hardware credit.
