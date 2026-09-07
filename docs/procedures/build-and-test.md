# Build, test and generated artifacts

Read [current status](../prototype-status.md) first. This procedure explains
how to run authorized work; it does not authorize a heavy build or E2E.

## Choose the check

Start with the narrowest relevant check. For C7.1 arithmetic/accounting:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c7_1_gemma_plan.py
.venv/bin/python scripts/c7_1_gemma_plan.py
```

Python scripts use the repository `.venv`; `pytest` is the global uv tool.
Use the script/report named by the active design. Historical budget scripts
are reference diagnostics when their specific assumptions are needed.
Documentation changes need link, consistency and diff checks, not Rust/Lean
builds. Existing passing checks need repeating only after relevant changes.

## Rust and resource limits

Rust is installed through rustup. All Cargo commands, including standalone
third-party manifests, share the absolute repository `rust/target`:

```bash
source "$HOME/.cargo/env"
export CARGO_TARGET_DIR="$(git rev-parse --show-toplevel)/rust/target"
export CARGO_INCREMENTAL=0
cd rust
cargo test --workspace
```

This is the broad workspace command, not the default check for every task.
Before a broad local build, check guest space and confirm at least 60 GiB free
on the host; guest `df` alone does not establish host capacity. Run the full
workspace before a protocol milestone checkpoint when authorized resources
permit; otherwise state the validation gap. Heavy benchmarks and every E2E
belong on the authorized pod, never on the local VM.

Do not create per-crate, top-level or experimental Cargo targets. Remove the
canonical target and ignored nested Cargo targets after a milestone checkpoint
and before leaving the session; keeping a build cache requires owner approval.
`rust/.cargo/config.toml` pins `target-cpu=native`: timing is machine-specific.
Re-measure the registered paired baseline before quoting rates on another CPU.
Reports use `cargo run --release -p volta-bench --bin <report>` with the active
design's report and workload.

## Lean and generated assets

Formal M1–M11 milestones are closed and frozen. Open Lean only when the protocol
statement requires it; if authorized, use `export PATH="$HOME/.elan/bin:$PATH"`,
then `cd lean && lake build`. Remove `lean/.lake` after the checkpoint unless
explicitly retained.

Weights and generated golden artifacts under `benchmarks/weights/` are produced
only by the registered export/dump scripts and are not newly committed as model
assets. Preserve existing tracked fixtures and evidence. The frozen GPT-2
[quantization spec](../quantization-spec.md), `scripts/gpt2_fixed.py` and Rust
forward must remain bit-identical when that baseline is touched. C7.1 requires
its own Gemma semantic/runtime correspondence as specified in design §2.1;
GPT-2 golden success does not validate Gemma.

Raw runs are new files under `benchmarks/results/<milestone>-<date>-<gitsha>.json`.
Keep every failure and all framing/resource costs. A run of record requires a
clean source tree and `git_dirty: false`; corrections go in a new linked record.
