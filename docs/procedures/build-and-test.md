# Build, test and generated artifacts

Read [current status](../prototype-status.md) first. This procedure explains
how to run authorized work; it does not authorize a heavy build or E2E.

## Choose the check

Start with the narrowest relevant check. For C7.1 arithmetic/accounting:

```bash
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c7_1_gemma_plan.py
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c7_1_baseline_budget.py
PYTHONDONTWRITEBYTECODE=1 pytest -q -p no:cacheprovider tests/test_c71_bootstrap.py
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python scripts/c7_1_gemma_plan.py
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
For the authorized B9 component, run from `rust` with the same absolute
target and `CARGO_INCREMENTAL=0`:

```bash
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_DEV_OPT_LEVEL=2 cargo test --offline --locked -j 2 -p volta-pcg --features c71-bootstrap c71_b9 -- --test-threads=1
```

From the repository root, `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python
scripts/run_c71_bootstrap.py --n 3` runs one OS-random two-role component
case; `--n 32` is the other registered size and `--fault` selects a bounded
adversarial case. It reuses the existing 60 s / 2 GiB / two-thread launcher,
uses only local Unix socketpairs and preserves failures. The script builds
only the `volta-pcg` example at opt-level 2, with no separate Cargo target.
This is not the stopped B7 matrix runner or a full Gemma E2E. The source
tree must be clean for a run of record; a detached temporary worktree can
preserve unrelated edits while sharing the canonical target.

For the owner-authorized B11 intermediate component, the same runner accepts
`--suite b11 --n 180` or `--n 207`, and `--suite b11 --n 3 --fault ...` for
the ten byte faults. It builds only the example with `c71-b11`, including
the existing MAC consumer diagnostic. Limits remain 60 s / 2 GiB / two
threads. Run the narrow native tests using the command above with
`--features c71-b11 c71_b`; this also retains the B7 negative and B9 checks.
The Python bootstrap/budget checks cover the conditional lifetime arithmetic.
These are component checks, with no durable-pool or PCS/Gemma admission.

For the owner-authorized B12 finite-pool component, the same narrow Cargo
command with `--features c71-b11 c71_b12 -- --test-threads=1` checks the
durable journal, completion-seal framing, subprocess crash/reopen and one
three-row real two-role MAC
transfer. The last check needs only a local Unix socketpair, as B9/B11 did;
if the sandbox denies it, permit that local test without external access.
No full workspace, matrix/Gemma runner or paid hardware is needed. These
are component tests, not run-of-record benchmarks or complete security evidence.

For the B12 salted PCS consumer, build only `volta-pcs` with the same Cargo
target and profile, `--features c71-b12-pcs --lib`, and run the `c71_b12`
test filter with one test thread. After compilation, bound the test binary
to 60 s and 2 GiB, with `RAYON_NUM_THREADS=1`. Its seven tests cover FS coin-block replay, unique-radius geometry (D35 configuration only), private
coin streams, salted Merkle/codec and three attempts of a 48×48 synthetic matrix using the real
180-row B11 roles and durable journal. The linear-form checks cover aligned
cubes and a 207-row real-B11 capacity: four original target MACs reach one
root/PCS, then a fresh false norm target is rejected and the run ends.
This internal bridge uses in-memory proof transport; it is not a Gemma runner
or standalone wire codec. These checks need only local Unix socketpairs.
The existing field/FS checks use `c71_matrix::tests::` with that feature.
The old B7 matrix runner rejects this feature before setup. This is an
opt-in component check, not a complete admitted PCS or Gemma execution.

Before a broad local build, check guest space and confirm at least 60 GiB free
on the host; guest `df` alone does not establish host capacity. Run the full
workspace before a protocol milestone checkpoint when authorized resources
permit; otherwise state the validation gap. Heavy benchmarks and full-model
E2E belong on authorized hardware, not the local VM. The owner's 2026-09-08
exception allows a small synthetic CPU E2E on this VM, within the
[active experiment contract](../c7.1-gemma31b-design.md#esperimento-ridotto-contratto-e-ambito-del-runner).
It does not authorize a broad build, GPU/provider access or paid resources.

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
