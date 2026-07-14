# P7 cloud runbook

Status: P7 cloud screening, resident integration, the full e2e measurement
and the exact same-host native anchor are complete. The final P7 A100 record is
`p7-integrated-resident-2026-07-13-1fd5195.json` paired with
`p7-gpu-native-inference-2026-07-13-1fd5195.json`: correctness,
communication and flat-cost gates pass, while ρ=3707.595/95.597 fails the
10/2 targets. Detailed history stays in the ledger and append-only JSONs.
Microkernel and hybrid gates remain historical attribution/screening and
must not be relabeled as the resident e2e result. Exact reproduction commands
and the hardware manifest are in `docs/p7-artifact.md`. P7b now uses the
separately preregistered `runpod-a100-v1` official profile; see
`docs/p7b-runpod-official-runbook.md`. No historical P7 or P7b result is
promoted retroactively.

## Provider / instance

The sole P7b official-verdict provider is RunPod on the exact
`runpod-a100-v1` A100-SXM4-80GB profile with eight Rayon workers. Profile
fields are exact gate inputs, not descriptive labels; the Rust writer and
Python selector fail closed on a mismatch. Other providers are permitted only
for explicitly non-gating diagnostics. Record provider, instance, region,
image, driver, CUDA version, GPU SKU, CPU model, RAM, vCPU inventory and actual
Rayon worker count in every cloud JSON. Historical provider records remain
append-only comparison artifacts and are not operational configuration.

## Result Hygiene

Bench outputs are append-only. The RunPod box must not overwrite local numbers
or reuse a local rho. Treat its disk as ephemeral: after every baseline or GPU
spike, pull the JSONs back to this local checkout before stopping the pod.

- Keep cloud work on a clean checkout/commit (`git status --short` empty
  before run-of-record commands). Commit cloud JSONs separately from local
  JSONs.
- Result filenames include date + git sha; current P7/P6/P1/report helpers
  choose a `-1`, `-2`, ... suffix if the exact filename already exists. Do
  not rename cloud files over local files.
- Local and cloud JSONs may live in the same `benchmarks/results/`
  directory, but compare only runs with the same machine/provider class.
  Provider, region, image, CUDA/driver, GPU SKU, CPU model and RAM must be
  recorded in the ledger before quoting cloud numbers.
- `git_dirty:false` is required for any cloud run of record. Untracked result
  files do not make the tree dirty; tracked code/config/doc edits do.
- Because `target-cpu=native` is enabled, first regenerate the cloud CPU
  baselines and use those denominators for rho. Never divide cloud prover
  or GPU timings by a local VM native baseline.
- Store cloud connection details only in the local `.env`, e.g.
  `CLOUD_HOST=64.247.206.140`, `CLOUD_PORT=30174`,
  `CLOUD_USER=ubuntu`, `CLOUD_SSH_KEY=...`. Do not commit secrets or live
  credentials.
- Pull results back locally with `scripts/cloud_pull_results.sh`. The helper
  copies `benchmarks/results/*.json` from `CLOUD_REMOTE_REPO` into the local
  `benchmarks/results/`; run it before terminating the box.

## Setup

```sh
source ~/.cargo/env
git status --short
cd rust
cargo check --workspace
```

Regenerate generated artifacts if absent:

```sh
.venv/bin/python scripts/export_gpt2.py
.venv/bin/python scripts/dump_golden.py --gen 50
```

## Required pre-GPU measurements

Re-measure native CPU baselines on the cloud box before quoting any rho.
`rust/.cargo/config.toml` uses `target-cpu=native`, so local CPU ratios are
not portable. These runs create cloud-specific JSONs; do not overwrite or
delete the local JSONs already in `benchmarks/results/`.

```sh
cd rust
cargo run --release -p volta-bench --bin p1_report
cargo run --release -p volta-bench --bin p6_report
```

Then regenerate the P7 aggregate:

```sh
cd ..
python3 scripts/report.py --write-json
```

After each command that writes a JSON, return to the local machine and run:

```sh
scripts/cloud_pull_results.sh
```

Then inspect and commit the pulled JSONs locally. Do not rely on the cloud
disk as storage.

## GPU spike order

1. ~~Real-PCG budget~~ **SATISFIED locally** (2026-07-07): `volta-pcg`
   phase A/B measured 3.2–4.4 s expansion + 1.08 MB setup comm for the P6
   volume (`p7-real-pcg-2026-07-07-a7a2a85.json`, corrected run). No cloud
   PCG work needed for the go/no-go; see handoff spec §4.4 for the
   remaining hardening (not on the critical path).
2. Goldilocks/Fp2 arithmetic roofline on the target GPU.
3. Fused MAC epilogue kernel. Keep it fused with GEMM.
4. LogUp fraction-tree kernels.
5. PCS row/global passes and blake3 hashing.

## Invariants

- No per-token proof instances or per-token PCS claims.
- PCS openings still resolve into VOLE-authenticated values; never cleartext
  weight evaluations.
- Q=150 remains exploratory only. Default/run-of-record protocol constants
  stay Q=200 unless a separate soundness decision is logged first.
- Static-query cache is accounting/design only until a separate protocol
  split is registered.
- Any GPU path must keep golden decode, flat-cost, and anti-replay gates
  unchanged.
