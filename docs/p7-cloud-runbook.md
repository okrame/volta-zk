# P7 cloud runbook

Status: cloud CPU baselines landed on the Thunder A100 instance on
2026-07-11. The clean cloud runs are
`benchmarks/results/p1-2026-07-11-64a8ead.json` and
`benchmarks/results/p6-2026-07-11-11e5630.json`; aggregate
`benchmarks/results/p7-2026-07-11-11e5630.json`. For this box the measured
relative prover-vs-native speedup requirement is 5.48x prefill / 3.97x
decode. The Goldilocks/Fp2 GPU roofline subsequently passed on replacement
instance `nc1k4a0g`: `p7-gpu-roofline-2026-07-11-a43d105.json` reports
55.48x stream / 300.94x chain speedup with full differential correctness.
The next step is the fused GEMM-MAC epilogue; no proving-path GPU kernel has
landed yet.

## Provider / instance

First option: Thunder Compute, H100 PCIe 80GB for roofline measurements. Use
A100 80GB when cost-constrained comparison is needed. Fallback: RunPod. Record
provider, region, image, driver, CUDA version, GPU SKU, CPU model, RAM, and
availability in `docs/prototype-status.md` and in every cloud JSON.

## Result Hygiene

Bench outputs are append-only. The cloud box must not overwrite local
numbers or reuse a local rho. Treat Thunder/RunPod disks as ephemeral:
after every baseline or GPU spike, pull the JSONs back to this local checkout
before stopping the instance.

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
