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
Clean aggregate: `benchmarks/results/p7-2026-07-11-14bafb8.json`.
The fused GEMM-MAC spike then passed at weighted `rho_kernel=1.003`
(`p7-gpu-fused-epilogue-2026-07-11-bde5d7d.json`). The next step is the
LogUp fraction-tree spike, followed by PCS row/global passes plus blake3;
proving-path integration remains open.
Current clean aggregate: `benchmarks/results/p7-2026-07-11-27cc9a8.json`.
The LogUp lookup-side tree build also passed at N=2^24: 66.12x CPU/GPU with
every internal layer exact (`p7-gpu-logup-tree-2026-07-11-5f7b443.json`).
Next: LogUp sumcheck round/fold kernels, then PCS row/global + blake3.
Current clean aggregate: `benchmarks/results/p7-2026-07-11-959b40b.json`.
The LogUp general round/fold sequence passed narrowly at N=2^22: 6.766x with
all 22 per-round D2H barriers retained
(`p7-gpu-logup-rounds-2026-07-11-e4470bf.json`). Next: PCS row/global passes
plus blake3; blind correction plumbing and proving-path integration remain.
Current clean aggregate: `benchmarks/results/p7-2026-07-11-fd67e64.json`.
PCS P4_LAYER arithmetic passed: NTT 80.33x and combine_rows 76.10x with exact
outputs (`p7-gpu-pcs-arithmetic-2026-07-11-366ec4a.json`). Column gather +
BLAKE3/Merkle then passed at exact P4_LAYER geometry: Rust 43.779 ms versus
GPU 1.407 ms = 31.10x, with exact Rust root and every host/device node
(`p7-gpu-blake3-merkle-2026-07-11-3b0a916.json`). NTT + hash totals 7.793 ms
on GPU. Next: mask/blind plumbing, proving-path integration, native GPU
inference anchor and unchanged e2e gates.
Current clean aggregate: `benchmarks/results/p7-2026-07-11-e4e0772.json`.
Blind general-layer LogUp plumbing subsequently passed on replacement instance
`6mprfo7p`: CPU 265.26 ms versus GPU 41.30 ms = 6.423x, all 848 correction
bytes exact, blind/clear 0.903 <=1.05 and zero extra transcript rounds
(`p7-gpu-logup-blind-rounds-2026-07-11-534dcad.json`). Pageable-buffer and
four-micro-copy failures are retained in the ledger. This replacement has a
different Xeon 8470 CPU, so its native P6 baseline must be remeasured before
quoting a new rho. Next: aux-leaf corrections, proving-path integration and
native GPU inference anchor.
That replacement baseline is now complete:
`p6-2026-07-11-f72e4dd.json` reports native prefill/decode 0.9956/1.7295 s,
CPU rho 20.512/8.294 and replacement-instance requirements **4.1025x prefill /
4.1468x decode**. It supersedes 5.48x/3.97x only for `6mprfo7p`; the native
GPU inference anchor remains open.

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
