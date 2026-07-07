# P7 cloud runbook

Status: local pre-cloud P7 is complete as of 2026-07-07. The local report of
record is `benchmarks/results/p7-2026-07-07-d0812a7.json`; the clean CPU
baseline with transcript-label breakdown is
`benchmarks/results/p6-2026-07-07-382bb56.json`.

## Provider / instance

First option: Thunder Compute, H100 PCIe 80GB for roofline measurements. Use
A100 80GB when cost-constrained comparison is needed. Fallback: RunPod. Record
provider, region, image, driver, CUDA version, GPU SKU, CPU model, RAM, and
availability in `docs/prototype-status.md` and in every cloud JSON.

## Setup

```sh
source ~/.cargo/env
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
not portable.

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
