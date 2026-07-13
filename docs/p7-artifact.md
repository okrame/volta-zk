# P7 paper artifact — resident CUDA end to end

This artifact reproduces the final P7 result on GPT-2 small. It is designed
to reproduce claims, including the negative performance result, rather than
to present VOLTA-ZK as a service or stable library.

## Claims and limits

The clean A100 full run supports these claims:

- fixed-point golden decode, resident proof, the unchanged verifier and all
  13 Q=200 PCS openings pass;
- flat-cost last/first is 0.950 (gate <=1.5);
- packed response download is 144,820,930 B (inside 150--200 MB);
- explicit resident allocations return to 0 B after context reuse; reusable
  workspace remains separately reported;
- protocol-core rho is 3707.595 prefill and 95.597 decode, so both
  preregistered targets (10/2) **fail**.

The artifact does not claim production readiness, a stable API, a network
service, production two-party PCG, or Llama/gpt-oss end to end. The latter
appear only in the explicitly synthetic shape/memory JSON.

Run-of-record provenance and checksums are pinned in
[`artifact/p7/hardware-a100.json`](../artifact/p7/hardware-a100.json). Raw
JSONs are append-only and must not be edited or renamed.

## Frozen inputs

Place the public GPT-2 `model.safetensors` under `benchmarks/weights/`, then
generate the fixed-point artifact and golden files if they are absent:

```bash
.venv/bin/python scripts/export_gpt2.py
.venv/bin/python scripts/dump_golden.py --gen 50
sha256sum -c benchmarks/weights/SHA256SUMS
```

`SHA256SUMS` pins both the public upstream file and every derived artifact.
The large upstream and quantized weight blobs are reproducible and therefore
not committed.

## Quick validation

The CPU/default path requires no CUDA:

```bash
source "$HOME/.cargo/env"
cd rust
cargo test --workspace
cd ..
pytest -q tests
export PATH="$HOME/.elan/bin:$PATH"
(cd lean && lake build)
scripts/audit_lean.sh
```

The audit requires the eight frozen M1--M9 theorems to depend only on the
standard Lean axioms and checks that the four named external assumptions in
`VoltaZk/Ideal.lean` have not entered that proved boundary.

## A100 quick and full commands

The record environment is CUDA 13.2, driver 610.43.02, A100 sm_80 and Rust
1.97.0. Export the cloud fingerprint fields for every JSON; use a stable,
non-secret instance identifier so the report can join proof and native
anchor only when they came from the same host.

```bash
export VOLTA_CLOUD_PROVIDER="Thunder Compute"
export VOLTA_CLOUD_INSTANCE_ID="<stable-instance-id>"
export VOLTA_CLOUD_REGION="<region-or-not-exposed>"
export VOLTA_CLOUD_IMAGE="base / Ubuntu 22.04.5 LTS"
export VOLTA_CLOUD_DRIVER_VERSION="610.43.02"
export VOLTA_CLOUD_CUDA_VERSION="toolkit 13.2 / driver 610.43.02"
export VOLTA_CLOUD_GPU_SKU="NVIDIA A100-SXM4-80GB"
export VOLTA_CLOUD_CPU_MODEL="<lscpu model and cgroup quota>"
export VOLTA_CLOUD_RAM_GIB="64"
export VOLTA_CLOUD_VCPUS="8 (quota 7.92)"

NVCC=/usr/local/cuda/bin/nvcc VOLTA_CUDA_ARCH=sm_80 \
  scripts/build_cuda_backend.sh
export VOLTA_CUDA_LIBRARY="$PWD/target/cuda/libvolta_cuda_backend.so"
export VOLTA_REQUIRE_CUDA=1
```

Quick harness/lifecycle gate (T=16+8, one sample, not a paper rho):

```bash
cd rust
cargo run --release -p volta-bench --bin p6_report --features cuda -- \
  --quick --accelerator cuda-resident \
  --warmup-repetitions 0 --repetitions 1
cd ..
```

Full record (T=100+50, Q=200, one warmup plus three samples):

```bash
cd rust
cargo run --release -p volta-bench --bin p6_report --features cuda -- \
  --accelerator cuda-resident \
  --warmup-repetitions 1 --repetitions 3
cd ..
```

Use the new full JSON as the explicit same-host correctness baseline for the
seven-repetition native-GPU anchor:

```bash
python3 scripts/p7_gpu_native_inference.py \
  --baseline benchmarks/results/<new-full-resident.json>
```

Do not quote rho unless both full JSONs are clean, golden-exact and share the
same `cloud.instance_id`.

## Aggregate, tables and figures

```bash
python3 scripts/p7_shape_memory_sweep.py --write-json
python3 scripts/report.py --write-json
python3 scripts/p7_artifact_outputs.py
python3 scripts/p7_artifact_outputs.py --check
```

The last command regenerates `artifact/p7/generated/` from raw JSON only.
The shape sweep validates scaling formulas but marks all non-GPT rows as
analytic projections and emits no proof-time or proof-peak projection.

## Security and operational blockers

The formal protocol and proof format are unchanged by CUDA. The remaining
model-owner/product blockers are deliberately documentation-only: genuine
two-party PCG, cited/hardened parameters and malicious checks, proof-bundle
versioning, commitment lifecycle, and an operational threat model. Multi-GPU,
multi-tenancy and production deployment are outside P7.
