# VOLTA-ZK

VOLTA is a research prototype for designated-verifier proofs of quantized
transformer inference. The implemented workload is GPT-2 small with a
VOLE-MAC blind-GKR/LogUp prover and a field-native Ligero-style PCS for
private weights. The formal M1–M9 phase is closed; P7 integrates and measures
the optional CUDA backend.

This repository is a paper artifact, not a production service or a stable
library API. In particular, the default correlation provider is mock PCG and
the measured real-PCG path is a setup cost model, not a production-grade
two-party implementation. See [the status ledger](docs/prototype-status.md)
for the current claims, raw-run provenance, deviations and open security
assumptions.

## Repository map

- `rust/`: fixed-point GPT-2, authenticated protocol, prover/verifier, PCS,
  accelerator seam and benchmark binaries.
- `cuda/`: versioned internal CUDA backend. CPU remains the default build.
- `lean/`: frozen Lean 4 formalization and named-assumption boundary.
- `scripts/`: weight export, golden generation, one-command benchmarks and
  the P7 aggregate report.
- `benchmarks/results/`: append-only raw JSON measurements.
- `docs/`: protocol, quantization, benchmark plan, P7 handoff and cloud
  runbook.

## Quick validation

Rust is installed through rustup and is not assumed to be on the default
`PATH`:

```bash
source "$HOME/.cargo/env"
cd rust
cargo test --workspace
cd ..
pytest -q tests/test_report.py
scripts/audit_lean.sh
```

The CPU-only workspace does not load or require CUDA. Requesting CUDA without
the feature/library fails explicitly; there is no silent CPU fallback.

With the generated frozen artifacts present, a short end-to-end response run
is:

```bash
source "$HOME/.cargo/env"
cd rust
cargo run --release -p volta-bench --bin p6_report -- --quick
```

The full CPU commands of record are `scripts/run_prefill.sh` and
`scripts/run_decode.sh`. They are intentionally expensive and write a new,
never-overwritten JSON under `benchmarks/results/`.

## Frozen weights and golden outputs

`gpt2s-q.bin` and the upstream `model.safetensors` are generated/local
artifacts and are not committed. Starting from the public GPT-2
`model.safetensors` in `benchmarks/weights/`:

```bash
.venv/bin/python scripts/export_gpt2.py
.venv/bin/python scripts/dump_golden.py --gen 50
sha256sum -c benchmarks/weights/SHA256SUMS
```

Quantization semantics are frozen in
[`docs/quantization-spec.md`](docs/quantization-spec.md). The Rust forward is
the witness generator and the NumPy golden checks are load-bearing gates.

## CUDA validation

On the pinned A100 environment, build the version-checked shared backend and
run CUDA tests explicitly:

```bash
NVCC=/usr/local/cuda/bin/nvcc CUDA_ARCH=sm_80 scripts/build_cuda_backend.sh
cd rust
export VOLTA_CUDA_LIBRARY="$PWD/../target/cuda/libvolta_cuda_backend.so"
export VOLTA_REQUIRE_CUDA=1
cargo test --features cuda --workspace
```

The exact quick/full resident benchmark commands and pinned hardware manifest
are maintained in the P7 artifact section once the resident run of record is
closed. Until then, microkernel and hybrid JSONs must not be presented as a
resident end-to-end result.

## Reports and provenance

Regenerate the aggregate report without mutating protocol parameters:

```bash
python3 scripts/report.py
python3 scripts/report.py --write-json
```

Every run records the commit, dirty state, workload, timings and byte
breakdown. A quoted run of record must have `git_dirty: false`; generated
JSONs are append-only. Machine-specific timings are not portable because the
Rust benchmark build pins `target-cpu=native`.

## Security boundary

Transcript/proof format, verifier logic and quantization are shared by CPU
and CUDA paths. CUDA keeps challenges and transcript orchestration in Rust
and returns only protocol messages and public outputs. Remaining operational
blockers—including real two-party PCG, parameter hardening, proof-bundle
versioning, commitment lifecycle and a deployment threat model—are documented
as future work, not production claims.
