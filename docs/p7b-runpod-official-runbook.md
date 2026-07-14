# P7b RunPod official runbook

This is the exact reproduction contract for the `runpod-a100-v1` profile.
The ledger entry `P7b RunPod official-provider and gate-profile migration` is
authoritative. Historical Thunder measurements and the RunPod ABI-27 control
are comparison artifacts, not substitutes for this run.

## Fixed profile

The report is official-eligible only when all values match exactly:

| Field | Required value |
| --- | --- |
| Provider / region | `RunPod` / `eur-is-1` |
| Image | `Ubuntu 24.04.3 LTS` |
| Driver / CUDA | `580.159.04` / `12.8` |
| GPU | `NVIDIA A100-SXM4-80GB` |
| CPU | `AMD EPYC 7713 64-Core Processor` |
| RAM / provider vCPUs | `1008` GiB / `255` |
| Prover CPU budget | `RAYON_NUM_THREADS=8` |
| Backend / ABI | `cuda-resident` / current ABI 28 |
| Timing | `wall-only-counters` |

The instance id must be present but is intentionally not pinned. A different
image, driver, region or hardware revision is a new profile and needs a ledger
deviation before measurement.

## Clean build and differential

Use a clean checkout of the intended commit and the existing generated weight
and golden artifacts. Verify their checksums against the ledger/control
manifest, then build and test the current backend:

```sh
source "$HOME/.cargo/env"
cd "$HOME/volta-zk"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
VOLTA_CUDA_ARCH=sm_80 scripts/build_cuda_backend.sh
export VOLTA_CUDA_LIBRARY="$PWD/target/cuda/libvolta_cuda_backend.so"
cargo test --manifest-path rust/Cargo.toml -p volta-accel --features cuda
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Set the serialized machine profile explicitly. Do not derive the Rayon budget
from the provider's vCPU inventory:

```sh
export VOLTA_CLOUD_PROVIDER='RunPod'
export VOLTA_CLOUD_INSTANCE_ID='REPLACE_WITH_CURRENT_POD_ID'
export VOLTA_CLOUD_REGION='eur-is-1'
export VOLTA_CLOUD_IMAGE='Ubuntu 24.04.3 LTS'
export VOLTA_CLOUD_DRIVER_VERSION='580.159.04'
export VOLTA_CLOUD_CUDA_VERSION='12.8'
export VOLTA_CLOUD_GPU_SKU='NVIDIA A100-SXM4-80GB'
export VOLTA_CLOUD_CPU_MODEL='AMD EPYC 7713 64-Core Processor'
export VOLTA_CLOUD_RAM_GIB='1008'
export VOLTA_CLOUD_VCPUS='255'
export RAYON_NUM_THREADS=8
```

## Quick then official

The runner enforces the exact profile, a clean unchanged SHA, Q=200,
counters-only timing and external staging. It first runs T=16+8 with 0+1,
then T=100+50 with 1+3 and validates the latter through the same fail-closed
selector used by `scripts/report.py`. A valid performance failure exits zero;
an incomplete or ineligible report exits non-zero. Completed raw JSONs are
restored append-only even if a later step fails.

```sh
cd "$HOME/volta-zk"
STAGING="$HOME/p7b-runpod-official-$(git rev-parse --short=12 HEAD)"
test ! -e "$STAGING"
scripts/run_p7b_runpod_official.sh "$STAGING"
sha256sum benchmarks/results/p7b-integrated-resident-*-wall-only-counters-*.json
```

Before terminating the pod, copy the two new JSONs and their SHA-256 values to
the canonical local checkout. Confirm the official full JSON again with:

```sh
python3 scripts/report.py \
  --validate-p7b-official benchmarks/results/REPLACE_WITH_FULL_RESULT.json
```

Record quick/full measurements, checksums and the valid pass/fail verdict in
`docs/prototype-status.md`. Raw synchronization count remains diagnostic. The
sync gate is the maximum per-repetition
`synchronization_s / t_response_session_wall_s <= 0.02`; no <=5,000 count
criterion exists under this profile. Mock-PCG remains non-production.
