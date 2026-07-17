# Fase-D RunPod official runbook (G4 v1/v2)

This is the exact reproduction contract for the fase-D RunPod profiles. The
historical `runpod-a100-realpcg-v1` profile retains its 2% synchronization
fraction gate and both immutable FAIL records. The current prospective profile
is `runpod-a100-realpcg-v2`, whose only gate change is the preregistered maximum
absolute synchronization wall <=0.150 s. The authoritative amendment is
`docs/fase-d-g4-sync-gate-amendment.md`. The historical `runpod-a100-v1`
profile also remains immutable and is not a substitute for either fase-D run.

## Fixed profile

The first real-PCG measurement establishes a new pod-CPU host class. Complete
machine metadata is mandatory, but the old pod's region, image, driver, CPU,
RAM and vCPU identity are not inherited as gates:

| Field | Required value |
| --- | --- |
| Provider | `RunPod` |
| Region / image / driver / CUDA | recorded exactly from this pod |
| GPU | `NVIDIA A100-SXM4-80GB` |
| CPU / RAM / provider vCPUs | recorded exactly from this pod |
| Prover CPU budget | `RAYON_NUM_THREADS=8` |
| Backend / ABI | `cuda-resident` / current ABI 28 |
| Timing | `wall-only-counters` |

The instance id must be present. Setup wall, stage splits and traffic are an
informative first-run baseline; there is no setup-wall gate on this unmeasured
host class.

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
export VOLTA_CLOUD_REGION='REPLACE_WITH_CURRENT_REGION'
export VOLTA_CLOUD_IMAGE='REPLACE_WITH_CURRENT_IMAGE'
export VOLTA_CLOUD_DRIVER_VERSION='REPLACE_WITH_NVIDIA_DRIVER_VERSION'
export VOLTA_CLOUD_CUDA_VERSION='REPLACE_WITH_CUDA_VERSION'
export VOLTA_CLOUD_GPU_SKU='NVIDIA A100-SXM4-80GB'
export VOLTA_CLOUD_CPU_MODEL='REPLACE_WITH_CURRENT_CPU_MODEL'
export VOLTA_CLOUD_RAM_GIB='REPLACE_WITH_CURRENT_RAM_GIB'
export VOLTA_CLOUD_VCPUS='REPLACE_WITH_CURRENT_VCPUS'
export RAYON_NUM_THREADS=8
```

## Quick then official

The runner enforces the selected exact profile, a clean unchanged SHA, Q=200,
counters-only timing, real-PCG/AES, one connection-scoped base phase and
external staging. It first runs T=16+8 with 0+1, then T=100+50 with 1+3 and
validates the latter through the fase-D fail-closed selector. Pass `v2` as the
second runner argument for the current absolute-sync profile; omitting it
reproduces historical v1. The full report
also executes the G2 capacity/byte gate on the pod CPU and records the setup
wall split as informative. A valid measured performance failure is retained;
an incomplete or ineligible report exits non-zero. Completed raw JSONs are
restored append-only even if a later step fails.

```sh
cd "$HOME/volta-zk"
STAGING="$HOME/p7b-runpod-official-$(git rev-parse --short=12 HEAD)"
test ! -e "$STAGING"
scripts/run_p7b_runpod_official.sh "$STAGING" v2
sha256sum benchmarks/results/runpod-a100-realpcg-v2-*.json
```

Before terminating the pod, copy the two new JSONs and their SHA-256 values to
the canonical local checkout. Confirm the official full JSON again with:

```sh
python3 scripts/report.py \
  --validate-fase-d-pod-official benchmarks/results/REPLACE_WITH_FULL_RESULT.json
```

Record quick/full measurements, checksums, real-PCG setup/G2 observations and
the pass/fail verdict in `docs/prototype-status.md`. Raw synchronization count
remains diagnostic. V1 uses maximum per-repetition
`synchronization_s / t_response_session_wall_s <= 0.02`; v2 reports the same
fraction informatively but binds maximum per-repetition
`synchronization_s <= 0.150 s`. No count criterion exists. Mock-PCG is an
explicit test backend and cannot produce this record.
