# P7b iteration 3 co-located A100 attribution control

Status: **prepared, not executed**. This is the Phase-0c one-off attribution
control. A result from Lambda, RunPod, or any provider other than Thunder is
never a P7b gate claim. Thunder remains the designated target and the sole
official-verdict provider.

## Pinned inputs

- Source commit: `098b2f128b7152cf7a4c701cba6dd0d8a876e578`, the exact
  clean commit used for the complete Phase-0a A/B.
- Source bundle: `/tmp/volta-zk-098b2f1.bundle` on the preparing machine.
- Bundle SHA-256:
  `64076288e251ea45194dd6b442e8f09f0862c3c64692734c2d6770b0f3a6ba77`.
- `gpt2s-q.bin` SHA-256:
  `bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a`.
- `gpt2s-q.json` SHA-256:
  `98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c`.
- `gpt2s-q.params` SHA-256:
  `264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac`.
- `golden-p6.bin` SHA-256:
  `e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862`.

Before transfer, verify the source locally:

```sh
cd /home/okrame/projects/volta-zk
test "$(git rev-parse HEAD)" != ""
git bundle verify /tmp/volta-zk-098b2f1.bundle
sha256sum /tmp/volta-zk-098b2f1.bundle \
  benchmarks/weights/gpt2s-q.bin \
  benchmarks/weights/gpt2s-q.json \
  benchmarks/weights/gpt2s-q.params \
  benchmarks/weights/golden-p6.bin
```

Transfer only after the user supplies an already-provisioned co-located A100
endpoint. Do not put credentials in the repository:

```sh
source .env
: "${CONTROL_HOST:?} ${CONTROL_PORT:?} ${CONTROL_USER:?} ${CONTROL_SSH_KEY:?}"
scp -F /dev/null -i "$CONTROL_SSH_KEY" -P "$CONTROL_PORT" \
  /tmp/volta-zk-098b2f1.bundle \
  benchmarks/weights/gpt2s-q.bin \
  benchmarks/weights/gpt2s-q.json \
  benchmarks/weights/gpt2s-q.params \
  benchmarks/weights/golden-p6.bin \
  "$CONTROL_USER@$CONTROL_HOST:/home/$CONTROL_USER/"
```

## Exact remote setup and build

These commands assume an Ubuntu A100 host with CUDA installed. The provider,
instance and region values are supplied by the instance owner; the remaining
metadata is read from that host.

```sh
export CONTROL_PROVIDER='REPLACE_WITH_PROVIDER'
export CONTROL_INSTANCE_ID='REPLACE_WITH_INSTANCE_ID'
export CONTROL_REGION='REPLACE_WITH_REGION'

cd "$HOME"
test "$(sha256sum volta-zk-098b2f1.bundle | cut -d' ' -f1)" = \
  64076288e251ea45194dd6b442e8f09f0862c3c64692734c2d6770b0f3a6ba77
git clone "$HOME/volta-zk-098b2f1.bundle" "$HOME/volta-zk-control-098b2f1"
cd "$HOME/volta-zk-control-098b2f1"
git checkout --detach 098b2f128b7152cf7a4c701cba6dd0d8a876e578
test "$(git rev-parse HEAD)" = 098b2f128b7152cf7a4c701cba6dd0d8a876e578

mkdir -p benchmarks/weights
mv "$HOME/gpt2s-q.bin" "$HOME/gpt2s-q.json" \
  "$HOME/gpt2s-q.params" "$HOME/golden-p6.bin" benchmarks/weights/
test "$(sha256sum benchmarks/weights/gpt2s-q.bin | cut -d' ' -f1)" = \
  bdd193720adc8243c64897eaf1b9cd27883ae5613552c96ed4533c52892adc6a
test "$(sha256sum benchmarks/weights/gpt2s-q.json | cut -d' ' -f1)" = \
  98927cac03348c23b06ef336aca027bdd0af54c7fbd9ca2116b61a81fd065a9c
test "$(sha256sum benchmarks/weights/gpt2s-q.params | cut -d' ' -f1)" = \
  264dd1c8fcde2e82bf404e8442375d61783b18961507c2cf5fa83217d8f3b2ac
test "$(sha256sum benchmarks/weights/golden-p6.bin | cut -d' ' -f1)" = \
  e102783acef548d30af65e56d636b6fc51a72697922e256aa5c97ded90567862
test -z "$(git status --porcelain=v1 --untracked-files=all)"

nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader
test "$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)" = \
  'NVIDIA A100-SXM4-80GB'
source "$HOME/.cargo/env"
VOLTA_CUDA_ARCH=sm_80 scripts/build_cuda_backend.sh
export VOLTA_CUDA_LIBRARY="$PWD/target/cuda/libvolta_cuda_backend.so"
cd rust
cargo test -p volta-accel --features cuda
cd ..
test -z "$(git status --porcelain=v1 --untracked-files=all)"
```

Set the complete schema-6 provider record before either measurement:

```sh
export VOLTA_CLOUD_PROVIDER="$CONTROL_PROVIDER"
export VOLTA_CLOUD_INSTANCE_ID="$CONTROL_INSTANCE_ID"
export VOLTA_CLOUD_REGION="$CONTROL_REGION"
. /etc/os-release
export VOLTA_CLOUD_IMAGE="$PRETTY_NAME"
export VOLTA_CLOUD_DRIVER_VERSION="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader | head -1)"
export VOLTA_CLOUD_CUDA_VERSION="$(/usr/local/cuda/bin/nvcc --version | sed -n 's/.*release \([0-9][0-9.]*\).*/\1/p' | tail -1)"
export VOLTA_CLOUD_GPU_SKU="$(nvidia-smi --query-gpu=name --format=csv,noheader | head -1)"
export VOLTA_CLOUD_CPU_MODEL="$(lscpu | sed -n 's/^Model name:[[:space:]]*//p' | head -1)"
export VOLTA_CLOUD_RAM_GIB="$(awk '/MemTotal/ {printf "%.0f", $2/1024/1024}' /proc/meminfo)"
export VOLTA_CLOUD_VCPUS="$(nproc)"
```

## Exact quick and full invocations

The quick result is moved outside the checkout before the full run so both
measurements begin and serialize at an unchanged clean SHA.

```sh
cd "$HOME/volta-zk-control-098b2f1"
CONTROL_RESULTS="$HOME/p7b-colocated-control-results-098b2f1"
test ! -e "$CONTROL_RESULTS"
mkdir -p "$CONTROL_RESULTS"
test -z "$(git status --porcelain=v1 --untracked-files=all)"

cargo run --release --manifest-path rust/Cargo.toml \
  -p volta-bench --features cuda --bin p6_report -- \
  --quick \
  --accelerator cuda-resident \
  --resident-timing wall-only-counters \
  --warmup-repetitions 0 \
  --repetitions 1
mapfile -t QUICK_RESULT < <(git ls-files --others --exclude-standard -- benchmarks/results)
test "${#QUICK_RESULT[@]}" -eq 1
mv "${QUICK_RESULT[0]}" "$CONTROL_RESULTS/"
test -z "$(git status --porcelain=v1 --untracked-files=all)"

cargo run --release --manifest-path rust/Cargo.toml \
  -p volta-bench --features cuda --bin p6_report -- \
  --accelerator cuda-resident \
  --resident-timing wall-only-counters \
  --warmup-repetitions 1 \
  --repetitions 3
mapfile -t FULL_RESULT < <(git ls-files --others --exclude-standard -- benchmarks/results)
test "${#FULL_RESULT[@]}" -eq 1
mv "${FULL_RESULT[0]}" "$CONTROL_RESULTS/"
test -z "$(git status --porcelain=v1 --untracked-files=all)"
sha256sum "$CONTROL_RESULTS"/*.json
```

## Expected-output checklist

Both JSONs must satisfy all of the following before they are copied back as
append-only attribution artifacts:

- `report_schema_version == 6`, full git SHA equals the pinned SHA, and all
  three dirty-tree fields are false.
- `accelerator_backend == "cuda-resident"`, CUDA ABI is 27,
  `resident_timing_policy == "wall-only-counters"`, every measured
  `accelerator_session.timing_method == "wall-only-counters"`, and
  `phase_attribution_available == false`.
- Timing records, elapsed attempts/no-write/query counts and aggregate
  CUDA-event API calls are all zero. Event-derived phase durations are null,
  not zero.
- Every proof is accepted; communication, PCG allocation, cleanup and cache
  trim invariants pass. Mock-PCG remains marked non-production.
- The quick run has T=16+8, Q=200, no golden claim, 39,201 host-output syncs,
  12,656,708 B H2D and 81,518,420 B D2H.
- The full run has T=100+50, Q=200, at least one warmup and three measured
  repetitions, and both golden-decode fields are true.
- Because this is a different provider,
  `p7b_machine_eligible == false` and `p7b_gate_evaluated == false` in both
  outputs. Any timing is attribution-only even if it is numerically below a
  Thunder gate.

Stop after copying the two JSONs and their SHA-256 values back to the local
append-only results directory. Do not run scheduler or protocol variants on
the control host.
