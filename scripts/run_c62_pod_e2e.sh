#!/usr/bin/env bash
# Run one fresh C6.2 A100 setup, preflight, session, and mutation record.

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 WEIGHTS_DIR SETUP_ROOT WORK_ROOT SESSION_ROOT" >&2
  exit 2
fi

WEIGHTS_DIR=$1
SETUP_ROOT=$2
WORK_ROOT=$3
SESSION_ROOT=$4
REPO_ROOT=$(git rev-parse --show-toplevel)

for path in "$WEIGHTS_DIR" "$SETUP_ROOT" "$WORK_ROOT" "$SESSION_ROOT"; do
  if [[ $path != /* ]]; then
    echo "all paths must be absolute" >&2
    exit 2
  fi
done

case "$SETUP_ROOT" in
  "$REPO_ROOT"/*)
    echo "SETUP_ROOT must be outside the source tree" >&2
    exit 2
    ;;
esac
case "$SESSION_ROOT" in
  "$REPO_ROOT"/*)
    echo "SESSION_ROOT must be outside the source tree" >&2
    exit 2
    ;;
esac

if [[ ! -d $WEIGHTS_DIR || ! -d $WORK_ROOT ]]; then
  echo "WEIGHTS_DIR and WORK_ROOT must exist" >&2
  exit 2
fi
if [[ -e $SETUP_ROOT || -e $SESSION_ROOT ]]; then
  echo "SETUP_ROOT and SESSION_ROOT must be new paths" >&2
  exit 2
fi
if [[ $(stat -c %d "$WORK_ROOT") != $(stat -c %d "$(dirname "$SESSION_ROOT")") ]]; then
  echo "WORK_ROOT and SESSION_ROOT must use one filesystem" >&2
  exit 2
fi

required_cloud=(
  VOLTA_CLOUD_PROVIDER
  VOLTA_CLOUD_INSTANCE_ID
  VOLTA_CLOUD_REGION
  VOLTA_CLOUD_IMAGE
  VOLTA_CLOUD_DRIVER_VERSION
  VOLTA_CLOUD_CUDA_VERSION
  VOLTA_CLOUD_GPU_SKU
  VOLTA_CLOUD_CPU_MODEL
  VOLTA_CLOUD_RAM_GIB
  VOLTA_CLOUD_VCPUS
  CUDA_VISIBLE_DEVICES
)
for name in "${required_cloud[@]}"; do
  if [[ -z ${!name:-} ]]; then
    echo "$name is required" >&2
    exit 2
  fi
done
if [[ $VOLTA_CLOUD_PROVIDER != RunPod || $CUDA_VISIBLE_DEVICES == *,* ]]; then
  echo "the record requires RunPod and one visible GPU" >&2
  exit 2
fi

cd "$REPO_ROOT"
source "$HOME/.cargo/env"
if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  echo "the C6.2 pod run requires a clean source tree" >&2
  exit 2
fi

VOLTA_CUDA_ARCH=sm_80 scripts/build_cuda_backend.sh
export VOLTA_CUDA_LIBRARY="$REPO_ROOT/target/cuda/libvolta_cuda_backend.so"
export RAYON_NUM_THREADS=8

cargo test --manifest-path rust/Cargo.toml -p volta-accel --features cuda
cargo test --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --bin c62_whir_fiat_shamir_record \
  --features cuda,c6-trace,c61-p3-authenticated-reference

cargo run --release --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --bin c62_setup_bundle_record \
  --features c6-trace \
  -- \
  --weights "$WEIGHTS_DIR" \
  --setup-root "$SETUP_ROOT"

mkdir "$SESSION_ROOT"
cargo run --release --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --bin c62_setup_bundle_measure \
  --features c6-trace,c61-p3-authenticated-reference \
  -- \
  --weights "$WEIGHTS_DIR" \
  --setup-root "$SETUP_ROOT" \
  > "$SESSION_ROOT/setup-measurement.json"

cargo run --release --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --bin c62_whir_fiat_shamir_record \
  --features cuda,c6-trace,c61-p3-authenticated-reference \
  -- \
  --mode preflight \
  --weights "$WEIGHTS_DIR" \
  --setup-dir "$SETUP_ROOT" \
  --work-root "$WORK_ROOT" \
  --output "$SESSION_ROOT/preflight.json"

cargo run --release --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --bin c62_whir_fiat_shamir_record \
  --features cuda,c6-trace,c61-p3-authenticated-reference \
  -- \
  --mode prove \
  --weights "$WEIGHTS_DIR" \
  --setup-dir "$SETUP_ROOT" \
  --work-root "$WORK_ROOT" \
  --run-root "$SESSION_ROOT/run" \
  --artifact-root "$SESSION_ROOT/artifacts" \
  --state-root "$SESSION_ROOT/state" \
  --output "$SESSION_ROOT/session.json"

cargo run --release --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --bin c62_whir_fiat_shamir_record \
  --features cuda,c6-trace,c61-p3-authenticated-reference \
  -- \
  --mode mutate \
  --artifact-root "$SESSION_ROOT/artifacts/certificate-00" \
  --output "$SESSION_ROOT/mutations.json"

sha256sum \
  "$SESSION_ROOT/setup-measurement.json" \
  "$SESSION_ROOT/preflight.json" \
  "$SESSION_ROOT/session.json" \
  "$SESSION_ROOT/mutations.json" \
  > "$SESSION_ROOT/checksums.sha256"

if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  echo "the source tree changed during the C6.2 pod run" >&2
  exit 1
fi

echo "C6.2 pod E2E completed: $SESSION_ROOT"
