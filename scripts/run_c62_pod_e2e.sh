#!/usr/bin/env bash
# Run one fresh C6.2 A100 genesis, CPU verification, and mutation record.
# Set C62_SETUP_SOURCE to copy a previously generated deterministic setup into
# the required create-new SETUP_ROOT instead of regenerating all 17 profiles.

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

SETUP_SOURCE=${C62_SETUP_SOURCE:-}
if [[ -n $SETUP_SOURCE ]]; then
  if [[ $SETUP_SOURCE != /* || ! -d $SETUP_SOURCE ]]; then
    echo "C62_SETUP_SOURCE must be an absolute existing directory" >&2
    exit 2
  fi
  if [[ $SETUP_SOURCE == "$SETUP_ROOT" ]]; then
    echo "C62_SETUP_SOURCE and SETUP_ROOT must differ" >&2
    exit 2
  fi
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

VOLTA_CUDA_ARCH=sm_80 scripts/check_c62_gpu_native_boundary.sh
export VOLTA_CUDA_LIBRARY="$REPO_ROOT/target/cuda/libvolta_cuda_backend.so"
export RAYON_NUM_THREADS=8
cargo test --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --bin c62_whir_fiat_shamir_record \
  --features cuda,c6-trace,c61-p3-authenticated-reference

if [[ -n $SETUP_SOURCE ]]; then
  mkdir "$SETUP_ROOT"
  cp -a --reflink=auto "$SETUP_SOURCE/." "$SETUP_ROOT/"
  diff \
    <(cd "$SETUP_SOURCE" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum) \
    <(cd "$SETUP_ROOT" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum)
else
  cargo run --release --manifest-path rust/Cargo.toml \
    -p volta-bench \
    --bin c62_setup_bundle_record \
    --features c6-trace \
    -- \
    --weights "$WEIGHTS_DIR" \
    --setup-root "$SETUP_ROOT"
fi

mkdir "$SESSION_ROOT"
cleanup_spill() {
  local status=$?
  if [[ -d $SESSION_ROOT/run ]]; then
    rm -rf -- "$SESSION_ROOT/run"
  fi
  if [[ -d $WORK_ROOT/c62gw4-provider-cache ]]; then
    rm -rf -- "$WORK_ROOT/c62gw4-provider-cache"
  fi
  return "$status"
}
trap cleanup_spill EXIT

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

CUDA_VISIBLE_DEVICES='' cargo run --release --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --bin c62_whir_fiat_shamir_record \
  --features cuda,c6-trace,c61-p3-authenticated-reference \
  -- \
  --mode verify \
  --artifact-root "$SESSION_ROOT/artifacts/certificate-00" \
  --threads 4 \
  --output "$SESSION_ROOT/verifier.json"

cargo run --release --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --bin c62_whir_fiat_shamir_record \
  --features cuda,c6-trace,c61-p3-authenticated-reference \
  -- \
  --mode mutate \
  --artifact-root "$SESSION_ROOT/artifacts/certificate-00" \
  --output "$SESSION_ROOT/mutations.json"

(
  cd "$SESSION_ROOT"
  find artifacts/certificate-00 -type f -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 sha256sum \
    > artifact-00-files.sha256
  tar -cf artifact-00.tar artifacts/certificate-00
)

(
  cd "$SESSION_ROOT"
  sha256sum \
    setup-measurement.json \
    preflight.json \
    session.json \
    verifier.json \
    mutations.json \
    artifact-00-files.sha256 \
    artifact-00.tar \
    > checksums.sha256
)

if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  echo "the source tree changed during the C6.2 pod run" >&2
  exit 1
fi

echo "C6.2 pod E2E completed: $SESSION_ROOT"
