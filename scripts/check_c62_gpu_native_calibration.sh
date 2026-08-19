#!/usr/bin/env bash
# Non-session A100 lower-bound calibration for the exact C62GW1 D28/D27
# initial lanes. It creates no setup, PCG state, proof, certificate or session.

set -euo pipefail

if [[ $# -ne 1 || $1 != /* ]]; then
  echo "usage: $0 /absolute/outside-repo-record.json" >&2
  exit 2
fi

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"
RECORD=$1

if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  echo "C62GW1 calibration requires a clean source tree" >&2
  exit 2
fi
if [[ $RECORD == "$REPO_ROOT"/* || -e $RECORD ]]; then
  echo "C62GW1 calibration record must be create-new and outside the repository" >&2
  exit 2
fi
if [[ ! -x /usr/local/cuda/bin/nvcc ]]; then
  echo "C62GW1 calibration requires /usr/local/cuda/bin/nvcc" >&2
  exit 2
fi
GPU=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits)
if [[ $GPU != *"A100-SXM4-80GB"* ]]; then
  echo "C62GW1 calibration requires one A100-SXM4-80GB; found: $GPU" >&2
  exit 2
fi

source "$HOME/.cargo/env"
export VOLTA_CUDA_ARCH=${VOLTA_CUDA_ARCH:-sm_80}
export VOLTA_CUDA_LIBRARY=${VOLTA_CUDA_LIBRARY:-$REPO_ROOT/target/cuda/libvolta_cuda_backend.so}
export VOLTA_REQUIRE_CUDA=1
export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-0}
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-8}
export CARGO_INCREMENTAL=0
export C62_CALIBRATION_RECORD=$RECORD
export C62_CALIBRATION_GIT_SHA=$(git rev-parse HEAD)
export C62_CALIBRATION_STARTED_UTC=$(date -u +%Y-%m-%dT%H:%M:%SZ)

scripts/build_cuda_backend.sh
timeout 1800 cargo test --release --manifest-path rust/Cargo.toml \
  -p volta-pcs \
  --features cuda,c61-p3-authenticated-reference,c6-trace \
  c61_authenticated_whir_p3::tests::c62_a100_initial_lower_bound_calibration \
  -- --ignored --exact --nocapture --test-threads=1

test -s "$RECORD"
echo "C62GW1_CALIBRATION_RECORD: $RECORD"
