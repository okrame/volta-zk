#!/usr/bin/env bash
# Non-session A100 gate for the C62GW1 boundary. It builds the exact CUDA ABI
# and runs only byte-identity/resource tests; it never creates setup, PCG state
# or a production attempt.

set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
cd "$REPO_ROOT"

if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  echo "C62GW1 boundary check requires a clean source tree" >&2
  exit 2
fi
if [[ ! -x /usr/local/cuda/bin/nvcc ]]; then
  echo "C62GW1 boundary check requires /usr/local/cuda/bin/nvcc" >&2
  exit 2
fi
if ! nvidia-smi --query-gpu=name,memory.total --format=csv,noheader; then
  echo "C62GW1 boundary check requires one visible NVIDIA GPU" >&2
  exit 2
fi

source "$HOME/.cargo/env"
export VOLTA_CUDA_ARCH=${VOLTA_CUDA_ARCH:-sm_80}
export VOLTA_CUDA_LIBRARY=${VOLTA_CUDA_LIBRARY:-$REPO_ROOT/target/cuda/libvolta_cuda_backend.so}
export VOLTA_REQUIRE_CUDA=1
export CUDA_VISIBLE_DEVICES=${CUDA_VISIBLE_DEVICES:-0}
export RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-8}
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_TEST_DEBUG=0

scripts/build_cuda_backend.sh

timeout 600 cargo test --manifest-path rust/Cargo.toml \
  -p volta-accel \
  --features cuda \
  resident_c62_zk_padding_and_cached_add_are_bit_exact \
  -- --nocapture

timeout 600 cargo test --manifest-path rust/Cargo.toml \
  -p volta-pcs \
  --features cuda,c61-p3-authenticated-reference,c6-trace \
  c62_gpu \
  -- --nocapture

echo "C62GW1_BOUNDARY_PASS: ABI, kernels, roots, openings and full payload are exact"
