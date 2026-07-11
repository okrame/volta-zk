#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NVCC="${NVCC:-/usr/local/cuda/bin/nvcc}"
OUT="${VOLTA_CUDA_LIBRARY:-$ROOT/target/cuda/libvolta_cuda_backend.so}"
ARCH="${VOLTA_CUDA_ARCH:-sm_80}"

mkdir -p "$(dirname "$OUT")"
"$NVCC" -std=c++17 -O3 --shared -Xcompiler=-fPIC -arch="$ARCH" \
  "$ROOT/cuda/volta_cuda_backend.cu" -o "$OUT"
printf '%s\n' "$OUT"
