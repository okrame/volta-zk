#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
scratch_dir="$(mktemp -d)"
trap 'rm -rf "$scratch_dir"' EXIT

g++ -std=c++17 -O2 -Wall -Wextra -Werror \
    -I"$repo_dir/cuda" \
    "$repo_dir/cuda/x4b_host_reference.cpp" \
    -o "$scratch_dir/x4b_host_reference"

"$scratch_dir/x4b_host_reference" >"$scratch_dir/cuda.txt"
(
    cd "$repo_dir/rust"
    cargo run -q -p volta-bench --bin x4b_cuda_reference
) >"$scratch_dir/rust.txt"

diff -u "$scratch_dir/rust.txt" "$scratch_dir/cuda.txt"
echo "X4B_CUDA_HOST_REFERENCE_OK"
