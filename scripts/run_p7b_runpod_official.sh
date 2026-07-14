#!/usr/bin/env bash
# Clean same-SHA RunPod quick preflight followed by the official P7b run.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ROOT/benchmarks/results"
STAGING="${1:-}"

if [[ -z "$STAGING" || "$STAGING" != /* ]]; then
  echo "usage: $0 ABSOLUTE_EMPTY_STAGING_DIRECTORY" >&2
  exit 2
fi
case "$STAGING/" in
  "$ROOT/"*)
    echo "staging directory must be outside the repository" >&2
    exit 2
    ;;
esac
if [[ -e "$STAGING" ]]; then
  if [[ ! -d "$STAGING" || -n "$(find "$STAGING" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo "staging path must be a missing or empty directory" >&2
    exit 2
  fi
else
  mkdir -p "$STAGING"
fi

required_env=(
  VOLTA_CUDA_LIBRARY
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
  RAYON_NUM_THREADS
)
for name in "${required_env[@]}"; do
  if [[ -z "${!name:-}" ]]; then
    echo "$name is required" >&2
    exit 2
  fi
done
if [[ ! -f "$VOLTA_CUDA_LIBRARY" ]]; then
  echo "VOLTA_CUDA_LIBRARY does not name a built ABI-28 backend" >&2
  exit 2
fi

expect_env() {
  local name="$1"
  local expected="$2"
  if [[ "${!name}" != "$expected" ]]; then
    echo "$name must be '$expected', got '${!name}'" >&2
    exit 2
  fi
}

expect_env VOLTA_CLOUD_PROVIDER "RunPod"
expect_env VOLTA_CLOUD_REGION "eur-is-1"
expect_env VOLTA_CLOUD_IMAGE "Ubuntu 24.04.3 LTS"
expect_env VOLTA_CLOUD_DRIVER_VERSION "580.159.04"
expect_env VOLTA_CLOUD_CUDA_VERSION "12.8"
expect_env VOLTA_CLOUD_GPU_SKU "NVIDIA A100-SXM4-80GB"
expect_env VOLTA_CLOUD_CPU_MODEL "AMD EPYC 7713 64-Core Processor"
expect_env VOLTA_CLOUD_RAM_GIB "1008"
expect_env VOLTA_CLOUD_VCPUS "255"
expect_env RAYON_NUM_THREADS "8"

if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
  echo "official P7b run requires a clean tree before the quick preflight" >&2
  exit 2
fi
start_sha="$(git -C "$ROOT" rev-parse HEAD)"
if [[ ! "$start_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "unable to resolve a full source SHA" >&2
  exit 2
fi

staged=()
destinations=()

# Preserve every completed raw measurement even if a later run or the
# fail-closed official validator exits non-zero. Staging keeps the next run's
# provenance clean; this trap restores append-only results only on exit.
restore_results() {
  local index
  for index in "${!staged[@]}"; do
    if [[ -e "${staged[$index]}" && ! -e "${destinations[$index]}" ]]; then
      mv "${staged[$index]}" "${destinations[$index]}"
      printf '%s\n' "${destinations[$index]}"
    fi
  done
}
trap restore_results EXIT

run_report() {
  local label="$1"
  shift
  if [[ "$(git -C "$ROOT" rev-parse HEAD)" != "$start_sha" ]] ||
     [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
    echo "source revision or cleanliness changed before $label" >&2
    exit 2
  fi

  cargo run --release --manifest-path "$ROOT/rust/Cargo.toml" \
    -p volta-bench --features cuda --bin p6_report -- \
    --accelerator cuda-resident \
    --resident-timing wall-only-counters \
    --pcs-q 200 \
    "$@"

  mapfile -t new_results < <(
    git -C "$ROOT" ls-files --others --exclude-standard -- benchmarks/results
  )
  if [[ "${#new_results[@]}" -ne 1 ]]; then
    echo "expected exactly one new result after $label" >&2
    exit 2
  fi
  if ! git -C "$ROOT" diff --quiet || ! git -C "$ROOT" diff --cached --quiet; then
    echo "tracked files changed during $label" >&2
    exit 2
  fi

  local source="$ROOT/${new_results[0]}"
  local destination="$RESULTS/$(basename "$source")"
  local staged_path="$STAGING/$label-$(basename "$source")"
  mv "$source" "$staged_path"
  staged+=("$staged_path")
  destinations+=("$destination")
}

run_report quick \
  --quick \
  --warmup-repetitions 0 \
  --repetitions 1
run_report official \
  --warmup-repetitions 1 \
  --repetitions 3

if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
  echo "tree did not return to clean state after the two staged runs" >&2
  exit 2
fi

python3 "$ROOT/scripts/report.py" --validate-p7b-official "${staged[1]}"
