#!/usr/bin/env bash
# P7b iteration 3 Phase 0a: counterbalanced CUDA instrumentation-tax A/B.
#
# Each arm is a separate one-repetition quick report so the order is exactly
# events/counters/counters/events/events/counters. Results are staged outside
# the repository between invocations to preserve clean-tree provenance for
# every sample, then restored append-only after all six measurements finish.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS="$ROOT/benchmarks/results"
STAGING="${1:-}"

if [[ -z "$STAGING" ]]; then
  echo "usage: $0 ABSOLUTE_EMPTY_STAGING_DIRECTORY" >&2
  exit 2
fi
if [[ "$STAGING" != /* ]]; then
  echo "staging directory must be absolute" >&2
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

if [[ -z "${VOLTA_CUDA_LIBRARY:-}" || ! -f "$VOLTA_CUDA_LIBRARY" ]]; then
  echo "VOLTA_CUDA_LIBRARY must name the built ABI-27 backend" >&2
  exit 2
fi
if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
  echo "Phase 0a requires a clean tree before the first sample" >&2
  exit 2
fi

start_sha="$(git -C "$ROOT" rev-parse HEAD)"
if [[ ! "$start_sha" =~ ^[0-9a-f]{40}$ ]]; then
  echo "unable to resolve a full source SHA" >&2
  exit 2
fi

order=(events counters counters events events counters)
events_rep=0
counters_rep=0
staged_sources=()
final_destinations=()

for sequence in "${!order[@]}"; do
  arm="${order[$sequence]}"
  if [[ "$(git -C "$ROOT" rev-parse HEAD)" != "$start_sha" ]]; then
    echo "source SHA changed during Phase 0a" >&2
    exit 2
  fi
  if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
    echo "tree is dirty before A/B sample $((sequence + 1))" >&2
    exit 2
  fi

  if [[ "$arm" == events ]]; then
    policy=deferred-events
    arm_rep="$events_rep"
    events_rep=$((events_rep + 1))
  else
    policy=wall-only-counters
    arm_rep="$counters_rep"
    counters_rep=$((counters_rep + 1))
  fi

  echo "Phase 0a sample $((sequence + 1))/6: $arm repetition $((arm_rep + 1))/3" >&2
  cargo run --release --manifest-path "$ROOT/rust/Cargo.toml" \
    -p volta-bench --bin p6_report -- \
    --quick \
    --accelerator cuda-resident \
    --resident-timing "$policy" \
    --warmup-repetitions 0 \
    --repetitions 1

  mapfile -t new_results < <(
    git -C "$ROOT" ls-files --others --exclude-standard -- benchmarks/results
  )
  if [[ "${#new_results[@]}" -ne 1 ]]; then
    echo "expected exactly one new result after sample $((sequence + 1))" >&2
    exit 2
  fi
  if ! git -C "$ROOT" diff --quiet || ! git -C "$ROOT" diff --cached --quiet; then
    echo "tracked files changed during sample $((sequence + 1))" >&2
    exit 2
  fi

  relative="${new_results[0]}"
  original_name="$(basename "$relative")"
  stem="${original_name%.json}"
  if (( arm_rep == 0 )); then
    final_name="$original_name"
  else
    final_name="$stem-$arm_rep.json"
  fi
  final_path="$RESULTS/$final_name"
  if [[ -e "$final_path" ]]; then
    echo "append-only result destination already exists: $final_path" >&2
    exit 2
  fi

  staged_path="$STAGING/$((sequence + 1))-$arm-$original_name"
  mv "$ROOT/$relative" "$staged_path"
  staged_sources+=("$staged_path")
  final_destinations+=("$final_path")
done

if [[ "$events_rep" -ne 3 || "$counters_rep" -ne 3 ]]; then
  echo "internal A/B repetition accounting mismatch" >&2
  exit 2
fi
if [[ -n "$(git -C "$ROOT" status --porcelain --untracked-files=all)" ]]; then
  echo "tree did not return to clean state after staging the six samples" >&2
  exit 2
fi

for index in "${!staged_sources[@]}"; do
  mv "${staged_sources[$index]}" "${final_destinations[$index]}"
  printf '%s\n' "${final_destinations[$index]}"
done
