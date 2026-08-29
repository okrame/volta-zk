#!/usr/bin/env bash
# One clean same-build A100 spike plus C4.1 anchor/candidate timing pair.
set -euo pipefail

if [[ $# -ne 1 || $1 != /* ]]; then
  echo "usage: $0 ABSOLUTE_EMPTY_STAGING_DIRECTORY" >&2
  exit 2
fi

ROOT=$(git rev-parse --show-toplevel)
RESULTS=$ROOT/benchmarks/results
STAGING=$1
case "$STAGING/" in
  "$ROOT/"*)
    echo "staging directory must be outside the repository" >&2
    exit 2
    ;;
esac
if [[ -e $STAGING ]]; then
  if [[ ! -d $STAGING || -n $(find "$STAGING" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "staging path must be missing or empty" >&2
    exit 2
  fi
else
  mkdir -p "$STAGING"
fi

required_env=(
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
  RAYON_NUM_THREADS
)
for name in "${required_env[@]}"; do
  if [[ -z ${!name:-} ]]; then
    echo "$name is required" >&2
    exit 2
  fi
done
if [[ $VOLTA_CLOUD_PROVIDER != RunPod || $VOLTA_CLOUD_GPU_SKU != NVIDIA\ A100-SXM4-80GB ]]; then
  echo "the timing pair requires one RunPod NVIDIA A100-SXM4-80GB" >&2
  exit 2
fi
if [[ $CUDA_VISIBLE_DEVICES == *,* || $RAYON_NUM_THREADS != 8 ]]; then
  echo "the timing pair requires one visible GPU and RAYON_NUM_THREADS=8" >&2
  exit 2
fi
if [[ ! -x /usr/local/cuda/bin/nvcc ]]; then
  echo "/usr/local/cuda/bin/nvcc is required" >&2
  exit 2
fi
for artifact in gpt2s-q.bin golden-p6.bin; do
  if [[ ! -f $ROOT/benchmarks/weights/$artifact ]]; then
    echo "missing frozen benchmark artifact: benchmarks/weights/$artifact" >&2
    exit 2
  fi
done
if [[ -n $(git -C "$ROOT" status --porcelain --untracked-files=all) ]]; then
  echo "the C4.1 timing run requires a clean source tree" >&2
  exit 2
fi

START_SHA=$(git -C "$ROOT" rev-parse HEAD)
if [[ ! $START_SHA =~ ^[0-9a-f]{40}$ ]]; then
  echo "unable to resolve a full source SHA" >&2
  exit 2
fi
SHORT_SHA=${START_SHA:0:7}
DATE=$(date +%Y-%m-%d)
export VOLTA_CUDA_ARCH=sm_80
export VOLTA_CUDA_LIBRARY=$ROOT/rust/target/cuda/libvolta_cuda_backend.so
source "$HOME/.cargo/env"

staged=()
destinations=()
restore_results() {
  local index
  for index in "${!staged[@]}"; do
    if [[ -e ${staged[$index]} && ! -e ${destinations[$index]} ]]; then
      mv "${staged[$index]}" "${destinations[$index]}"
      printf '%s\n' "${destinations[$index]}"
    fi
  done
}
trap restore_results EXIT

check_clean_sha() {
  if [[ $(git -C "$ROOT" rev-parse HEAD) != "$START_SHA" ]] ||
    [[ -n $(git -C "$ROOT" status --porcelain --untracked-files=all) ]]; then
    echo "source revision or cleanliness changed during the C4.1 run" >&2
    exit 2
  fi
}

"$ROOT/scripts/build_cuda_backend.sh"
check_clean_sha

SPIKE=$STAGING/c41-fused-fold-spike-a100-$DATE-$SHORT_SHA.json
if ! (set -o noclobber; cargo run --release --manifest-path "$ROOT/rust/Cargo.toml" \
  -p volta-bench --features cuda --bin c41_fused_fold_spike -- 3110400 7 > "$SPIKE"); then
  echo "C4.1 fused-fold spike failed or its output already exists" >&2
  exit 1
fi
staged+=("$SPIKE")
destinations+=("$RESULTS/$(basename "$SPIKE")")
python3 - "$SPIKE" <<'PY'
import json
import sys

row = json.load(open(sys.argv[1]))
assert row["schema"] == "c41-fused-fold-spike-v1"
assert row["credit"] is False
assert row["cells"] == 3_110_400 and row["samples"] == 7
assert row["setup_slab_bytes"] == 1_194_393_600
assert row["analytic_spike_gate_pass"] is True
PY

run_arm() {
  local profile=$1
  check_clean_sha
  cargo run --release --manifest-path "$ROOT/rust/Cargo.toml" \
    -p volta-bench --features cuda --bin p6_report -- \
    --accelerator cuda-resident \
    --resident-timing wall-only-counters \
    --c4-record \
    --c4-profile anchor \
    --c41-timing-profile "$profile" \
    --pcg-authorization-store "$STAGING/$profile-authorizations" \
    --pcg-connection-store "$STAGING/$profile-connections" \
    --warmup-repetitions 1 \
    --repetitions 3

  mapfile -t new_results < <(
    git -C "$ROOT" ls-files --others --exclude-standard -- benchmarks/results
  )
  if [[ ${#new_results[@]} -ne 1 ]] ||
    ! git -C "$ROOT" diff --quiet ||
    ! git -C "$ROOT" diff --cached --quiet; then
    echo "expected exactly one append-only raw result from the $profile arm" >&2
    exit 2
  fi
  local source=$ROOT/${new_results[0]}
  local destination=$RESULTS/$(basename "$source")
  local staged_path=$STAGING/$(basename "$source")
  mv "$source" "$staged_path"
  staged+=("$staged_path")
  destinations+=("$destination")
  python3 "$ROOT/scripts/report.py" --validate-c41-timing "$staged_path"
}

run_arm anchor
ANCHOR=${staged[1]}
run_arm candidate
CANDIDATE=${staged[2]}
check_clean_sha

PAIR=$STAGING/c41-fq-hd-tole-paired-timing-a100-$DATE-$SHORT_SHA.json
python3 "$ROOT/scripts/report.py" \
  --validate-c41-timing-pair "$ANCHOR" "$CANDIDATE" \
  --write-c41-timing-pair "$PAIR"
staged+=("$PAIR")
destinations+=("$RESULTS/$(basename "$PAIR")")
python3 - "$PAIR" <<'PY'
import json
import sys

row = json.load(open(sys.argv[1]))
if row["overall_timing_screen_pass"] is not True:
    raise SystemExit("C4.1 paired full-prover timing gate failed")
PY

echo "C4.1 paired timing completed; append-only evidence will be restored under $RESULTS"
