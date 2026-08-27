#!/usr/bin/env bash
# One guarded C6.4 A100 campaign: two setup profiles and two no-retry proofs.

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 WEIGHTS_DIR SETUP_ROOT WORK_ROOT SESSION_ROOT" >&2
  exit 2
fi

WEIGHTS_DIR=$(realpath -e "$1")
SETUP_ROOT=$(realpath -m "$2")
WORK_ROOT=$(realpath -e "$3")
SESSION_ROOT=$(realpath -m "$4")
REPO_ROOT=$(git rev-parse --show-toplevel)
EXPECTED_SHA=${C64_EXPECTED_GIT_SHA:-}
SETUP_SOURCE=${C64_SETUP_SOURCE:-}
SESSION_TIMEOUT_S=${C64_SESSION_TIMEOUT_S:-600}
DISK_FLOOR_BYTES=223338299392
RUN_DISK_STOP_BYTES=107374182400
HOST_FLOOR_BYTES=103079215104
CGROUP_RESERVE_BYTES=17179869184
GPU_TOTAL_FLOOR_MIB=80000
GPU_STOP_MIB=43696

if [[ ${C64_RUN_SPECIFIC_OWNER_GO:-} != 1 ]]; then
  echo "C64_RUN_SPECIFIC_OWNER_GO=1 is required" >&2
  exit 2
fi
if [[ ! $EXPECTED_SHA =~ ^[0-9a-f]{40}$ || $(git rev-parse HEAD) != "$EXPECTED_SHA" ]]; then
  echo "C64_EXPECTED_GIT_SHA must equal the checked-out full SHA" >&2
  exit 2
fi
if [[ ! $SESSION_TIMEOUT_S =~ ^[1-9][0-9]*$ ]]; then
  echo "C64_SESSION_TIMEOUT_S must be a positive integer" >&2
  exit 2
fi
if [[ ! -d $WEIGHTS_DIR ]]; then
  echo "WEIGHTS_DIR must be a directory" >&2
  exit 2
fi
for name in gpt2s-q.bin gpt2s-q.json gpt2s-q.params golden-p6.bin; do
  if [[ ! -f $WEIGHTS_DIR/$name ]]; then
    echo "WEIGHTS_DIR lacks $name" >&2
    exit 2
  fi
done
if [[ -n $SETUP_SOURCE ]]; then
  SETUP_SOURCE=$(realpath -e "$SETUP_SOURCE")
  if [[ ! -d $SETUP_SOURCE/context-000 || ! -d $SETUP_SOURCE/context-150 ]]; then
    echo "C64_SETUP_SOURCE lacks context-000 or context-150" >&2
    exit 2
  fi
fi
for path in "$SETUP_ROOT" "$WORK_ROOT" "$SESSION_ROOT"; do
  if [[ $path == / || $path == "$REPO_ROOT" || $path == "$REPO_ROOT"/* ]]; then
    echo "setup, work and session roots must be outside the repository" >&2
    exit 2
  fi
done
if [[ -e $SETUP_ROOT || -e $SESSION_ROOT || -e $WORK_ROOT/c63-fixed-model-cache ]]; then
  echo "setup/session roots and the fixed-model cache must be create-new" >&2
  exit 2
fi
if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  echo "C6.4 requires a clean source tree" >&2
  exit 2
fi
if [[ ! -x /usr/local/cuda/bin/nvcc ]]; then
  echo "C6.4 requires /usr/local/cuda/bin/nvcc" >&2
  exit 2
fi

required_cloud=(
  VOLTA_CLOUD_PROVIDER VOLTA_CLOUD_INSTANCE_ID VOLTA_CLOUD_REGION
  VOLTA_CLOUD_IMAGE VOLTA_CLOUD_DRIVER_VERSION VOLTA_CLOUD_CUDA_VERSION
  VOLTA_CLOUD_GPU_SKU VOLTA_CLOUD_CPU_MODEL VOLTA_CLOUD_RAM_GIB
  VOLTA_CLOUD_VCPUS CUDA_VISIBLE_DEVICES
)
for name in "${required_cloud[@]}"; do
  if [[ -z ${!name:-} ]]; then
    echo "$name is required" >&2
    exit 2
  fi
done
if [[ $VOLTA_CLOUD_PROVIDER != RunPod || $CUDA_VISIBLE_DEVICES == *,* ]]; then
  echo "the record requires RunPod and exactly one selected GPU" >&2
  exit 2
fi
if [[ ! $VOLTA_CLOUD_VCPUS =~ ^[1-9][0-9]*$ ]]; then
  echo "VOLTA_CLOUD_VCPUS must be the positive allocated vCPU count" >&2
  exit 2
fi

IFS=, read -r gpu_name gpu_total_mib <<<"$(
  nvidia-smi --query-gpu=name,memory.total --format=csv,noheader,nounits --id="$CUDA_VISIBLE_DEVICES"
)"
gpu_name=${gpu_name## }
gpu_total_mib=${gpu_total_mib//[[:space:]]/}
if [[ $gpu_name != *A100* || ! $gpu_total_mib =~ ^[0-9]+$ || $gpu_total_mib -lt $GPU_TOTAL_FLOOR_MIB ]]; then
  echo "C6.4 requires one 80-GB A100" >&2
  exit 2
fi
compute_pids=$(nvidia-smi --query-compute-apps=pid --format=csv,noheader,nounits)
if [[ $compute_pids =~ [0-9] ]]; then
  echo "C6.4 requires an idle GPU" >&2
  exit 2
fi

devices=(
  "$(stat -c %d "$REPO_ROOT/rust")"
  "$(stat -c %d "$WEIGHTS_DIR")"
  "$(stat -c %d "$WORK_ROOT")"
  "$(stat -c %d "$(dirname "$SETUP_ROOT")")"
  "$(stat -c %d "$(dirname "$SESSION_ROOT")")"
)
if [[ $(printf '%s\n' "${devices[@]}" | LC_ALL=C sort -u | wc -l) -ne 1 ]]; then
  echo "repository, weights, setup, work and session must share one persistent filesystem" >&2
  exit 2
fi
disk_available=$(df -PB1 "$WORK_ROOT" | awk 'NR == 2 { print $4 }')
mem_available=$(awk '/^MemAvailable:/ { print $2 * 1024 }' /proc/meminfo)
if [[ $disk_available -lt $DISK_FLOOR_BYTES || $mem_available -lt $HOST_FLOOR_BYTES ]]; then
  echo "C6.4 admission requires 208 GiB free disk and 96 GiB available RAM" >&2
  exit 2
fi
if [[ -r /sys/fs/cgroup/memory.max && -r /sys/fs/cgroup/memory.current ]]; then
  cgroup_max=$(< /sys/fs/cgroup/memory.max)
  cgroup_current=$(< /sys/fs/cgroup/memory.current)
  if [[ $cgroup_max != max && $((cgroup_max - cgroup_current)) -lt $HOST_FLOOR_BYTES ]]; then
    echo "C6.4 cgroup has less than 96 GiB available" >&2
    exit 2
  fi
else
  cgroup_max=max
fi

mkdir "$SESSION_ROOT"
record_pid=
cleanup() {
  status=$?
  trap - EXIT
  if [[ -n $record_pid ]] && kill -0 "$record_pid" 2>/dev/null; then
    kill -TERM "$record_pid" 2>/dev/null || true
    wait "$record_pid" 2>/dev/null || true
  fi
  if [[ $status -ne 0 && -d $SESSION_ROOT/run ]]; then
    find "$SESSION_ROOT/run" -type f -printf '%P\t%s\n' \
      | LC_ALL=C sort >"$SESSION_ROOT/failure-run-files.tsv" || true
  fi
  rm -rf -- "$SESSION_ROOT/run" "$WORK_ROOT/c63-fixed-model-cache"
  exit "$status"
}
trap cleanup EXIT

cd "$REPO_ROOT"
source "$HOME/.cargo/env"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_RELEASE_DEBUG=0
export RAYON_NUM_THREADS="$VOLTA_CLOUD_VCPUS"
export VOLTA_CUDA_ARCH=sm_80
export VOLTA_CUDA_LIBRARY="$REPO_ROOT/rust/target/cuda/libvolta_cuda_backend.so"
export VOLTA_REQUIRE_CUDA=1

rustc -C target-cpu=native --print cfg >"$SESSION_ROOT/rustc-native-cfg.txt"
if ! grep -Eq 'target_feature="(avx2|neon|sve)"' "$SESSION_ROOT/rustc-native-cfg.txt"; then
  echo "native Rust target exposes no admitted SIMD feature" >&2
  exit 2
fi
lscpu >"$SESSION_ROOT/cpu-topology.txt"
printf 'rayon_threads=%s\n' "$RAYON_NUM_THREADS" >"$SESSION_ROOT/cpu-execution.txt"
grep -E '^target_feature=' "$SESSION_ROOT/rustc-native-cfg.txt" \
  >>"$SESSION_ROOT/cpu-execution.txt"

scripts/build_cuda_backend.sh >"$SESSION_ROOT/cuda-build.log" 2>&1
cargo test --release --manifest-path rust/Cargo.toml \
  -p volta-pcs --test cuda \
  --features cuda,c6-trace,c61-p3-authenticated-reference \
  cuda_c64_projected_residual_matches_reference_and_reclaims_buffers \
  -- --exact --nocapture \
  >"$SESSION_ROOT/cuda-differential.log" 2>&1
cargo test --release --manifest-path rust/Cargo.toml \
  -p volta-bench --bin c62_whir_fiat_shamir_record \
  --features cuda,c6-trace,c61-p3-authenticated-reference \
  c64_campaign_is_two_profiles_two_proofs_and_reload_before_accept \
  -- --nocapture \
  >"$SESSION_ROOT/driver-check.log" 2>&1
cargo build --release --manifest-path rust/Cargo.toml \
  -p volta-bench \
  --features cuda,c6-trace,c61-p3-authenticated-reference \
  --bin c62_setup_bundle_record --bin c62_whir_fiat_shamir_record \
  >"$SESSION_ROOT/release-build.log" 2>&1

setup_started_ns=$(date +%s%N)
if [[ -n $SETUP_SOURCE ]]; then
  mkdir "$SETUP_ROOT"
  cp -a --reflink=auto "$SETUP_SOURCE/context-000" "$SETUP_SOURCE/context-150" "$SETUP_ROOT/"
  printf 'reused=%s\n' "$SETUP_SOURCE" >"$SESSION_ROOT/setup-source.txt"
else
  "$REPO_ROOT/rust/target/release/c62_setup_bundle_record" \
    --weights "$WEIGHTS_DIR" \
    --setup-root "$SETUP_ROOT" \
    --stop-after 150 \
    >"$SESSION_ROOT/setup.stdout.log" 2>"$SESSION_ROOT/setup.stderr.log"
  printf 'generated=contexts-0-150\n' >"$SESSION_ROOT/setup-source.txt"
fi
setup_elapsed_ns=$(( $(date +%s%N) - setup_started_ns ))
VOLTA_C64_INSTALLED_SETUP_GENERATION_WALL_S=$(
  awk -v elapsed="$setup_elapsed_ns" 'BEGIN { printf "%.9f", elapsed / 1000000000 }'
)
export VOLTA_C64_INSTALLED_SETUP_GENERATION_WALL_S

record_bin="$REPO_ROOT/rust/target/release/c62_whir_fiat_shamir_record"
timeline="$SESSION_ROOT/resource-timeline.tsv"
printf 'timestamp_ns\telapsed_s\trss_bytes\thwm_bytes\tread_bytes\twrite_bytes\tgpu_mib\tgpu_util_pct\tgpu_mem_util_pct\tgpu_power_w\tgpu_sm_clock_mhz\tgpu_mem_clock_mhz\tgpu_temp_c\tdisk_free_bytes\tcgroup_current_bytes\tevent\n' >"$timeline"
"$record_bin" \
  --mode c64-prove \
  --weights "$WEIGHTS_DIR" \
  --setup-dir "$SETUP_ROOT" \
  --work-root "$WORK_ROOT" \
  --run-root "$SESSION_ROOT/run" \
  --artifact-root "$SESSION_ROOT/artifacts" \
  --state-root "$SESSION_ROOT/state" \
  --output "$SESSION_ROOT/session.json" \
  >"$SESSION_ROOT/session.stdout.log" 2>"$SESSION_ROOT/session.stderr.log" &
record_pid=$!
record_started_s=$(date +%s)
sent_term_at=0
mark_20=0
mark_150=0
while kill -0 "$record_pid" 2>/dev/null; do
  now_s=$(date +%s)
  elapsed_s=$((now_s - record_started_s))
  rss_bytes=0
  hwm_bytes=0
  read_bytes=0
  write_bytes=0
  if [[ -r /proc/$record_pid/status ]]; then
    read -r rss_bytes hwm_bytes < <(
      awk '/^VmRSS:/ { rss=$2*1024 } /^VmHWM:/ { hwm=$2*1024 } END { print rss+0, hwm+0 }' "/proc/$record_pid/status"
    ) || true
  fi
  if [[ -r /proc/$record_pid/io ]]; then
    read -r read_bytes write_bytes < <(
      awk '/^read_bytes:/ { r=$2 } /^write_bytes:/ { w=$2 } END { print r+0, w+0 }' "/proc/$record_pid/io"
    ) || true
  fi
  monitor_failed=0
  if ! IFS=, read -r gpu_mib gpu_util_pct gpu_mem_util_pct gpu_power_w \
    gpu_sm_clock_mhz gpu_mem_clock_mhz gpu_temp_c < <(
      nvidia-smi \
        --query-gpu=memory.used,utilization.gpu,utilization.memory,power.draw,clocks.current.sm,clocks.current.memory,temperature.gpu \
        --format=csv,noheader,nounits --id="$CUDA_VISIBLE_DEVICES" | tr -d ' '
    ); then
    gpu_mib=0 gpu_util_pct=0 gpu_mem_util_pct=0 gpu_power_w=0
    gpu_sm_clock_mhz=0 gpu_mem_clock_mhz=0 gpu_temp_c=0
    monitor_failed=1
  fi
  if ! disk_free=$(df -PB1 "$WORK_ROOT" | awk 'NR == 2 { print $4 }'); then
    disk_free=0
    monitor_failed=1
  fi
  if [[ -r /sys/fs/cgroup/memory.current ]]; then
    cgroup_current=$(< /sys/fs/cgroup/memory.current)
  else
    cgroup_current=0
  fi
  event=sample
  if [[ $mark_20 -eq 0 && $elapsed_s -ge 20 ]]; then event=proof_mark_20s; mark_20=1; fi
  if [[ $mark_150 -eq 0 && $elapsed_s -ge 150 ]]; then event=diagnostic_mark_150s; mark_150=1; fi
  if [[ $sent_term_at -eq 0 && $monitor_failed -ne 0 ]]; then event=monitor_hard_stop; sent_term_at=$now_s; kill -TERM "$record_pid" 2>/dev/null || true; fi
  if [[ $sent_term_at -eq 0 && $disk_free -lt $RUN_DISK_STOP_BYTES ]]; then event=disk_hard_stop; sent_term_at=$now_s; kill -TERM "$record_pid" 2>/dev/null || true; fi
  if [[ $sent_term_at -eq 0 && $gpu_mib -gt $GPU_STOP_MIB ]]; then event=gpu_hard_stop; sent_term_at=$now_s; kill -TERM "$record_pid" 2>/dev/null || true; fi
  if [[ $sent_term_at -eq 0 && $cgroup_max != max && $((cgroup_max - cgroup_current)) -lt $CGROUP_RESERVE_BYTES ]]; then event=cgroup_hard_stop; sent_term_at=$now_s; kill -TERM "$record_pid" 2>/dev/null || true; fi
  if [[ $sent_term_at -eq 0 && $elapsed_s -ge $SESSION_TIMEOUT_S ]]; then event=session_timebox; sent_term_at=$now_s; kill -TERM "$record_pid" 2>/dev/null || true; fi
  if [[ $sent_term_at -ne 0 && $((now_s - sent_term_at)) -ge 30 ]]; then event=forced_kill; kill -KILL "$record_pid" 2>/dev/null || true; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date +%s%N)" "$elapsed_s" "$rss_bytes" "$hwm_bytes" "$read_bytes" "$write_bytes" \
    "$gpu_mib" "$gpu_util_pct" "$gpu_mem_util_pct" "$gpu_power_w" "$gpu_sm_clock_mhz" \
    "$gpu_mem_clock_mhz" "$gpu_temp_c" "$disk_free" "$cgroup_current" "$event" >>"$timeline"
  sleep 1
done
set +e
wait "$record_pid"
record_status=$?
record_pid=
set -e
printf '%s\t%s\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\t0\texit_%s\n' \
  "$(date +%s%N)" "$(( $(date +%s) - record_started_s ))" "$record_status" >>"$timeline"
if [[ $record_status -ne 0 ]]; then
  exit "$record_status"
fi

find "$SESSION_ROOT/artifacts" -type f -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 sha256sum >"$SESSION_ROOT/artifact-files.sha256"
find "$SESSION_ROOT" -maxdepth 1 -type f ! -name checksums.sha256 -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 sha256sum >"$SESSION_ROOT/checksums.sha256"
if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  echo "the source tree changed during the C6.4 run" >&2
  exit 1
fi
echo "C6.4 pod campaign completed: $SESSION_ROOT"
