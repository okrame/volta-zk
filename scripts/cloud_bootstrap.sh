#!/usr/bin/env bash
# P7 cloud-box bootstrap (Ubuntu/Debian image, run as the login user).
# Brings a fresh GPU instance to "cargo test --workspace green + artifacts
# regenerated" per docs/p7-cloud-runbook.md. Idempotent.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
weights_dir="$repo_root/benchmarks/weights"

echo "== system deps =="
if command -v apt-get >/dev/null; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq build-essential curl git python3 python3-venv pkg-config
fi

echo "== rust toolchain =="
if [[ ! -f "$HOME/.cargo/env" ]]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
source "$HOME/.cargo/env"

echo "== python venv =="
if [[ ! -d "$repo_root/.venv" ]]; then
    python3 -m venv "$repo_root/.venv"
    "$repo_root/.venv/bin/pip" -q install numpy
fi

echo "== weight artifact (HF gpt2, public — no token needed) =="
mkdir -p "$weights_dir"
if [[ ! -f "$weights_dir/model.safetensors" ]]; then
    curl -L -o "$weights_dir/model.safetensors" \
        "https://huggingface.co/gpt2/resolve/main/model.safetensors"
fi
if [[ ! -f "$weights_dir/gpt2s-q.bin" ]]; then
    "$repo_root/.venv/bin/python" "$repo_root/scripts/export_gpt2.py"
fi
if [[ ! -f "$weights_dir/golden-p6.bin" ]]; then
    "$repo_root/.venv/bin/python" "$repo_root/scripts/dump_golden.py" --gen 50
fi

echo "== build + tests =="
cd "$repo_root/rust"
cargo check --workspace

echo "== GPU / machine fingerprint (record in ledger + every cloud JSON) =="
nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv 2>/dev/null || echo "no GPU visible"
nvcc --version 2>/dev/null | tail -1 || echo "no nvcc on PATH"
lscpu | grep -E "Model name|^CPU\(s\)" || true
free -h | head -2

cat <<'MSG'

Bootstrap done. Next (docs/p7-cloud-runbook.md):
  1. git status --short                  # clean tracked tree for runs of record
  2. cargo test --workspace              # full suite green on the new box
  3. cargo run --release -p volta-bench --bin p1_report    # NEW native baseline
  4. cargo run --release -p volta-bench --bin p6_report    # NEW CPU baseline
  5. python3 scripts/report.py --write-json                # regenerate P7 aggregate
Result JSONs are append-only; helpers add -1/-2 suffixes on same date+sha.
Remember: target-cpu=native ⇒ old JSON ratios are NOT comparable on this box.
MSG
