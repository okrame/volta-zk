#!/usr/bin/env bash
# P5 run of record: GPT-2 small, prefill T=100, real HF weights, real PCS.
# One-command entry point — see docs/prototype-status.md and
# docs/benchmark-plan.md for the schema/gates this run reports against.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
weights_dir="$repo_root/benchmarks/weights"

if [[ ! -f "$weights_dir/gpt2s-q.bin" ]]; then
    echo "run_prefill: frozen artifact not found at $weights_dir/gpt2s-q.bin" >&2
    echo "  run: python3 scripts/export_gpt2.py" >&2
    exit 1
fi

if [[ ! -f "$weights_dir/golden-p5.bin" ]]; then
    echo "run_prefill: golden-p5.bin not found at $weights_dir/golden-p5.bin" >&2
    echo "  run: python3 scripts/dump_golden.py" >&2
    exit 1
fi

source "$HOME/.cargo/env"
cd "$repo_root/rust"
authorization_store="${VOLTA_PCG_AUTHORIZATION_STORE:-${XDG_STATE_HOME:-$HOME/.local/state}/volta-zk/response-authorizations}"
mkdir -p "$authorization_store"
cargo run --release -p volta-bench --bin p5_report -- \
    --pcg-backend real \
    --ggm-prg aes128-mmo \
    --pcg-authorization-store "$authorization_store"
