#!/usr/bin/env bash
# P6 run of record: GPT-2 small, prompt 100 + 50 greedy decode tokens,
# authenticated KV cache, deferred stacked chunk proving, real PCS.
# One-command entry point — see docs/prototype-status.md (P6).
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
weights_dir="$repo_root/benchmarks/weights"

if [[ ! -f "$weights_dir/gpt2s-q.bin" ]]; then
    echo "run_decode: frozen artifact not found — run: python3 scripts/export_gpt2.py" >&2
    exit 1
fi
if [[ ! -f "$weights_dir/golden-p6.bin" ]]; then
    echo "run_decode: golden-p6.bin not found — run: .venv/bin/python scripts/dump_golden.py --gen 50" >&2
    exit 1
fi

source "$HOME/.cargo/env"
cd "$repo_root/rust"
authorization_store="${VOLTA_PCG_AUTHORIZATION_STORE:-${XDG_STATE_HOME:-$HOME/.local/state}/volta-zk/response-authorizations}"
mkdir -p "$authorization_store"
cargo run --release -p volta-bench --bin p6_report -- \
    --pcg-backend real \
    --ggm-prg aes128-mmo \
    --pcg-authorization-store "$authorization_store"
