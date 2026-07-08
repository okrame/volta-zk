#!/usr/bin/env bash
# Pull append-only cloud benchmark JSONs back into this local checkout.
# Run from the local machine before stopping an ephemeral cloud instance.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env_file="$repo_root/.env"

if [[ -f "$env_file" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$env_file"
    set +a
fi

: "${CLOUD_USER:=ubuntu}"
: "${CLOUD_PORT:=22}"
: "${CLOUD_REMOTE_REPO:=/home/${CLOUD_USER}/volta-zk}"

if [[ -z "${CLOUD_HOST:-}" ]]; then
    echo "CLOUD_HOST is not set. Put it in .env or export it before running." >&2
    exit 2
fi
if [[ -z "${CLOUD_SSH_KEY:-}" ]]; then
    echo "CLOUD_SSH_KEY is not set. Put it in .env or export it before running." >&2
    exit 2
fi

key="${CLOUD_SSH_KEY/#\~/$HOME}"
dest="$repo_root/benchmarks/results"
mkdir -p "$dest"

echo "== remote benchmark files =="
ssh -i "$key" -p "$CLOUD_PORT" -o BatchMode=yes "${CLOUD_USER}@${CLOUD_HOST}" \
    "set -e; cd '$CLOUD_REMOTE_REPO'; ls -1 benchmarks/results/*.json 2>/dev/null || true"

echo "== pulling JSONs to $dest =="
scp -i "$key" -P "$CLOUD_PORT" -p \
    "${CLOUD_USER}@${CLOUD_HOST}:${CLOUD_REMOTE_REPO}/benchmarks/results/*.json" \
    "$dest/"

echo "== done =="
echo "Local status:"
git -C "$repo_root" status --short benchmarks/results
