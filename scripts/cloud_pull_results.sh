#!/usr/bin/env bash
# Fetch small, committed pod evidence through the GitHub HTTPS origin.
set -euo pipefail

[[ $# -eq 1 && $1 =~ ^runpod/[a-z0-9]+/[a-z0-9][a-z0-9._-]*$ ]] || {
  echo "usage: $0 runpod/POD_ID/LABEL" >&2
  exit 2
}

repo_root=$(git -C "$(dirname "${BASH_SOURCE[0]}")/.." rev-parse --show-toplevel)
[[ $(git -C "$repo_root" remote get-url origin) == \
  https://github.com/okrame/volta-zk.git ]] || {
  echo "origin must be https://github.com/okrame/volta-zk.git" >&2
  exit 2
}

git -C "$repo_root" fetch origin "$1"
echo "Fetched $1 as FETCH_HEAD at $(git -C "$repo_root" rev-parse FETCH_HEAD)."
echo "Review it, then cherry-pick FETCH_HEAD and update the ledger before checkpointing."
