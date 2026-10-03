#!/usr/bin/env bash
# Control-plane and Git HTTPS preflight for future, explicitly authorized pod runs.
set -euo pipefail

origin_url=https://github.com/okrame/volta-zk.git
script_path=$(realpath "$0")
repo_root=$(realpath "$(dirname "$script_path")/..")

usage() {
  cat <<'EOF'
usage:
  scripts/runpod_harness.sh list
  scripts/runpod_harness.sh status POD_ID
  scripts/runpod_harness.sh pause POD_ID
  scripts/runpod_harness.sh delete POD_ID --confirm POD_ID
  scripts/runpod_harness.sh local-secret-preflight
  scripts/runpod_harness.sh git-preflight
  scripts/runpod_harness.sh git-push runpod/POD_ID/LABEL
  scripts/runpod_harness.sh self-test

pause  = stop the pod, release its GPU, preserve its volume (storage still bills)
delete = permanently terminate the pod and its non-network-volume data

HARD STOP: runpodctl v2.12.0 removed the provider deadline flags because the
backend ignored them. Do not create a paid pod until a provider-enforced,
read-back deadline or an independently authorized spending guard exists.

git-preflight must pass before builds or generated artifacts. It requires a
RunPod Secret mapped to VOLTA_GITHUB_TOKEN with repository Contents read/write.
After committing only small tracked evidence, git-push publishes the clean
commit to a unique RunPod branch without force-pushing.
EOF
}

die() {
  echo "runpod harness: $*" >&2
  exit 2
}

valid_pod_id() {
  [[ $1 =~ ^[a-z0-9]+$ ]]
}

valid_runpod_branch() {
  [[ $1 =~ ^runpod/([a-z0-9]+)/[a-z0-9][a-z0-9._-]*$ ]] &&
    [[ ${BASH_REMATCH[1]} == "${RUNPOD_POD_ID:-}" ]]
}

pod_id() {
  [[ $# -eq 1 ]] || die "POD_ID is required"
  valid_pod_id "$1" || die "invalid POD_ID: $1"
  printf '%s\n' "$1"
}

runpodctl_ready() {
  command -v runpodctl >/dev/null || die "runpodctl is not installed"
}

local_secret_preflight() {
  local file="$repo_root/.env"
  [[ ! -e $file ]] && return
  [[ -f $file && ! -L $file && -O $file ]] || \
    die ".env must be a regular file owned by the current user"
  [[ -z $(find "$file" -maxdepth 0 -perm /077 -print) ]] || \
    die ".env must not be readable, writable or executable by group/others (use chmod 600)"
}

git_with_token() {
  VOLTA_RUNPOD_ASKPASS=1 GIT_ASKPASS="$script_path" GIT_TERMINAL_PROMPT=0 \
    git -c credential.helper= "$@"
}

# Git invokes this same file as GIT_ASKPASS. The secret stays out of argv,
# remotes, Git config and the checkout.
if [[ ${VOLTA_RUNPOD_ASKPASS:-} == 1 ]]; then
  case ${1:-} in
    Username*) printf '%s\n' x-access-token ;;
    Password*) printf '%s\n' "${VOLTA_GITHUB_TOKEN:?VOLTA_GITHUB_TOKEN is required}" ;;
    *) exit 1 ;;
  esac
  exit 0
fi

action=${1:-help}
shift || true

case "$action" in
  help|-h|--help)
    usage
    ;;
  list)
    [[ $# -eq 0 ]] || die "list takes no arguments"
    runpodctl_ready
    runpodctl pod list --all
    ;;
  status)
    id=$(pod_id "$@")
    runpodctl_ready
    runpodctl pod get "$id"
    ;;
  pause|stop)
    id=$(pod_id "$@")
    runpodctl_ready
    runpodctl pod stop "$id"
    ;;
  delete|terminate)
    [[ $# -eq 3 && $2 == --confirm && $1 == "$3" ]] || \
      die "delete requires: POD_ID --confirm POD_ID"
    id=$(pod_id "$1")
    runpodctl_ready
    runpodctl pod delete "$id"
    ;;
  local-secret-preflight)
    [[ $# -eq 0 ]] || die "local-secret-preflight takes no arguments"
    local_secret_preflight
    printf 'Local secret-file permissions passed.\n'
    ;;
  git-preflight)
    [[ $# -eq 0 ]] || die "git-preflight takes no arguments"
    [[ -n ${VOLTA_GITHUB_TOKEN:-} ]] || die "VOLTA_GITHUB_TOKEN is not set"
    [[ $(git remote get-url origin) == "$origin_url" ]] || \
      die "origin must be $origin_url"
    [[ -z $(git status --porcelain=v1 --untracked-files=all) ]] || \
      die "the checkout must be clean"
    id=$(pod_id "${RUNPOD_POD_ID:-}")
    GIT_TERMINAL_PROMPT=0 git -c credential.helper= \
      ls-remote --exit-code origin HEAD >/dev/null
    git_with_token push --dry-run --porcelain origin \
      "HEAD:refs/heads/runpod/preflight-$id" >/dev/null
    printf 'Git HTTPS read/write preflight passed at %s (clean).\n' \
      "$(git rev-parse HEAD)"
    ;;
  git-push)
    [[ $# -eq 1 ]] || die "git-push requires runpod/POD_ID/LABEL"
    [[ -n ${VOLTA_GITHUB_TOKEN:-} ]] || die "VOLTA_GITHUB_TOKEN is not set"
    valid_runpod_branch "$1" || \
      die "branch must be runpod/${RUNPOD_POD_ID:-POD_ID}/LABEL"
    [[ $(git remote get-url origin) == "$origin_url" ]] || \
      die "origin must be $origin_url"
    [[ -z $(git status --porcelain=v1 --untracked-files=all) ]] || \
      die "commit the small evidence first; the checkout must be clean"
    git_with_token push origin "HEAD:refs/heads/$1"
    ;;
  self-test)
    [[ $# -eq 0 ]] || die "self-test takes no arguments"
    valid_pod_id abc123
    ! valid_pod_id 'abc;123'
    [[ $(pod_id abc123) == abc123 ]]
    RUNPOD_POD_ID=abc123 valid_runpod_branch runpod/abc123/c7-result
    ! RUNPOD_POD_ID=abc123 valid_runpod_branch runpod/wrong/c7-result
    local_secret_preflight
    echo "runpod harness self-test passed"
    ;;
  *)
    usage >&2
    die "unknown action: $action"
    ;;
esac
