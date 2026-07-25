#!/usr/bin/env bash
set -euo pipefail

# Pod-local schema-3 campaign. Provider provisioning time is outside this
# diagnostic clock; the clock starts before the first repository workload.
# The 2,700-second value is an owner estimate, never a timeout or gate.

campaign_target_s=2700

required() {
    local name="$1"
    if [[ -z "${!name:-}" ]]; then
        echo "missing required environment variable: ${name}" >&2
        exit 2
    fi
}

for name in \
    VOLTA_X4C_RUNNER \
    VOLTA_X4C_WEIGHTS \
    VOLTA_X4C_DURABLE_ROOT \
    VOLTA_X4C_ONBOARDING_OUTPUT \
    VOLTA_X4C_ONLINE_OUTPUT \
    VOLTA_X4C_REBUILD_ADMISSION \
    VOLTA_X4C_AUTHORIZATION_STORE \
    VOLTA_X4C_CONNECTION_STORE \
    VOLTA_X4C_SOURCE_SHA256 \
    VOLTA_X4C_EPOCH_BASE
do
    required "$name"
done

reuse_onboarding="${VOLTA_X4C_REUSE_ONBOARDING:-0}"
if [[ "$reuse_onboarding" != 0 && "$reuse_onboarding" != 1 ]]; then
    echo "VOLTA_X4C_REUSE_ONBOARDING must be 0 or 1" >&2
    exit 2
fi
if [[ -e "$VOLTA_X4C_ONLINE_OUTPUT" || -e "$VOLTA_X4C_REBUILD_ADMISSION" ]]; then
    echo "online output and rebuild-admission marker must both be fresh" >&2
    exit 2
fi

campaign_started_unix_s="${VOLTA_X4C_CAMPAIGN_STARTED_UNIX_S:-$(date +%s)}"
if [[ ! "$campaign_started_unix_s" =~ ^[1-9][0-9]*$ ]]; then
    echo "campaign start must be a positive Unix timestamp" >&2
    exit 2
fi
if [[ "$reuse_onboarding" == 0 ]]; then
    required VOLTA_X4C_SCRATCH_ROOT
    "$VOLTA_X4C_RUNNER" \
        --mode onboard \
        --weights "$VOLTA_X4C_WEIGHTS" \
        --durable-root "$VOLTA_X4C_DURABLE_ROOT" \
        --scratch-root "$VOLTA_X4C_SCRATCH_ROOT" \
        --output "$VOLTA_X4C_ONBOARDING_OUTPUT" \
        --clean-source-sha256 "$VOLTA_X4C_SOURCE_SHA256" \
        --campaign-started-unix-s "$campaign_started_unix_s"
else
    if [[ ! -f "$VOLTA_X4C_ONBOARDING_OUTPUT" ]]; then
        echo "reused onboarding record is absent" >&2
        exit 2
    fi
    if [[ ! -d "$VOLTA_X4C_DURABLE_ROOT" ]]; then
        echo "reused durable tier is absent" >&2
        exit 2
    fi
fi

onboarding_sha256="$(
    sha256sum "$VOLTA_X4C_ONBOARDING_OUTPUT" | awk '{print $1}'
)"

"$VOLTA_X4C_RUNNER" \
    --mode online-accelerated \
    --weights "$VOLTA_X4C_WEIGHTS" \
    --durable-root "$VOLTA_X4C_DURABLE_ROOT" \
    --onboarding "$VOLTA_X4C_ONBOARDING_OUTPUT" \
    --onboarding-sha256 "$onboarding_sha256" \
    --output "$VOLTA_X4C_ONLINE_OUTPUT" \
    --rebuild-admission-marker "$VOLTA_X4C_REBUILD_ADMISSION" \
    --authorization-store "$VOLTA_X4C_AUTHORIZATION_STORE" \
    --connection-store "$VOLTA_X4C_CONNECTION_STORE" \
    --clean-source-sha256 "$VOLTA_X4C_SOURCE_SHA256" \
    --campaign-started-unix-s "$campaign_started_unix_s" \
    --epoch-base "$VOLTA_X4C_EPOCH_BASE" &
online_pid=$!

admitted=0
while kill -0 "$online_pid" 2>/dev/null; do
    if [[ -f "$VOLTA_X4C_REBUILD_ADMISSION" ]]; then
        admitted=1
        break
    fi
    sleep 1
done

if [[ "$admitted" == 0 && -f "$VOLTA_X4C_REBUILD_ADMISSION" ]]; then
    admitted=1
fi
if [[ "$admitted" == 0 ]]; then
    set +e
    wait "$online_pid"
    online_status=$?
    set -e
    echo "HARD STOP: online process exited without rebuild admission (status ${online_status})" >&2
    if (( online_status == 0 )); then
        exit 1
    fi
    exit "$online_status"
fi

campaign_elapsed_s=$(($(date +%s) - campaign_started_unix_s))
if (( campaign_elapsed_s <= campaign_target_s )); then
    echo "X4c schema-3 rebuild admitted after ${campaign_elapsed_s}s; diagnostic target ${campaign_target_s}s met"
else
    echo "X4c schema-3 rebuild admitted after ${campaign_elapsed_s}s; diagnostic target ${campaign_target_s}s missed (run continues)" >&2
fi
wait "$online_pid"
