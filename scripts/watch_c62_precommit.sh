#!/usr/bin/env bash
set -euo pipefail

if (( $# < 4 )); then
    echo "usage: watch_c62_precommit.sh RUN_ROOT TIMELINE.tsv -- BINARY [ARGS...]" >&2
    exit 2
fi
if [[ $3 != -- ]]; then
    echo "usage: watch_c62_precommit.sh RUN_ROOT TIMELINE.tsv -- BINARY [ARGS...]" >&2
    exit 2
fi

run_root=$(realpath -m "$1")
timeline=$(realpath -m "$2")
shift 3
command=("$@")
repo_root=$(realpath -e "$(dirname "${BASH_SOURCE[0]}")/..")

if [[ $(basename "${command[0]}") != c62_whir_fiat_shamir_record ]]; then
    echo "invoke the compiled c62_whir_fiat_shamir_record binary directly" >&2
    exit 2
fi
case "$timeline" in
    "$run_root"|"$run_root"/*)
        echo "timeline must be outside RUN_ROOT" >&2
        exit 2
        ;;
    "$repo_root"|"$repo_root"/*)
        echo "timeline must be outside the repository during the clean run" >&2
        exit 2
        ;;
esac
mode=
child_run_root=
work_root=
for ((index = 1; index < ${#command[@]}; index++)); do
    case "${command[index]}" in
        --mode|--run-root|--work-root)
            if (( index + 1 >= ${#command[@]} )); then
                echo "${command[index]} requires a value" >&2
                exit 2
            fi
            value=${command[index + 1]}
            case "${command[index]}" in
                --mode)
                    [[ -z $mode ]] || { echo "duplicate --mode" >&2; exit 2; }
                    mode=$value
                    ;;
                --run-root)
                    [[ -z $child_run_root ]] || { echo "duplicate --run-root" >&2; exit 2; }
                    child_run_root=$(realpath -m "$value")
                    ;;
                --work-root)
                    [[ -z $work_root ]] || { echo "duplicate --work-root" >&2; exit 2; }
                    work_root=$(realpath -m "$value")
                    ;;
            esac
            ((index += 1))
            ;;
    esac
done
if [[ $mode != precommit || $child_run_root != "$run_root" ]]; then
    echo "child must use exactly --mode precommit and the watched --run-root" >&2
    exit 2
fi
run_parent=$(dirname "$run_root")
if [[ ! -x ${command[0]} || -e $run_root || ! -d $run_parent || ! -d $work_root ]]; then
    echo "RUN_ROOT must be absent; its parent and --work-root must exist" >&2
    exit 2
fi
if [[ $(stat -c %d "$run_parent") != $(stat -c %d "$work_root") ]]; then
    echo "RUN_ROOT and --work-root must use the same filesystem" >&2
    exit 2
fi
if [[ ! -d $(dirname "$timeline") ]] ||
    ! (set -o noclobber; : >"$timeline") 2>/dev/null; then
    echo "timeline must be create-new under an existing directory" >&2
    exit 2
fi

perf_data=
if [[ -n ${C62_PRECOMMIT_PERF_DATA:-} ]]; then
    if [[ ! -x $(command -v perf || true) ]]; then
        echo "perf unavailable; continuing with the timeline only" >&2
    else
        perf_data=$(realpath -m "$C62_PRECOMMIT_PERF_DATA")
        case "$perf_data" in
            "$run_root"|"$run_root"/*|"$repo_root"|"$repo_root"/*)
                echo "perf output must be outside RUN_ROOT and the repository" >&2
                exit 2
                ;;
        esac
        if [[ -e $perf_data || ! -d $(dirname "$perf_data") ]]; then
            echo "perf output must be create-new under an existing directory" >&2
            exit 2
        fi
    fi
fi

"${command[@]}" &
diag_pid=$!
perf_pid=
interrupt_child() {
    kill -TERM "$diag_pid" 2>/dev/null || true
    if [[ -n $perf_pid ]]; then
        kill -INT "$perf_pid" 2>/dev/null || true
    fi
}
trap interrupt_child INT TERM
if [[ -n $perf_data ]]; then
    perf record -F 49 -g -p "$diag_pid" -o "$perf_data" &
    perf_pid=$!
fi

wrapper_root="$run_root/certificate-00/wrapper"
while kill -0 "$diag_pid" 2>/dev/null; do
    stamp=$(date +%s%N)
    awk -v t="$stamp" '/^(read_bytes|write_bytes):/ {
        print t "\tio\t" substr($1, 1, length($1) - 1) "\t" $2
    }' "/proc/$diag_pid/io" >>"$timeline" 2>/dev/null || true
    awk -v t="$stamp" '/^(VmRSS|VmHWM):/ {
        print t "\tstatus\t" substr($1, 1, length($1) - 1) "_bytes\t" ($2 * 1024)
    }' "/proc/$diag_pid/status" >>"$timeline" 2>/dev/null || true
    awk -v t="$stamp" '{
        print t "\tcpu\tutime_ticks\t" $14
        print t "\tcpu\tstime_ticks\t" $15
    }' "/proc/$diag_pid/stat" >>"$timeline" 2>/dev/null || true
    if [[ -d $wrapper_root ]]; then
        printf '%s\tdirectory\twrapper\t1\n' "$stamp" >>"$timeline"
        find "$wrapper_root" -type f -printf '%P\t%s\n' 2>/dev/null |
            LC_ALL=C sort |
            awk -v t="$stamp" '{ print t "\tfile\t" $0 }' >>"$timeline" || true
    fi
    sleep 1 || true
done

set +e
wait "$diag_pid"
status=$?
set -e
if [[ -n $perf_pid ]]; then
    kill -INT "$perf_pid" 2>/dev/null || true
    wait "$perf_pid" || true
fi
printf '%s\tprocess\texit_status\t%s\n' "$(date +%s%N)" "$status" >>"$timeline"
exit "$status"
