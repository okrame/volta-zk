#!/usr/bin/env bash
# Stage the one-use provider object before WebDAV can cache the served root.
set -euo pipefail
umask 077

if [[ $# -ne 9 ]]; then
  echo "usage: $0 PROVIDER_BUNDLE EMPTY_SERVE_ROOT ADDR CERT KEY USER PASSWORD_FILE EXPECTED_BYTES EXPECTED_BLAKE3" >&2
  exit 2
fi

provider_source=$1
serve_root=$2
addr=$3
cert=$4
key=$5
user=$6
password_file=$7
expected_bytes=$8
expected_blake3=$9
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
rclone_bin=$(command -v "${RCLONE_BIN:-rclone}") || {
  echo "rclone is required" >&2
  exit 2
}

if [[ $provider_source != /* || $serve_root != /* || $cert != /* || $key != /* || $password_file != /* ]]; then
  echo "all artifact and credential paths must be absolute" >&2
  exit 2
fi
for path in "$provider_source" "$cert" "$key" "$password_file"; do
  if [[ ! -f $path ]]; then
    echo "missing input: $path" >&2
    exit 2
  fi
  case "$(readlink -f "$path")" in
    "$repo_root" | "$repo_root"/*)
      echo "artifacts and credentials must stay outside the repository" >&2
      exit 2
      ;;
  esac
done
if [[ ! $expected_bytes =~ ^[1-9][0-9]*$ || ! $expected_blake3 =~ ^[0-9a-f]{64}$ ]]; then
  echo "expected byte count or BLAKE3 is malformed" >&2
  exit 2
fi
if [[ -e $serve_root ]]; then
  if [[ ! -d $serve_root || -n $(find "$serve_root" -mindepth 1 -maxdepth 1 -print -quit) ]]; then
    echo "serve root must be missing or empty" >&2
    exit 2
  fi
else
  install -d -m 700 "$serve_root"
fi
case "$(readlink -f "$serve_root")" in
  "$repo_root" | "$repo_root"/*)
    echo "serve root must stay outside the repository" >&2
    exit 2
    ;;
esac

actual_bytes=$(stat -c %s "$provider_source")
actual_blake3=$("$rclone_bin" hashsum BLAKE3 "$provider_source" | awk 'NR == 1 { print $1 }')
if [[ $actual_bytes != "$expected_bytes" || $actual_blake3 != "$expected_blake3" ]]; then
  echo "provider bundle length or BLAKE3 mismatch" >&2
  exit 2
fi
webdav_pass=$(<"$password_file")
if [[ -z $user || -z $webdav_pass ]]; then
  echo "WebDAV user and password must be non-empty" >&2
  exit 2
fi

provider_target=$serve_root/provider.bundle
mv -- "$provider_source" "$provider_target"
chmod 600 "$provider_target"
test "$(stat -c %s "$provider_target")" = "$expected_bytes"
test "$("$rclone_bin" hashsum BLAKE3 "$provider_target" | awk 'NR == 1 { print $1 }')" = "$expected_blake3"
export RCLONE_SERVE_WEBDAV_USER=$user
export RCLONE_SERVE_WEBDAV_PASS=$webdav_pass
exec "$rclone_bin" serve webdav "$serve_root" \
  --addr "$addr" --cert "$cert" --key "$key" --log-level INFO
