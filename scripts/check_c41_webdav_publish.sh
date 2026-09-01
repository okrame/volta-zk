#!/usr/bin/env bash
# Local regression: a root probe followed by provider GET must not see 404.
set -euo pipefail
umask 077

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)
rclone_bin=$(command -v "${RCLONE_BIN:-rclone}") || {
  echo "rclone is required" >&2
  exit 2
}
for command in curl openssl; do
  command -v "$command" >/dev/null || {
    echo "$command is required" >&2
    exit 2
  }
done

run_root=$(mktemp -d)
server_pid=
cleanup() {
  if [[ -n $server_pid ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$run_root"
}
trap cleanup EXIT

provider_source=$run_root/provider-source.bin
serve_root=$run_root/serve
cert=$run_root/webdav.crt
key=$run_root/webdav.key
password_file=$run_root/password
download=$run_root/provider-download.bin
printf 'C41SC1 WebDAV cache-order regression\n' > "$provider_source"
expected_bytes=$(stat -c %s "$provider_source")
expected_blake3=$("$rclone_bin" hashsum BLAKE3 "$provider_source" | awk 'NR == 1 { print $1 }')
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
  -addext subjectAltName=IP:127.0.0.1 -keyout "$key" -out "$cert" >/dev/null 2>&1
openssl rand -hex -out "$password_file" 24
chmod 600 "$cert" "$key" "$password_file"

RCLONE_BIN=$rclone_bin "$repo_root/scripts/serve_c41_webdav.sh" \
  "$provider_source" "$serve_root" 127.0.0.1:38444 "$cert" "$key" \
  c41sc1 "$password_file" "$expected_bytes" "$expected_blake3" \
  >"$run_root/server.log" 2>&1 &
server_pid=$!

webdav_pass=$(<"$password_file")
root_config=$run_root/root.curl
provider_config=$run_root/provider.curl
printf '%s\n' \
  "user = \"c41sc1:$webdav_pass\"" \
  "cacert = \"$cert\"" \
  'fail' 'silent' 'show-error' 'retry = 20' 'retry-connrefused' 'retry-delay = 0' \
  'url = "https://127.0.0.1:38444/"' \
  "output = \"$run_root/root-listing\"" > "$root_config"
printf '%s\n' \
  "user = \"c41sc1:$webdav_pass\"" \
  "cacert = \"$cert\"" \
  'fail' 'silent' 'show-error' \
  'url = "https://127.0.0.1:38444/provider.bundle"' \
  "output = \"$download\"" > "$provider_config"

curl --config "$root_config"
grep -q 'provider.bundle' "$run_root/root-listing"
test ! -e "$provider_source"
curl --config "$provider_config"
test "$(stat -c %s "$download")" = "$expected_bytes"
test "$("$rclone_bin" hashsum BLAKE3 "$download" | awk 'NR == 1 { print $1 }')" = "$expected_blake3"

blocked_source=$run_root/blocked-source.bin
blocked_root=$run_root/blocked-root
printf blocked > "$blocked_source"
install -d -m 700 "$blocked_root"
touch "$blocked_root/already-visible"
blocked_bytes=$(stat -c %s "$blocked_source")
blocked_blake3=$("$rclone_bin" hashsum BLAKE3 "$blocked_source" | awk 'NR == 1 { print $1 }')
if RCLONE_BIN=$rclone_bin "$repo_root/scripts/serve_c41_webdav.sh" \
  "$blocked_source" "$blocked_root" 127.0.0.1:38445 "$cert" "$key" \
  c41sc1 "$password_file" "$blocked_bytes" "$blocked_blake3" \
  >"$run_root/blocked.log" 2>&1; then
  echo "non-empty serve root was accepted" >&2
  exit 1
fi
test -f "$blocked_source"
printf 'C41_WEBDAV_PUBLISH_PASS\n'
