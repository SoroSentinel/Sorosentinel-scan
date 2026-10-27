#!/bin/sh
# Runs one scan in an isolated container and prints the ScanReport JSON.
# Usage: sandbox/run.sh <file.wasm> [known-bad-hashes-file]
#
# Isolation: no network, read-only root FS, all capabilities dropped,
# no-new-privileges, Docker's default seccomp profile, non-root user, and
# memory/CPU/PID limits. The container is killed after SCAN_TIMEOUT seconds.
# TODO: a syscall allowlist stricter than Docker's default (sandbox/seccomp.json).
set -eu

IMAGE="${SCAN_IMAGE:-sorosentinel-scan}"
TIMEOUT="${SCAN_TIMEOUT:-30}"

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "usage: $0 <file.wasm> [known-bad-hashes-file]" >&2
  exit 2
fi
WASM="$1"
HASHES="${2:-}"
case "$HASHES" in
  *,* | *"
"*) echo "error: hash list path must not contain commas or newlines" >&2; exit 2 ;;
esac

NAME="sorosentinel-scan-$$"
set -- docker run --name "$NAME" -i \
  --network none \
  --read-only \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --user 65534:65534 \
  --memory 256m --memory-swap 256m \
  --cpus 1 \
  --pids-limit 16 \
  --tmpfs /tmp:rw,noexec,nosuid,size=8m
if [ -n "$HASHES" ]; then
  set -- "$@" --mount "type=bind,src=$(cd "$(dirname "$HASHES")" && pwd)/$(basename "$HASHES"),dst=/known-bad.txt,readonly" \
    "$IMAGE" - --known-bad-hashes /known-bad.txt
else
  set -- "$@" "$IMAGE" -
fi

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

"$@" < "$WASM" &
pid=$!
# The watcher kills the container after TIMEOUT. When the scan finishes first,
# only the watcher's sleep is stopped, so the watcher exits normally.
( sleep "$TIMEOUT" && docker kill "$NAME" >/dev/null ) 2>/dev/null &
killer=$!

status=0
wait "$pid" || status=$?
pkill -P "$killer" sleep 2>/dev/null || true
wait "$killer" 2>/dev/null || true

if [ "$status" -eq 137 ]; then
  echo '{"error":"timeout"}' >&2
  exit 1
fi
exit "$status"
