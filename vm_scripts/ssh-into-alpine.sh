#!/bin/sh
# Connects directly over `puff-tap` (192.168.8.1/24) to the Alpine Linux guest
# started by `run-linux.sh`, `run-airlock-linux-alpine.sh` (`--passthrough-net` /
# `--passthrough-all`), `run-passthrough-net-linux.sh`, or `run-passthrough-blk-linux.sh`.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
AIRLOCK_KEY="$REPO_ROOT/target/airlock/id_ed25519"
FALLBACK_KEY="$REPO_ROOT/../motor-dev/motor-os/vm_images/release/test.key"

if [ -n "${LINUX_SSH_KEY:-}" ]; then
    if [ ! -f "$LINUX_SSH_KEY" ]; then
        echo "ssh-into-alpine: SSH key '$LINUX_SSH_KEY' not found" >&2
        exit 1
    fi
    exec ssh \
        -F /dev/null \
        -o ProxyCommand=none \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$LINUX_SSH_KEY" \
        root@192.168.8.2 \
        "$@"
fi

if [ -f "$AIRLOCK_KEY" ] && [ -f "$FALLBACK_KEY" ]; then
    exec ssh \
        -F /dev/null \
        -o ProxyCommand=none \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$AIRLOCK_KEY" \
        -i "$FALLBACK_KEY" \
        root@192.168.8.2 \
        "$@"
elif [ -f "$AIRLOCK_KEY" ]; then
    exec ssh \
        -F /dev/null \
        -o ProxyCommand=none \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$AIRLOCK_KEY" \
        root@192.168.8.2 \
        "$@"
elif [ -f "$FALLBACK_KEY" ]; then
    exec ssh \
        -F /dev/null \
        -o ProxyCommand=none \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$FALLBACK_KEY" \
        root@192.168.8.2 \
        "$@"
fi

exec ssh -o ProxyCommand=none root@192.168.8.2 "$@"
