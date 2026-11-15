#!/bin/sh
# Connects to the nested L2 Alpine Linux guest running on `airlock.ko`
# (`run-airlock-linux-alpine.sh`):
#   - In `--passthrough-all` / `--passthrough-net` modes, L0's `puff-tap` is passed
#     straight through to L2, so this connects directly to `root@192.168.8.2:22`.
#   - In default bridged mode, L1 owns `192.168.8.2` and this jumps via L1's OpenSSH
#     server to `root@192.168.5.2:22`.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime/airlock-linux-alpine"
KEY="${LINUX_SSH_KEY:-$REPO_ROOT/target/airlock/id_ed25519}"

if [ ! -f "$KEY" ]; then
    echo "ssh-into-airlock-nested-alpine: SSH key '$KEY' not found (override with LINUX_SSH_KEY)" >&2
    exit 1
fi

SSH_MODE=""
if [ -f "$RUNTIME_DIR/ssh-mode" ]; then
    SSH_MODE=$(cat "$RUNTIME_DIR/ssh-mode")
elif [ -f "$RUNTIME_DIR/initramfs-airlock-pt-all-alpine.cpio" ]; then
    SSH_MODE="direct"
fi

if [ "$SSH_MODE" = "direct" ]; then
    exec ssh \
        -F /dev/null \
        -o ProxyCommand=none \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$KEY" \
        -p 22 \
        root@192.168.8.2 \
        "$@"
fi

PROXY_CMD="ssh -F /dev/null -o ProxyCommand=none -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $KEY -W %h:%p -p 22 root@192.168.8.2"

exec ssh \
    -F /dev/null \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o "ProxyCommand=$PROXY_CMD" \
    -i "$KEY" \
    -p 22 \
    root@192.168.5.2 \
    "$@"
