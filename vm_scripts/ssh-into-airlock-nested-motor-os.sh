#!/bin/sh
# Connects to the nested L2 Motor OS guest running on `airlock.ko`
# (`run-airlock-linux-motor-os.sh`):
#   - In `--passthrough-all` / `--passthrough-net` modes, L0's host TAP is passed
#     straight through to L2, so this connects directly to `motor@<host>:2222`
#     (`192.168.4.2` on `moto-tap`, or `192.168.8.2` when falling back to `puff-tap`).
#   - In default bridged mode, L1 owns `192.168.8.2` and this jumps via L1's OpenSSH
#     server to `motor@192.168.5.2:2222`.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime/airlock-linux-motor-os"
L1_KEY="${LINUX_SSH_KEY:-$REPO_ROOT/target/airlock/id_ed25519}"
MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
MOTO_KEY="${MOTO_SSH_KEY:-$MOTO_DIR/test.key}"

if [ ! -f "$MOTO_KEY" ]; then
    echo "ssh-into-airlock-nested-motor-os: Motor OS SSH key '$MOTO_KEY' not found (override with MOTO_SSH_KEY)" >&2
    exit 1
fi

SSH_MODE=""
if [ -f "$RUNTIME_DIR/ssh-mode" ]; then
    SSH_MODE=$(cat "$RUNTIME_DIR/ssh-mode")
elif [ -f "$RUNTIME_DIR/initramfs-airlock-pt-all-motor-os.cpio" ]; then
    SSH_MODE="direct"
fi

if [ "$SSH_MODE" = "direct" ]; then
    if [ -n "${MOTO_SSH_HOST:-}" ]; then
        TARGET_HOST="$MOTO_SSH_HOST"
    elif [ -f "$RUNTIME_DIR/ssh-host" ]; then
        TARGET_HOST=$(cat "$RUNTIME_DIR/ssh-host")
    elif [ -d /sys/class/net/moto-tap ]; then
        TARGET_HOST="192.168.4.2"
    else
        TARGET_HOST="192.168.8.2"
    fi
    exec ssh \
        -F /dev/null \
        -o ProxyCommand=none \
        -o IdentitiesOnly=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$MOTO_KEY" \
        -p 2222 \
        "motor@$TARGET_HOST" \
        "$@"
fi

if [ ! -f "$L1_KEY" ]; then
    echo "ssh-into-airlock-nested-motor-os: L1 Linux SSH key '$L1_KEY' not found (override with LINUX_SSH_KEY)" >&2
    exit 1
fi

PROXY_CMD="ssh -F /dev/null -o ProxyCommand=none -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $L1_KEY -W %h:%p -p 22 root@192.168.8.2"

exec ssh \
    -F /dev/null \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o "ProxyCommand=$PROXY_CMD" \
    -i "$MOTO_KEY" \
    -p 2222 \
    motor@192.168.5.2 \
    "$@"
