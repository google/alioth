#!/bin/sh
# Connects to the Motor OS guest (`motor@192.168.4.2:2222`, or `192.168.8.2:2222`
# when `run-airlock-linux-motor-os.sh` falls back to `puff-tap`) started by
# `run-motor-os.sh`, `run-nested-motor-os.sh`, `run-nested-linux.sh`, or
# `run-airlock-linux-motor-os.sh --passthrough-{net,all}`.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
KEY="${MOTO_SSH_KEY:-$MOTO_DIR/test.key}"
AIRLOCK_HOST_FILE="$REPO_ROOT/target/vm-runtime/airlock-linux-motor-os/ssh-host"

if [ ! -f "$KEY" ]; then
    echo "ssh-into-motor-os: SSH key '$KEY' not found (override with MOTO_SSH_KEY)" >&2
    exit 1
fi

if [ -n "${MOTO_SSH_HOST:-}" ]; then
    TARGET_HOST="$MOTO_SSH_HOST"
elif [ -d /sys/class/net/moto-tap ]; then
    TARGET_HOST="192.168.4.2"
elif [ -f "$AIRLOCK_HOST_FILE" ]; then
    TARGET_HOST=$(cat "$AIRLOCK_HOST_FILE")
else
    TARGET_HOST="192.168.4.2"
fi

exec ssh \
    -F /dev/null \
    -o ProxyCommand=none \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i "$KEY" \
    -p 2222 \
    "motor@$TARGET_HOST" \
    "$@"
