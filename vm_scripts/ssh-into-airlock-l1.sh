#!/bin/sh
# Connects directly over `puff-tap` (192.168.8.1/24) to the disk-backed L1 Alpine
# Linux hypervisor guest (`root@192.168.8.2:22`) started by
# `run-airlock-linux-motor-os.sh` or `run-airlock-linux-alpine.sh`.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
KEY="${MOTO_SSH_KEY:-$MOTO_DIR/test.key}"

if [ ! -f "$KEY" ]; then
    echo "ssh-into-airlock-l1: SSH key '$KEY' not found (override with MOTO_SSH_KEY)" >&2
    exit 1
fi

exec ssh \
    -F /dev/null \
    -o ProxyCommand=none \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i "$KEY" \
    root@192.168.8.2 \
    "$@"
