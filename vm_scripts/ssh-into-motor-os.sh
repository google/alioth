#!/bin/sh
# Connects to the Motor OS guest (192.168.4.2:2222) started by `run-motor-os.sh`
# or to L1 Motor OS started by `run-nested-motor-os.sh` / `run-nested-linux.sh`.
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
KEY="${MOTO_SSH_KEY:-$MOTO_DIR/test.key}"

if [ ! -f "$KEY" ]; then
    echo "ssh-into-motor-os: SSH key '$KEY' not found (override with MOTO_SSH_KEY)" >&2
    exit 1
fi

exec ssh \
    -F /dev/null \
    -o ProxyCommand=none \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -i "$KEY" \
    -p 2222 \
    motor@192.168.4.2 \
    "$@"
