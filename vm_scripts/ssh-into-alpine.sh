#!/bin/sh
# Connects directly over `puff-tap` (192.168.8.1/24) to the Alpine Linux guest
# started by `run-linux.sh`, `run-passthrough-net-linux.sh`, or `run-passthrough-blk-linux.sh`.
# See also:
#   ./ssh-into-motor-os.sh
#   ./ssh-into-nested-motor-os.sh
#   ./ssh-into-nested-linux.sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
KEY="${MOTO_SSH_KEY:-$MOTO_DIR/test.key}"

if [ -f "$KEY" ]; then
    exec ssh \
        -F /dev/null \
        -o ProxyCommand=none \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -i "$KEY" \
        root@192.168.8.2 \
        "$@"
fi

exec ssh -o ProxyCommand=none root@192.168.8.2 "$@"
