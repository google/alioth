#!/bin/sh
# Connects to the nested L2 Motor OS guest (`motor@192.168.5.2:2222`) running on
# `airlock.ko` inside L1 Linux (`run-airlock-linux-motor-os.sh`), jumping via
# L1's OpenSSH server (`root@192.168.8.2:22`).
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
KEY="${MOTO_SSH_KEY:-$MOTO_DIR/test.key}"

if [ ! -f "$KEY" ]; then
    echo "ssh-into-airlock-nested-motor-os: SSH key '$KEY' not found (override with MOTO_SSH_KEY)" >&2
    exit 1
fi

PROXY_CMD="ssh -F /dev/null -o ProxyCommand=none -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i $KEY -W %h:%p -p 22 root@192.168.8.2"

exec ssh \
    -F /dev/null \
    -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -o "ProxyCommand=$PROXY_CMD" \
    -i "$KEY" \
    -p 2222 \
    motor@192.168.5.2 \
    "$@"
