#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime"
LINUX_BLOBS_DIR="${LINUX_BLOBS_DIR:-$REPO_ROOT/../linux-blobs}"

if [ ! -d "$LINUX_BLOBS_DIR" ]; then
    echo "run-linux: Linux blobs directory '$LINUX_BLOBS_DIR' not found (override with LINUX_BLOBS_DIR)" >&2
    exit 1
fi
LINUX_BLOBS_DIR=$(CDPATH= cd -- "$LINUX_BLOBS_DIR" && pwd)

MODE="cwasm"
CONFIG="$RUNTIME_DIR/vm-linux.toml"
CUSTOM_CONFIG=0
SMP="${LINUX_SMP:-4}"
MEM_SIZE="${LINUX_MEM_SIZE:-256M}"
IMAGE="${LINUX_IMAGE:-alpine.raw}"
NO_NETWORK=0

usage() {
    cat >&2 <<EOF
Usage: $0 [--cwasm | --wasm] [-c path/to/vm.toml] [--cpus N] [--memory SIZE] [--no-network]
  --cwasm         Run vmm-{io,core}-host-cwasm + vmm-{io,core}.cwasm (default)
  --wasm          Run vmm-{io,core}-host-wasm + vmm-{io,core}.wasm
  -c FILE         Use an existing custom wasm-vmm TOML config
  --cpus N        Override vCPU count (or set LINUX_SMP, default: 4)
  --memory SIZE   Override guest RAM with M or G suffix (or set LINUX_MEM_SIZE, default: 256M)
  --no-network    Omit the virtio-net device (puff-tap)

Environment variables:
  LINUX_BLOBS_DIR Directory holding bzImage and alpine.raw (default: $LINUX_BLOBS_DIR)
  LINUX_IMAGE     Root raw disk filename in LINUX_BLOBS_DIR (default: alpine.raw)
  LINUX_VM_LOCK   Host lock file for puff-tap / alpine.raw (default: /tmp/wasm-vmm-linux.<uid>.lock)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --wasm)
            MODE="wasm"
            shift
            ;;
        --cwasm)
            MODE="cwasm"
            shift
            ;;
        -c)
            [ "$#" -ge 2 ] || { echo "run-linux: -c requires a config path" >&2; exit 2; }
            CONFIG="$2"
            CUSTOM_CONFIG=1
            shift 2
            ;;
        --cpus)
            [ "$#" -ge 2 ] || { echo "run-linux: --cpus requires a value" >&2; exit 2; }
            SMP="$2"
            shift 2
            ;;
        --cpus=*)
            SMP="${1#--cpus=}"
            shift
            ;;
        --memory)
            [ "$#" -ge 2 ] || { echo "run-linux: --memory requires a value" >&2; exit 2; }
            MEM_SIZE="$2"
            shift 2
            ;;
        --memory=*)
            MEM_SIZE="${1#--memory=}"
            shift
            ;;
        --no-network)
            NO_NETWORK=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "run-linux: unknown argument '$1'" >&2
            usage
            exit 2
            ;;
    esac
done

VM_LOCK="${LINUX_VM_LOCK:-/tmp/wasm-vmm-linux.$(id -u).lock}"
exec 9>"$VM_LOCK"
if ! flock -n 9; then
    echo "run-linux: another Linux VM owns $VM_LOCK" >&2
    exit 1
fi

if [ "$CUSTOM_CONFIG" = 1 ]; then
    if [ ! -f "$CONFIG" ]; then
        echo "run-linux: config file '$CONFIG' not found" >&2
        exit 1
    fi
else
    KERNEL_PATH="$LINUX_BLOBS_DIR/bzImage"
    DISK_PATH="$LINUX_BLOBS_DIR/$IMAGE"
    if [ ! -f "$KERNEL_PATH" ]; then
        echo "run-linux: kernel '$KERNEL_PATH' not found" >&2
        exit 1
    fi
    if [ ! -f "$DISK_PATH" ]; then
        echo "run-linux: disk image '$DISK_PATH' not found" >&2
        exit 1
    fi
    if [ "$NO_NETWORK" != 1 ] && [ ! -d /sys/class/net/puff-tap ]; then
        echo "run-linux: tap device 'puff-tap' not found; run '$SCRIPT_DIR/create-tap.sh' or pass --no-network" >&2
        exit 1
    fi

    mkdir -m 750 -p "$RUNTIME_DIR"
    LOG_FILE="${WASM_VMM_LOG:-/tmp/wasm-vmm-linux.log}"
    LOG_LEVEL="${WASM_VMM_LOG_LEVEL:-info}"

    {
        printf 'kernel = "%s"\n' "$KERNEL_PATH"
        printf 'cmd_line = "console=ttyS0 root=/dev/vda3 rw"\n'
        printf 'num_cpus = %s\n' "$SMP"
        printf 'mem_size = "%s"\n' "$MEM_SIZE"
        printf 'blk = ["%s"]\n' "$DISK_PATH"
        printf 'log_file = "%s"\n' "$LOG_FILE"
        printf 'log_level = "%s"\n' "$LOG_LEVEL"
        if [ "$NO_NETWORK" != 1 ]; then
            printf '\n[net.dev0]\n'
            printf 'mac = "a4:a1:c2:00:00:01"\n'
            printf 'mtu = 1500\n'
            printf 'if_name = "puff-tap"\n'
        fi
    } > "$CONFIG"
    chmod 640 "$CONFIG"
fi

exec "$SCRIPT_DIR/run-vm.sh" "--$MODE" -c "$CONFIG"
