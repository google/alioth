#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime"
LINUX_BLOBS_DIR="${LINUX_BLOBS_DIR:-$REPO_ROOT/../linux-blobs}"

if [ ! -d "$LINUX_BLOBS_DIR" ]; then
    echo "run-linux-initrd: Linux blobs directory '$LINUX_BLOBS_DIR' not found (override with LINUX_BLOBS_DIR)" >&2
    exit 1
fi
LINUX_BLOBS_DIR=$(CDPATH= cd -- "$LINUX_BLOBS_DIR" && pwd)

MODE="cwasm"
CONFIG="$RUNTIME_DIR/vm-linux-initrd.toml"
CUSTOM_CONFIG=0
SMP="${LINUX_INITRD_SMP:-2}"
MEM_SIZE="${LINUX_INITRD_MEM_SIZE:-256M}"

usage() {
    cat >&2 <<EOF
Usage: $0 [--cwasm | --wasm] [-c path/to/vm-initrd.toml] [--cpus N] [--memory SIZE]
  --cwasm         Run vmm-{io,core}-host-cwasm + vmm-{io,core}.cwasm (default)
  --wasm          Run vmm-{io,core}-host-wasm + vmm-{io,core}.wasm
  -c FILE         Use an existing custom wasm-vmm TOML config
  --cpus N        Override vCPU count (default: 2)
  --memory SIZE   Override guest RAM with M or G suffix (default: 256M)

Environment variables:
  LINUX_BLOBS_DIR Directory holding bzImage and initramfs.cpio.gz (default: $LINUX_BLOBS_DIR)
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
            [ "$#" -ge 2 ] || { echo "run-linux-initrd: -c requires a config path" >&2; exit 2; }
            CONFIG="$2"
            CUSTOM_CONFIG=1
            shift 2
            ;;
        --cpus)
            [ "$#" -ge 2 ] || { echo "run-linux-initrd: --cpus requires a value" >&2; exit 2; }
            SMP="$2"
            shift 2
            ;;
        --cpus=*)
            SMP="${1#--cpus=}"
            shift
            ;;
        --memory)
            [ "$#" -ge 2 ] || { echo "run-linux-initrd: --memory requires a value" >&2; exit 2; }
            MEM_SIZE="$2"
            shift 2
            ;;
        --memory=*)
            MEM_SIZE="${1#--memory=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "run-linux-initrd: unknown argument '$1'" >&2
            usage
            exit 2
            ;;
    esac
done

if [ "$CUSTOM_CONFIG" = 1 ]; then
    if [ ! -f "$CONFIG" ]; then
        echo "run-linux-initrd: config file '$CONFIG' not found" >&2
        exit 1
    fi
else
    KERNEL_PATH="$LINUX_BLOBS_DIR/bzImage"
    INITRAMFS_PATH="$LINUX_BLOBS_DIR/initramfs.cpio.gz"
    if [ ! -f "$KERNEL_PATH" ]; then
        echo "run-linux-initrd: kernel '$KERNEL_PATH' not found" >&2
        exit 1
    fi
    if [ ! -f "$INITRAMFS_PATH" ]; then
        echo "run-linux-initrd: initramfs '$INITRAMFS_PATH' not found" >&2
        exit 1
    fi

    mkdir -m 750 -p "$RUNTIME_DIR"
    LOG_FILE="${WASM_VMM_LOG:-/tmp/wasm-vmm-initrd.log}"
    LOG_LEVEL="${WASM_VMM_LOG_LEVEL:-info}"

    {
        printf 'kernel = "%s"\n' "$KERNEL_PATH"
        printf 'initramfs = "%s"\n' "$INITRAMFS_PATH"
        printf 'cmd_line = "console=ttyS0 rdinit=/init"\n'
        printf 'num_cpus = %s\n' "$SMP"
        printf 'mem_size = "%s"\n' "$MEM_SIZE"
        printf 'log_file = "%s"\n' "$LOG_FILE"
        printf 'log_level = "%s"\n' "$LOG_LEVEL"
    } > "$CONFIG"
    chmod 640 "$CONFIG"
fi

exec "$SCRIPT_DIR/run-vm.sh" "--$MODE" -c "$CONFIG"
