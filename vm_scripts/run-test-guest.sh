#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime"
TEST_GUEST_DIR="$REPO_ROOT/target/test-guest"

MODE="cwasm"
CONFIG="$RUNTIME_DIR/vm-test-guest.toml"
CUSTOM_CONFIG=0
SMP="${TEST_GUEST_SMP:-2}"
MEM_SIZE="${TEST_GUEST_MEM_SIZE:-64M}"
CMDLINE="${TEST_GUEST_CMDLINE:-test-guest}"

usage() {
    cat >&2 <<EOF
Usage: $0 [--cwasm | --wasm] [-c path/to/vm-test-guest.toml] [--cpus N] [--memory SIZE] [--cmdline STR]
  --cwasm         Run vmm-{io,core}-host-cwasm + vmm-{io,core}.cwasm (default)
  --wasm          Run vmm-{io,core}-host-wasm + vmm-{io,core}.wasm
  -c FILE         Use an existing custom wasm-vmm TOML config
  --cpus N        Override vCPU count (default: 2)
  --memory SIZE   Override guest RAM with M or G suffix (default: 64M)
  --cmdline STR   Override kernel command line (default: test-guest)
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
            [ "$#" -ge 2 ] || { echo "run-test-guest: -c requires a config path" >&2; exit 2; }
            CONFIG="$2"
            CUSTOM_CONFIG=1
            shift 2
            ;;
        --cpus)
            [ "$#" -ge 2 ] || { echo "run-test-guest: --cpus requires a value" >&2; exit 2; }
            SMP="$2"
            shift 2
            ;;
        --cpus=*)
            SMP="${1#--cpus=}"
            shift
            ;;
        --memory)
            [ "$#" -ge 2 ] || { echo "run-test-guest: --memory requires a value" >&2; exit 2; }
            MEM_SIZE="$2"
            shift 2
            ;;
        --memory=*)
            MEM_SIZE="${1#--memory=}"
            shift
            ;;
        --cmdline)
            [ "$#" -ge 2 ] || { echo "run-test-guest: --cmdline requires a value" >&2; exit 2; }
            CMDLINE="$2"
            shift 2
            ;;
        --cmdline=*)
            CMDLINE="${1#--cmdline=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "run-test-guest: unknown argument '$1'" >&2
            usage
            exit 2
            ;;
    esac
done

case "$CMDLINE" in
    *\"* | *'
'*)
        echo "run-test-guest: --cmdline cannot contain double quotes or newlines" >&2
        exit 2
        ;;
esac

if [ "$CUSTOM_CONFIG" = 1 ]; then
    if [ ! -f "$CONFIG" ]; then
        echo "run-test-guest: config file '$CONFIG' not found" >&2
        exit 1
    fi
else
    cargo run --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-tests --bin build_test_guest >&2

    KLOADER_PATH="$TEST_GUEST_DIR/kloader"
    INITRD_PATH="$TEST_GUEST_DIR/initrd-test-guest"
    if [ ! -f "$KLOADER_PATH" ] || [ ! -f "$INITRD_PATH" ]; then
        echo "run-test-guest: expected artifacts missing under '$TEST_GUEST_DIR'" >&2
        exit 1
    fi

    mkdir -m 750 -p "$RUNTIME_DIR"
    LOG_FILE="${WASM_VMM_LOG:-/tmp/wasm-vmm-test-guest.log}"
    LOG_LEVEL="${WASM_VMM_LOG_LEVEL:-info}"

    {
        printf 'pvh = "%s"\n' "$KLOADER_PATH"
        printf 'initramfs = "%s"\n' "$INITRD_PATH"
        printf 'cmd_line = "%s"\n' "$CMDLINE"
        printf 'num_cpus = %s\n' "$SMP"
        printf 'mem_size = "%s"\n' "$MEM_SIZE"
        printf 'blk = []\n'
        printf 'log_file = "%s"\n' "$LOG_FILE"
        printf 'log_level = "%s"\n' "$LOG_LEVEL"
    } > "$CONFIG"
    chmod 640 "$CONFIG"
fi

exec "$SCRIPT_DIR/run-vm.sh" "--$MODE" -c "$CONFIG"
