#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TARGET_DIR="$REPO_ROOT/target/x86_64-unknown-linux-musl/release"

MODE="cwasm"
CONFIG=""

usage() {
    cat >&2 <<EOF
Usage: $0 [--cwasm | --wasm] [-c path/to/vm.toml]
  --cwasm   Run vmm-{io,core}-host-cwasm + vmm-{io,core}.cwasm (default)
  --wasm    Run vmm-{io,core}-host-wasm + vmm-{io,core}.wasm
  -c FILE   Boot with the specified vm.toml (defaults to run-linux.sh when omitted)
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
            [ "$#" -ge 2 ] || { echo "run-vm: -c requires a config path" >&2; exit 2; }
            CONFIG="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            echo "run-vm: unknown option '$1'" >&2
            usage
            exit 2
            ;;
        *)
            if [ -n "$CONFIG" ]; then
                echo "run-vm: multiple config files specified ('$CONFIG' and '$1')" >&2
                usage
                exit 2
            fi
            CONFIG="$1"
            shift
            ;;
    esac
done

if [ -z "$CONFIG" ]; then
    exec "$SCRIPT_DIR/run-linux.sh" "--$MODE"
fi

if [ ! -f "$CONFIG" ]; then
    echo "run-vm: config file '$CONFIG' not found" >&2
    exit 1
fi

echo "Building split hosts and guests (x86_64-unknown-linux-musl / wasm32-unknown-unknown + wasm32-wasip1-threads release)..."
cargo build --manifest-path "$REPO_ROOT/Cargo.toml" \
    -p vmm-core-host -p vmm-io-host \
    --release --target=x86_64-unknown-linux-musl

CONFIG_DIR=$(CDPATH= cd -- "$(dirname -- "$CONFIG")" && pwd)
CONFIG_FILE=$(basename -- "$CONFIG")

cd "$CONFIG_DIR"
if [ "$MODE" = "wasm" ]; then
    exec "$TARGET_DIR/vmm-io-host-wasm" \
        -c "$CONFIG_FILE" \
        -w "$TARGET_DIR/vmm-io.wasm" \
        --core-host "$TARGET_DIR/vmm-core-host-wasm" \
        --core-wasm "$TARGET_DIR/vmm-core.wasm"
else
    exec "$TARGET_DIR/vmm-io-host-cwasm" \
        -c "$CONFIG_FILE" \
        -w "$TARGET_DIR/vmm-io.cwasm" \
        --core-host "$TARGET_DIR/vmm-core-host-cwasm" \
        --core-wasm "$TARGET_DIR/vmm-core.cwasm"
fi
