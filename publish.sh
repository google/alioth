#!/bin/sh
set -e

if [ $# -ne 1 ] || [ -z "$1" ]; then
    echo "Usage: $0 <DIR>" >&2
    exit 1
fi

DEST_DIR="$1"
REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

mkdir -m 750 -p "$DEST_DIR"
DEST_DIR=$(CDPATH= cd -- "$DEST_DIR" && pwd)

echo "Building split hosts and guests (x86_64-unknown-linux-musl release)..."
cargo build --manifest-path "$REPO_ROOT/Cargo.toml" --release --target=x86_64-unknown-linux-musl

echo "Copying artifacts to $DEST_DIR..."
for bin in vmm-core-host-cwasm vmm-core-host-wasm vmm-io-host-cwasm vmm-io-host-wasm; do
    cp "$REPO_ROOT/target/x86_64-unknown-linux-musl/release/$bin" "$DEST_DIR/$bin"
    chmod 750 "$DEST_DIR/$bin"
done

for mod in vmm-core.cwasm vmm-core.wasm vmm-io.cwasm vmm-io.wasm; do
    cp "$REPO_ROOT/target/x86_64-unknown-linux-musl/release/$mod" "$DEST_DIR/$mod"
    chmod 640 "$DEST_DIR/$mod"
done

cat > "$DEST_DIR/run-vm.sh" << 'EOF'
#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

usage() {
    echo "Usage: $0 (--wasm | --cwasm) [path/to/vm.toml]" >&2
    echo "" >&2
    echo "Required mode flag (choose one):" >&2
    echo "  --wasm    Run the 'safe' split pair (vmm-{io,core}-host-wasm + vmm-{io,core}.wasm)" >&2
    echo "  --cwasm   Run the 'small' split pair (vmm-{io,core}-host-cwasm + vmm-{io,core}.cwasm)" >&2
    exit 1
}

MODE=""
CONFIG=""

while [ $# -gt 0 ]; do
    case "$1" in
        --wasm)
            if [ -n "$MODE" ]; then
                echo "Error: cannot specify both --wasm and --cwasm." >&2
                usage
            fi
            MODE="wasm"
            shift
            ;;
        --cwasm)
            if [ -n "$MODE" ]; then
                echo "Error: cannot specify both --wasm and --cwasm." >&2
                usage
            fi
            MODE="cwasm"
            shift
            ;;
        -c)
            if [ $# -lt 2 ]; then
                usage
            fi
            CONFIG="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        -*)
            echo "Error: unknown option '$1'." >&2
            usage
            ;;
        *)
            if [ -n "$CONFIG" ]; then
                echo "Error: multiple config files specified ('$CONFIG' and '$1')." >&2
                usage
            fi
            CONFIG="$1"
            shift
            ;;
    esac
done

if [ -z "$MODE" ]; then
    echo "Error: must specify either --wasm or --cwasm." >&2
    usage
fi

if [ -z "$CONFIG" ]; then
    CONFIG="$SCRIPT_DIR/vm.toml"
    if [ ! -f "$CONFIG" ]; then
        echo "Error: $CONFIG not found." >&2
        echo "Please create vm.toml in $SCRIPT_DIR or pass a config file as an input parameter:" >&2
        echo "  $0 --$MODE <path/to/vm.toml>" >&2
        exit 1
    fi
else
    if [ ! -f "$CONFIG" ]; then
        echo "Error: config file '$CONFIG' not found." >&2
        echo "Please create vm.toml in $SCRIPT_DIR or pass a valid config file as an input parameter:" >&2
        echo "  $0 --$MODE <path/to/vm.toml>" >&2
        exit 1
    fi
fi

CONFIG_DIR=$(CDPATH= cd -- "$(dirname -- "$CONFIG")" && pwd)
CONFIG_FILE=$(basename -- "$CONFIG")

cd "$CONFIG_DIR"
if [ "$MODE" = "wasm" ]; then
    exec "$SCRIPT_DIR/vmm-io-host-wasm" \
        -c "$CONFIG_FILE" \
        -w "$SCRIPT_DIR/vmm-io.wasm" \
        --core-host "$SCRIPT_DIR/vmm-core-host-wasm" \
        --core-wasm "$SCRIPT_DIR/vmm-core.wasm"
else
    exec "$SCRIPT_DIR/vmm-io-host-cwasm" \
        -c "$CONFIG_FILE" \
        -w "$SCRIPT_DIR/vmm-io.cwasm" \
        --core-host "$SCRIPT_DIR/vmm-core-host-cwasm" \
        --core-wasm "$SCRIPT_DIR/vmm-core.cwasm"
fi
EOF

chmod 750 "$DEST_DIR/run-vm.sh"
echo "Published split VMM hosts, modules, and run-vm.sh to $DEST_DIR"
