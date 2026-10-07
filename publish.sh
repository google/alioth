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

echo "Building vmm-host-cwasm, vmm-host-wasm, vmm-runner.cwasm, and vmm-runner.wasm (x86_64-unknown-linux-musl release)..."
cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-host --release --target=x86_64-unknown-linux-musl

echo "Copying artifacts to $DEST_DIR..."
cp "$REPO_ROOT/target/x86_64-unknown-linux-musl/release/vmm-host-cwasm" "$DEST_DIR/vmm-host-cwasm"
chmod 750 "$DEST_DIR/vmm-host-cwasm"

cp "$REPO_ROOT/target/x86_64-unknown-linux-musl/release/vmm-host-wasm" "$DEST_DIR/vmm-host-wasm"
chmod 750 "$DEST_DIR/vmm-host-wasm"

cp "$REPO_ROOT/target/x86_64-unknown-linux-musl/release/vmm-runner.cwasm" "$DEST_DIR/vmm-runner.cwasm"
chmod 640 "$DEST_DIR/vmm-runner.cwasm"

cp "$REPO_ROOT/target/x86_64-unknown-linux-musl/release/vmm-runner.wasm" "$DEST_DIR/vmm-runner.wasm"
chmod 640 "$DEST_DIR/vmm-runner.wasm"

cat > "$DEST_DIR/run-vm.sh" << 'EOF'
#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

usage() {
    echo "Usage: $0 (--wasm | --cwasm) [path/to/vm.toml]" >&2
    echo "" >&2
    echo "Required mode flag (choose one):" >&2
    echo "  --wasm    Run the 'safe' pair (vmm-host-wasm with built-in compiler + vmm-runner.wasm)" >&2
    echo "  --cwasm   Run the 'small' pair (vmm-host-cwasm + precompiled vmm-runner.cwasm)" >&2
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
    exec "$SCRIPT_DIR/vmm-host-wasm" -c "$CONFIG_FILE" -w "$SCRIPT_DIR/vmm-runner.wasm"
else
    exec "$SCRIPT_DIR/vmm-host-cwasm" -c "$CONFIG_FILE" -w "$SCRIPT_DIR/vmm-runner.cwasm"
fi
EOF

chmod 750 "$DEST_DIR/run-vm.sh"
echo "Published vmm-host-cwasm, vmm-host-wasm, vmm-runner.cwasm, vmm-runner.wasm, and run-vm.sh to $DEST_DIR"
