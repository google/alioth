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

echo "Building vmm-host (x86_64-unknown-linux-musl release)..."
cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-host --release --target=x86_64-unknown-linux-musl

echo "Building vmm-runner.wasm (wasm32-wasip2 release)..."
cargo build --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-runner --bin vmm-runner --release --target=wasm32-wasip2

echo "Copying artifacts to $DEST_DIR..."
cp "$REPO_ROOT/target/x86_64-unknown-linux-musl/release/vmm-host" "$DEST_DIR/vmm-host"
chmod 750 "$DEST_DIR/vmm-host"

cp "$REPO_ROOT/target/wasm32-wasip2/release/vmm-runner.wasm" "$DEST_DIR/vmm-runner.wasm"
chmod 640 "$DEST_DIR/vmm-runner.wasm"

cat > "$DEST_DIR/run-vm.sh" << 'EOF'
#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ $# -eq 0 ]; then
    CONFIG="$SCRIPT_DIR/vm.toml"
    if [ ! -f "$CONFIG" ]; then
        echo "Error: $CONFIG not found." >&2
        echo "Please create vm.toml in $SCRIPT_DIR or pass a config file as an input parameter:" >&2
        echo "  $0 <path/to/vm.toml>" >&2
        exit 1
    fi
elif [ $# -eq 1 ]; then
    CONFIG="$1"
    if [ ! -f "$CONFIG" ]; then
        echo "Error: config file '$CONFIG' not found." >&2
        echo "Please create vm.toml in $SCRIPT_DIR or pass a valid config file as an input parameter:" >&2
        echo "  $0 <path/to/vm.toml>" >&2
        exit 1
    fi
elif [ $# -eq 2 ] && [ "$1" = "-c" ]; then
    CONFIG="$2"
    if [ ! -f "$CONFIG" ]; then
        echo "Error: config file '$CONFIG' not found." >&2
        echo "Please create vm.toml in $SCRIPT_DIR or pass a valid config file as an input parameter:" >&2
        echo "  $0 <path/to/vm.toml>" >&2
        exit 1
    fi
else
    echo "Usage: $0 [path/to/vm.toml]" >&2
    exit 1
fi

CONFIG_DIR=$(CDPATH= cd -- "$(dirname -- "$CONFIG")" && pwd)
CONFIG_FILE=$(basename -- "$CONFIG")

cd "$CONFIG_DIR"
exec "$SCRIPT_DIR/vmm-host" -c "$CONFIG_FILE" -w "$SCRIPT_DIR/vmm-runner.wasm"
EOF

chmod 750 "$DEST_DIR/run-vm.sh"
echo "Published vmm-host, vmm-runner.wasm, and run-vm.sh to $DEST_DIR"
