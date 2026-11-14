#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${MOTO_VMM_OUT:-$REPO_ROOT/target/motor}"
TARGET_DIR="${CARGO_TARGET_DIR:-$SCRIPT_DIR/target}"

cd "$SCRIPT_DIR"
unset CARGO RUSTC RUSTDOC RUSTUP_TOOLCHAIN

SYSROOT="$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-motor/sysroot"
export CC_x86_64_unknown_motor="$SYSROOT/bin/motor-clang"
export CARGO_TARGET_X86_64_UNKNOWN_MOTOR_LINKER="$SYSROOT/bin/motor-clang"
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-true}"

mkdir -p "$OUT_DIR"

echo "Building motor-io-host-cwasm (runtime-only, x86_64-unknown-motor)..."
CARGO_TARGET_DIR="$TARGET_DIR/cwasm" cargo build --release --target x86_64-unknown-motor
cp "$TARGET_DIR/cwasm/x86_64-unknown-motor/release/motor-io-host" "$OUT_DIR/motor-io-host-cwasm"

echo "Building motor-io-host-wasm (with Cranelift JIT, x86_64-unknown-motor)..."
CARGO_TARGET_DIR="$TARGET_DIR/wasm" cargo build --release --features compiler --target x86_64-unknown-motor
cp "$TARGET_DIR/wasm/x86_64-unknown-motor/release/motor-io-host" "$OUT_DIR/motor-io-host-wasm"

if [[ -f "$REPO_ROOT/target/wasm32-wasip1/release/vmm-io.wasm" ]]; then
    cp "$REPO_ROOT/target/wasm32-wasip1/release/vmm-io.wasm" "$OUT_DIR/vmm-io.wasm"
fi
for candidate in \
    "$REPO_ROOT/target/x86_64-unknown-linux-musl/release/vmm-core-motor.cwasm" \
    "$REPO_ROOT/target/release/vmm-core-motor.cwasm"; do
    if [[ -f "$candidate" ]]; then
        cp "$candidate" "$OUT_DIR/vmm-core.cwasm"
        break
    fi
done

echo "Motor OS Ring-3 I/O host artifacts ready in $OUT_DIR"
