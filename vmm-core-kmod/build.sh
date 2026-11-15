#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
set -euo pipefail

KMOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$KMOD_DIR/.." && pwd)"
LINUX_SRC="${LINUX_SRC:-$REPO_ROOT/../linux-stable}"
DEFAULT_KBUILD_DIR="$REPO_ROOT/target/linux-kbuild"
OUT_DIR="$REPO_ROOT/target/airlock"

KMOD_ONLY=0
KDIR=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --kmod-only)
            KMOD_ONLY=1
            shift
            ;;
        --kdir)
            KDIR="$2"
            shift 2
            ;;
        *)
            echo "Usage: $0 [--kmod-only] [--kdir /path/to/kbuild]" >&2
            exit 2
            ;;
    esac
done

JOBS="$(nproc)"
mkdir -p "$OUT_DIR"

if [[ "$KMOD_ONLY" -eq 0 ]]; then
    if [[ ! -f "$LINUX_SRC/Makefile" ]]; then
        echo "build.sh: Linux source tree not found at '$LINUX_SRC'" >&2
        exit 1
    fi
    KDIR="${KDIR:-$DEFAULT_KBUILD_DIR}"
    mkdir -p "$KDIR"

    STAMP_HASH="$(sha256sum \
        "$KMOD_DIR/l1-guest.config" \
        "$LINUX_SRC/arch/x86/configs/x86_64_defconfig" \
        "$LINUX_SRC/kernel/configs/kvm_guest.config" | sha256sum | awk '{print $1}')"
    STAMP_FILE="$KDIR/.airlock_config_stamp"

    if [[ ! -f "$KDIR/.config" ]] || [[ "$(cat "$STAMP_FILE" 2>/dev/null || true)" != "$STAMP_HASH" ]]; then
        echo "[airlock-build] Configuring out-of-tree L1 Linux kernel in $KDIR ..."
        (
            cd "$LINUX_SRC"
            KCONFIG_CONFIG="$KDIR/.config" \
                ./scripts/kconfig/merge_config.sh -m -O "$KDIR" \
                "$LINUX_SRC/arch/x86/configs/x86_64_defconfig" \
                "$LINUX_SRC/kernel/configs/kvm_guest.config" \
                "$KMOD_DIR/l1-guest.config" >/dev/null
        )
        make -C "$LINUX_SRC" O="$KDIR" olddefconfig >/dev/null
        echo "$STAMP_HASH" > "$STAMP_FILE"
    fi

    echo "[airlock-build] Building L1 bzImage & optional kvm modules (-j$JOBS) ..."
    make -C "$LINUX_SRC" O="$KDIR" -j"$JOBS" bzImage modules >/dev/null

    cp -f "$KDIR/arch/x86/boot/bzImage" "$OUT_DIR/bzImage"
    if [[ -f "$KDIR/virt/lib/irqbypass.ko" ]]; then
        cp -f "$KDIR/virt/lib/irqbypass.ko" "$OUT_DIR/irqbypass.ko"
    fi
    if [[ -f "$KDIR/arch/x86/kvm/kvm.ko" ]]; then
        cp -f "$KDIR/arch/x86/kvm/kvm.ko" "$OUT_DIR/kvm.ko"
    fi
    if [[ -f "$KDIR/arch/x86/kvm/kvm-amd.ko" ]]; then
        cp -f "$KDIR/arch/x86/kvm/kvm-amd.ko" "$OUT_DIR/kvm-amd.ko"
    fi
else
    KDIR="${KDIR:-/lib/modules/$(uname -r)/build}"
fi

KDIR="$(cd "$KDIR" && pwd)"
AUTOCONF="$KDIR/include/config/auto.conf"
if [[ ! -f "$AUTOCONF" ]]; then
    echo "build.sh: '$AUTOCONF' not found; build or prepare KDIR='$KDIR' first" >&2
    exit 1
fi

has_kcfg() {
    grep -Eq "^$1=(y|m)$" "$AUTOCONF"
}

get_kcfg_val() {
    sed -n "s/^$1=//p" "$AUTOCONF" | head -n 1
}

KDIR_KEY="$(printf '%s' "$KDIR" | sha256sum | cut -c1-12)"
RUST_WORK_DIR="$REPO_ROOT/target/airlock-rust-$KDIR_KEY"
mkdir -p "$RUST_WORK_DIR"

TARGET_FEATURES="-mmx,-sse,-sse2,-sse3,-ssse3,-sse4.1,-sse4.2,-avx,-avx2,+soft-float"
if has_kcfg CONFIG_MITIGATION_RETPOLINE; then
    TARGET_FEATURES="${TARGET_FEATURES},+retpoline-external-thunk,+retpoline-indirect-branches,+retpoline-indirect-calls"
fi
if has_kcfg CONFIG_MITIGATION_SLS; then
    TARGET_FEATURES="${TARGET_FEATURES},+harden-sls-ijmp,+harden-sls-ret"
fi

# Named `x86_64-unknown-none.json` so Wasmtime's `build.rs` selects bare-metal x86_64.
TARGET_JSON="$RUST_WORK_DIR/x86_64-unknown-none.json"
cat > "$TARGET_JSON" <<EOF
{
  "arch": "x86_64",
  "code-model": "kernel",
  "cpu": "x86-64",
  "data-layout": "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
  "disable-redzone": true,
  "features": "$TARGET_FEATURES",
  "llvm-target": "x86_64-linux-gnu",
  "max-atomic-width": 64,
  "panic-strategy": "abort",
  "relocation-model": "static",
  "rustc-abi": "softfloat",
  "target-pointer-width": 64
}
EOF

KMOD_RUSTFLAGS="-Cforce-frame-pointers=y -Csymbol-mangling-version=v0 -Cforce-unwind-tables=n -Cembed-bitcode=n -Zfunction-sections=n"
if has_kcfg CONFIG_MITIGATION_RETHUNK; then
    KMOD_RUSTFLAGS="$KMOD_RUSTFLAGS -Zfunction-return=thunk-extern"
fi
if has_kcfg CONFIG_X86_KERNEL_IBT; then
    KMOD_RUSTFLAGS="$KMOD_RUSTFLAGS -Zcf-protection=branch -Cjump-tables=n"
fi
if has_kcfg CONFIG_CALL_PADDING; then
    PAD_BYTES="$(get_kcfg_val CONFIG_FUNCTION_PADDING_BYTES)"
    PAD_BYTES="${PAD_BYTES:-16}"
    KMOD_RUSTFLAGS="$KMOD_RUSTFLAGS -Zpatchable-function-entry=${PAD_BYTES},${PAD_BYTES}"
fi

echo "[airlock-build] Compiling airlock-rust staticlib for KDIR=$KDIR ..."
(
    unset CARGO RUSTC RUSTDOC RUSTUP_TOOLCHAIN CARGO_ENCODED_RUSTFLAGS
    export RUSTC_BOOTSTRAP=1
    export CARGO_NET_OFFLINE=true
    export RUSTFLAGS="$KMOD_RUSTFLAGS"
    cargo build --release \
        --manifest-path "$KMOD_DIR/rust/Cargo.toml" \
        --target "$TARGET_JSON" \
        --target-dir "$RUST_WORK_DIR/cargo-target" \
        -Zjson-target-spec \
        -Zbuild-std=core,alloc \
        -Zbuild-std-features=compiler-builtins-mem
)

STATICLIB="$RUST_WORK_DIR/cargo-target/x86_64-unknown-none/release/libairlock_rust.a"
RAW_OBJ="$RUST_WORK_DIR/airlock_rust.raw.o"
KEEP_SYMS="$RUST_WORK_DIR/keep_syms.txt"

cat > "$KEEP_SYMS" <<'EOF'
airlock_rust_init
airlock_rust_exit
airlock_rust_get_caps
airlock_rust_vm_create
airlock_rust_vm_destroy
airlock_rust_on_msix_irq
EOF

ld -r -m elf_x86_64 \
    -u airlock_rust_init \
    -u airlock_rust_exit \
    -u airlock_rust_get_caps \
    -u airlock_rust_vm_create \
    -u airlock_rust_vm_destroy \
    -u airlock_rust_on_msix_irq \
    "$STATICLIB" -o "$RAW_OBJ"

# Mark Wasmtime's inline-asm trap unwinder (`throw`/`raise` SP+FP restore gadget)
# with `STACK_FRAME_NON_STANDARD` (`.discard.func_stack_frame_non_standard`) for objtool.
ANNOT_ASM="$RUST_WORK_DIR/objtool_annot.s"
ANNOT_OBJ="$RUST_WORK_DIR/objtool_annot.o"
MERGED_OBJ="$RUST_WORK_DIR/airlock_rust.merged.o"
: > "$ANNOT_ASM"
while IFS= read -r sym; do
    [[ -n "$sym" ]] || continue
    cat >> "$ANNOT_ASM" <<EOF
.pushsection .discard.func_stack_frame_non_standard, "aw"
.quad $sym
.popsection
EOF
done < <(nm "$RAW_OBJ" | awk '/wasmtime.*(libcalls.*raw.*raise|unwinder.*throw)/ {print $3}')

if [[ -s "$ANNOT_ASM" ]]; then
    # Temporarily globalize referenced local symbols if needed, link annotation, then localize.
    ANNOT_SYMS="$RUST_WORK_DIR/annot_syms.txt"
    nm "$RAW_OBJ" | awk '/wasmtime.*(libcalls.*raw.*raise|unwinder.*throw)/ {print $3}' > "$ANNOT_SYMS"
    objcopy --globalize-symbols="$ANNOT_SYMS" "$RAW_OBJ" "$RAW_OBJ.glob"
    as --64 "$ANNOT_ASM" -o "$ANNOT_OBJ"
    ld -r -m elf_x86_64 "$RAW_OBJ.glob" "$ANNOT_OBJ" -o "$MERGED_OBJ"
else
    cp -f "$RAW_OBJ" "$MERGED_OBJ"
fi

objcopy \
    --keep-global-symbols="$KEEP_SYMS" \
    --remove-section=.eh_frame \
    --remove-section=.eh_frame_hdr \
    "$MERGED_OBJ" "$KMOD_DIR/airlock_rust.blob.o"

# Verify zero FP/SIMD registers in the compiled Rust object.
if objdump -d "$KMOD_DIR/airlock_rust.blob.o" | grep -Eq '%(xmm|ymm|zmm|mm)[0-9]'; then
    echo "ERROR: Floating-point or SIMD register found in airlock_rust.blob.o!" >&2
    objdump -d "$KMOD_DIR/airlock_rust.blob.o" | grep -En -C 3 '%(xmm|ymm|zmm|mm)[0-9]' | head -n 40 >&2
    exit 1
fi

echo "[airlock-build] Linking out-of-tree airlock.ko via Kbuild ..."
make -C "$KDIR" M="$KMOD_DIR" -j"$JOBS" modules

if objdump -d "$KMOD_DIR/airlock.ko" | grep -Eq '%(xmm|ymm|zmm|mm)[0-9]'; then
    echo "ERROR: Floating-point or SIMD register found in airlock.ko!" >&2
    exit 1
fi

cp -f "$KMOD_DIR/airlock.ko" "$OUT_DIR/airlock.ko"
gcc -static -Os -Wall -Werror "$KMOD_DIR/c/airlock_ioctl_check.c" -o "$OUT_DIR/airlock-ioctl-check"
strip "$OUT_DIR/airlock-ioctl-check"
echo "[airlock-build] Ready: $OUT_DIR/airlock.ko"
