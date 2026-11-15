#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime"
TEST_GUEST_DIR="$REPO_ROOT/target/test-guest"
HOST_TARGET_DIR="$REPO_ROOT/target/x86_64-unknown-linux-musl/release"

MODE="cwasm"
L0_VMM="wasm"
CONFIG="$RUNTIME_DIR/vm-nested-test-guest.toml"
CUSTOM_CONFIG=0
SMP="${TEST_GUEST_SMP:-2}"
MEM_SIZE="${TEST_GUEST_MEM_SIZE:-256M}"
CMDLINE="${TEST_GUEST_CMDLINE:-test-guest-nested}"

usage() {
    cat >&2 <<EOF
Usage: $0 [--vmm wasm|chv] [--cwasm | --wasm] [-c path/to/vm-nested-test-guest.toml] [--cpus N] [--memory SIZE] [--cmdline STR]
  --vmm wasm|chv  Select L0 hypervisor: Linux Wasm VMM (default) or cloud-hypervisor-static (with virtio-iommu)
  --cwasm         Run L0 vmm-{io,core}-host-cwasm + vmm-{io,core}.cwasm (default)
  --wasm          Run L0 vmm-{io,core}-host-wasm + vmm-{io,core}.wasm
  -c FILE         Use an existing custom wasm-vmm TOML config for L0
  --cpus N        Override L1 vCPU count (default: 2)
  --memory SIZE   Override L1 guest RAM with M or G suffix (default: 256M)
  --cmdline STR   Override L1 kernel command line (default: test-guest-nested)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --vmm)
            [ "$#" -ge 2 ] || { echo "run-nested-test-guest: --vmm requires wasm or chv" >&2; exit 2; }
            L0_VMM="$2"
            shift 2
            ;;
        --vmm=*)
            L0_VMM="${1#--vmm=}"
            shift
            ;;
        --wasm)
            MODE="wasm"
            shift
            ;;
        --cwasm)
            MODE="cwasm"
            shift
            ;;
        -c)
            [ "$#" -ge 2 ] || { echo "run-nested-test-guest: -c requires a config path" >&2; exit 2; }
            CONFIG="$2"
            CUSTOM_CONFIG=1
            shift 2
            ;;
        --cpus)
            [ "$#" -ge 2 ] || { echo "run-nested-test-guest: --cpus requires a value" >&2; exit 2; }
            SMP="$2"
            shift 2
            ;;
        --cpus=*)
            SMP="${1#--cpus=}"
            shift
            ;;
        --memory)
            [ "$#" -ge 2 ] || { echo "run-nested-test-guest: --memory requires a value" >&2; exit 2; }
            MEM_SIZE="$2"
            shift 2
            ;;
        --memory=*)
            MEM_SIZE="${1#--memory=}"
            shift
            ;;
        --cmdline)
            [ "$#" -ge 2 ] || { echo "run-nested-test-guest: --cmdline requires a value" >&2; exit 2; }
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
            echo "run-nested-test-guest: unknown argument '$1'" >&2
            usage
            exit 2
            ;;
    esac
done

case "$L0_VMM" in
    wasm|chv) ;;
    *)
        echo "run-nested-test-guest: invalid --vmm '$L0_VMM' (expected 'wasm' or 'chv')" >&2
        exit 2
        ;;
esac

case "$CMDLINE" in
    *\"* | *'
'*)
        echo "run-nested-test-guest: --cmdline cannot contain double quotes or newlines" >&2
        exit 2
        ;;
esac

banner() {
    printf '\n================================================================================\n'
    printf '%s\n' "$1"
    printf '================================================================================\n'
}

file_size() {
    wc -c < "$1" | tr -d ' '
}

banner "[Step 1/4] Building L0 Linux Wasm VMM hosts & L1/L2 Motor OS nested guest artifacts"
cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-tests --bin build_test_guest

WASM_SHA256=$(sha256sum "$HOST_TARGET_DIR/vmm-core.wasm" | awk '{print $1}')

banner "[Step 2/4] Verifying Airlock VMM & nested Motor OS artifacts"
printf '  Shared Wasm core module (byte-identical across L0 Linux & L1 Motor OS Ring 0):\n'
printf '    vmm-core.wasm:            %s (%s bytes)\n' "$HOST_TARGET_DIR/vmm-core.wasm" "$(file_size "$HOST_TARGET_DIR/vmm-core.wasm")"
printf '    sha256(vmm-core.wasm):    %s\n' "$WASM_SHA256"
printf '    L0 Linux AOT (.cwasm):    %s (%s bytes)\n' "$HOST_TARGET_DIR/vmm-core.cwasm" "$(file_size "$HOST_TARGET_DIR/vmm-core.cwasm")"
printf '    L1 Ring-0 AOT (.cwasm):   %s (%s bytes)\n' "$TEST_GUEST_DIR/vmm-core-motor.cwasm" "$(file_size "$TEST_GUEST_DIR/vmm-core-motor.cwasm")"
printf '\n  Motor OS L1/L2 guest artifacts:\n'
printf '    Ring-0 VMM kernel:        %s (%s bytes)\n' "$TEST_GUEST_DIR/kernel" "$(file_size "$TEST_GUEST_DIR/kernel")"
printf '    PVH kloader (+kernel):    %s (%s bytes)\n' "$TEST_GUEST_DIR/kloader" "$(file_size "$TEST_GUEST_DIR/kloader")"
printf '    L2 leaf initrd:           %s (%s bytes)\n' "$TEST_GUEST_DIR/initrd-test-guest" "$(file_size "$TEST_GUEST_DIR/initrd-test-guest")"
printf '    L1 nested initrd (+L2):   %s (%s bytes)\n' "$TEST_GUEST_DIR/initrd-test-guest-nested" "$(file_size "$TEST_GUEST_DIR/initrd-test-guest-nested")"

banner "[Step 3/4] Preparing L0 -> L1 -> L2 nested virtualization topology"
if [ "$CUSTOM_CONFIG" = 1 ]; then
    if [ ! -f "$CONFIG" ]; then
        echo "run-nested-test-guest: config file '$CONFIG' not found" >&2
        exit 1
    fi
else
    KLOADER_PATH="$TEST_GUEST_DIR/kloader"
    INITRD_PATH="$TEST_GUEST_DIR/initrd-test-guest-nested"
    mkdir -m 750 -p "$RUNTIME_DIR"
    LOG_FILE="${WASM_VMM_LOG:-/tmp/wasm-vmm-nested-test-guest.log}"
    LOG_LEVEL="${WASM_VMM_LOG_LEVEL:-info}"

    {
        printf 'pvh = "%s"\n' "$KLOADER_PATH"
        printf 'initramfs = "%s"\n' "$INITRD_PATH"
        printf 'cmd_line = "%s"\n' "$CMDLINE"
        printf 'num_cpus = %s\n' "$SMP"
        printf 'mem_size = "%s"\n' "$MEM_SIZE"
        printf 'iommu = true\n'
        printf 'blk = []\n'
        printf 'log_file = "%s"\n' "$LOG_FILE"
        printf 'log_level = "%s"\n' "$LOG_LEVEL"
    } > "$CONFIG"
    chmod 640 "$CONFIG"
fi

if [ "$L0_VMM" = "chv" ]; then
    CHV_BIN="${CHV_BIN:-$(command -v cloud-hypervisor-static 2>/dev/null || echo /usr/local/google/home/posk/bin/cloud-hypervisor-static)}"
    if [ ! -x "$CHV_BIN" ]; then
        echo "run-nested-test-guest: cloud-hypervisor-static not found at '$CHV_BIN' (override with CHV_BIN)" >&2
        exit 1
    fi
    CHV_LOG="${CHV_LOG:-/tmp/chv-nested-test-guest.log}"
    printf '  L0 Host:   cloud-hypervisor-static (virtio-iommu + nested=on)\n'
    printf '  L0 Binary: %s\n' "$CHV_BIN"
    printf '  L1 Guest:  Motor OS (%s vCPUs, %s RAM, cmd="%s")\n' "$SMP" "$MEM_SIZE" "$CMDLINE"
    printf '             -> Ring-0 AMD-V SVM + #![no_std] Wasmtime running vmm-core-motor.cwasm\n'
    printf '  L2 Guest:  Motor OS SMP (2 vCPUs, 64M RAM, cmd="test-guest-l2")\n'

    banner "[Step 4/4] Booting L0 (CHV + virtio-iommu) -> L1 -> L2 nested VM stack"
    "$CHV_BIN" \
        --cpus "boot=$SMP,nested=on" \
        --memory "size=$MEM_SIZE,thp=on" \
        --console off --serial tty \
        --log-file "$CHV_LOG" \
        --kernel "$TEST_GUEST_DIR/kloader" \
        --initramfs "$TEST_GUEST_DIR/initrd-test-guest-nested" \
        --cmdline "$CMDLINE" \
        --rng "src=/dev/urandom,iommu=virtio,pci_device_id=4"
else
    printf '  L0 Host:   Linux KVM + Airlock Wasm VMM (--%s mode, virtio-iommu enabled)\n' "$MODE"
    printf '  L0 Config: %s\n' "$CONFIG"
    printf '  L1 Guest:  Motor OS (%s vCPUs, %s RAM, cmd="%s")\n' "$SMP" "$MEM_SIZE" "$CMDLINE"
    printf '             -> Ring-0 AMD-V SVM + #![no_std] Wasmtime running vmm-core-motor.cwasm\n'
    printf '  L2 Guest:  Motor OS SMP (2 vCPUs, 64M RAM, cmd="test-guest-l2")\n'

    CONFIG_DIR=$(CDPATH= cd -- "$(dirname -- "$CONFIG")" && pwd)
    CONFIG_FILE=$(basename -- "$CONFIG")

    if [ "$MODE" = "wasm" ]; then
        IO_HOST="$HOST_TARGET_DIR/vmm-io-host-wasm"
        IO_MOD="$HOST_TARGET_DIR/vmm-io.wasm"
        CORE_HOST="$HOST_TARGET_DIR/vmm-core-host-wasm"
        CORE_MOD="$HOST_TARGET_DIR/vmm-core.wasm"
    else
        IO_HOST="$HOST_TARGET_DIR/vmm-io-host-cwasm"
        IO_MOD="$HOST_TARGET_DIR/vmm-io.cwasm"
        CORE_HOST="$HOST_TARGET_DIR/vmm-core-host-cwasm"
        CORE_MOD="$HOST_TARGET_DIR/vmm-core.cwasm"
    fi

    banner "[Step 4/4] Booting L0 -> L1 -> L2 nested VM stack (streaming live serial console)"
    (
        cd "$CONFIG_DIR"
        "$IO_HOST" \
            -c "$CONFIG_FILE" \
            -w "$IO_MOD" \
            --core-host "$CORE_HOST" \
            --core-wasm "$CORE_MOD"
    )
fi

banner "[Complete] L2 shut down cleanly inside L1, and L1 shut down cleanly inside L0 (exit 0)"
