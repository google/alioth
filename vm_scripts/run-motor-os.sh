#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime"

# Motor OS builds inside a `$MOTORH` workspace directory (`../motor-dev`), placing the
# main checkout at `../motor-dev/motor-os` and packaged VM artifacts (`kloader`, `initrd`,
# `motor-os.qcow2`, `vm-options.sh`) under `../motor-dev/motor-os/vm_images/release`.
# See https://github.com/moturus/motor-os/blob/main/docs/build.md for the setup & build flow.
MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
if [ ! -d "$MOTO_DIR" ]; then
    echo "run-motor-os: Motor OS image directory '$MOTO_DIR' not found (override with MOTO_DIR; see https://github.com/moturus/motor-os/blob/main/docs/build.md)" >&2
    exit 1
fi
MOTO_DIR=$(CDPATH= cd -- "$MOTO_DIR" && pwd)

if [ ! -f "$MOTO_DIR/vm-options.sh" ]; then
    echo "run-motor-os: '$MOTO_DIR/vm-options.sh' not found" >&2
    exit 1
fi

MODE="cwasm"
CONFIG="$RUNTIME_DIR/vm-motor-os.toml"
CUSTOM_CONFIG=0
SMP="${MOTO_SMP:-4}"
MEMORY_MIB="${MOTO_MEMORY_MIB:-1024}"
CMDLINE=""
CMDLINE_SET=0

. "$MOTO_DIR/vm-options.sh"
VM_DISKS=""
VM_ROOT_READ_ONLY=off
VM_SYSTEM_TTY=0
VM_NO_NETWORK=0

usage() {
    cat >&2 <<EOF
Usage: $0 [--cwasm | --wasm] [-c path/to/vm.toml] [--cpus N] [--memory SIZE] [--system-tty] [--cmdline STR] [--no-network] [--extra-disk FILE]...
  --cwasm           Run vmm-{io,core}-host-cwasm + vmm-{io,core}.cwasm (default)
  --wasm            Run vmm-{io,core}-host-wasm + vmm-{io,core}.wasm
  -c FILE           Use an existing custom wasm-vmm TOML config
  --cpus N          Override vCPU count (or set MOTO_SMP, default: 4)
  --memory SIZE     Override guest RAM with M or G suffix (or set MOTO_MEMORY_MIB, default: 1024M)
  --system-tty      Append 'system-tty' to the kernel command line
  --cmdline STR     Pass kernel command line to Motor OS
  --no-network      Omit the virtio-net device (moto-tap)
  --extra-disk FILE Attach an additional disk from \$MOTO_DIR (.img/.raw or .qcow2)

Environment variables:
  MOTO_ROOT               Motor OS repository root (default: ../motor-dev/motor-os)
  MOTO_DIR                Motor OS release directory (default: $MOTO_DIR)
  MOTO_IMAGE              Root disk filename in MOTO_DIR (default: motor-os.qcow2; converted to .raw in $RUNTIME_DIR)
  MOTO_SMP                vCPU count (default: 4)
  MOTO_MEMORY_MIB         Guest RAM in MiB (default: 1024)
  MOTO_QEMU_LOCK          Host lock file shared with other Motor OS launchers
  MOTO_WASM_VMM_LOG       Log file path (default: /tmp/wasm-vmm-motor-os.log)
  MOTO_WASM_VMM_LOG_LEVEL Log level (default: info)
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
            [ "$#" -ge 2 ] || { echo "run-motor-os: -c requires a config path" >&2; exit 2; }
            CONFIG="$2"
            CUSTOM_CONFIG=1
            shift 2
            ;;
        --cmdline)
            [ "$#" -ge 2 ] || { echo "run-motor-os: --cmdline requires a value" >&2; exit 2; }
            CMDLINE="$2"
            CMDLINE_SET=1
            shift 2
            ;;
        --cmdline=*)
            CMDLINE="${1#--cmdline=}"
            CMDLINE_SET=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            if vm_option "$@"; then
                shift "$VM_OPTION_SHIFT"
            else
                echo "run-motor-os: unknown argument '$1'" >&2
                usage
                exit 2
            fi
            ;;
    esac
done

if [ "$VM_SYSTEM_TTY" = 1 ]; then
    CMDLINE="${CMDLINE:+$CMDLINE }system-tty"
    CMDLINE_SET=1
fi

case "$CMDLINE" in
    *\"* | *'
'*)
        echo "run-motor-os: --cmdline cannot contain double quotes or newlines" >&2
        exit 2
        ;;
esac

case "$SMP" in
    "" | *[!0-9]* | 0*)
        echo "run-motor-os: MOTO_SMP must be a positive integer" >&2
        exit 2
        ;;
esac

case "$MEMORY_MIB" in
    "" | *[!0-9]* | 0*)
        echo "run-motor-os: MOTO_MEMORY_MIB must be a positive integer" >&2
        exit 2
        ;;
esac

if [ "$VM_ROOT_READ_ONLY" = "on" ]; then
    echo "run-motor-os: --root-read-only is unsupported by wasm-vmm" >&2
    exit 2
fi

for DISK in $VM_DISKS; do
    if [ "${DISK#*:}" = "on" ]; then
        echo "run-motor-os: --extra-disk-ro is unsupported by wasm-vmm" >&2
        exit 2
    fi
done

# Share the same host-wide lock as run-chv.sh / run-qemu.sh / run-fc.sh because
# all Motor OS launchers share moto-tap (192.168.4.2) and the guest disk image.
VM_LOCK="${MOTO_QEMU_LOCK:-/tmp/motor-os-qemu.$(id -u).lock}"
exec 9>"$VM_LOCK"
if ! flock -n 9; then
    echo "run-motor-os: another Motor OS VM owns $VM_LOCK" >&2
    exit 1
fi

mkdir -m 750 -p "$RUNTIME_DIR"

resolve_raw_disk() {
    DISK_FILE="$1"
    case "$DISK_FILE" in
        "" | *[!A-Za-z0-9._-]*)
            echo "run-motor-os: invalid image filename '$DISK_FILE'" >&2
            exit 2
            ;;
    esac
    SRC_DISK="$MOTO_DIR/$DISK_FILE"
    if [ ! -f "$SRC_DISK" ]; then
        echo "run-motor-os: disk image '$SRC_DISK' not found" >&2
        exit 1
    fi
    case "$DISK_FILE" in
        *.img | *.raw)
            RESOLVED_DISK="$SRC_DISK"
            ;;
        *.qcow2)
            RAW_DISK="$RUNTIME_DIR/${DISK_FILE%.qcow2}.raw"
            if [ ! -f "$RAW_DISK" ] || [ "$SRC_DISK" -nt "$RAW_DISK" ]; then
                if ! command -v qemu-img >/dev/null 2>&1; then
                    echo "run-motor-os: qemu-img is required to convert '$DISK_FILE' to raw format" >&2
                    exit 1
                fi
                echo "Converting $SRC_DISK -> $RAW_DISK..." >&2
                TMP_DISK="$RAW_DISK.tmp.$$"
                trap 'rm -f "$TMP_DISK"' EXIT INT TERM
                qemu-img convert -f qcow2 -O raw "$SRC_DISK" "$TMP_DISK"
                chmod 640 "$TMP_DISK"
                mv -f "$TMP_DISK" "$RAW_DISK"
                trap - EXIT INT TERM
            fi
            RESOLVED_DISK="$RAW_DISK"
            ;;
        *)
            echo "run-motor-os: unsupported image filename '$DISK_FILE'" >&2
            exit 2
            ;;
    esac
}

if [ "$CUSTOM_CONFIG" = 1 ]; then
    if [ ! -f "$CONFIG" ]; then
        echo "run-motor-os: config file '$CONFIG' not found" >&2
        exit 1
    fi
else
    for req in kloader initrd; do
        if [ ! -f "$MOTO_DIR/$req" ]; then
            echo "run-motor-os: '$MOTO_DIR/$req' not found" >&2
            exit 1
        fi
    done

    if [ "$VM_NO_NETWORK" != 1 ] && [ ! -d /sys/class/net/moto-tap ]; then
        echo "run-motor-os: tap device 'moto-tap' not found; run '$MOTO_DIR/create-tap.sh' or pass --no-network" >&2
        exit 1
    fi

    IMAGE="${MOTO_IMAGE:-motor-os.qcow2}"
    resolve_raw_disk "$IMAGE"
    BLK_LIST="\"$RESOLVED_DISK\""

    for DISK in $VM_DISKS; do
        DISK_NAME="${DISK%:*}"
        resolve_raw_disk "$DISK_NAME"
        BLK_LIST="$BLK_LIST, \"$RESOLVED_DISK\""
    done

    LOG_FILE="${MOTO_WASM_VMM_LOG:-/tmp/wasm-vmm-motor-os.log}"
    LOG_LEVEL="${MOTO_WASM_VMM_LOG_LEVEL:-info}"

    {
        printf 'pvh = "%s/kloader"\n' "$MOTO_DIR"
        printf 'initramfs = "%s/initrd"\n' "$MOTO_DIR"
        if [ "$CMDLINE_SET" = 1 ]; then
            printf 'cmd_line = "%s"\n' "$CMDLINE"
        fi
        printf 'num_cpus = %s\n' "$SMP"
        printf 'mem_size = "%sM"\n' "$MEMORY_MIB"
        printf 'blk = [%s]\n' "$BLK_LIST"
        printf 'log_file = "%s"\n' "$LOG_FILE"
        printf 'log_level = "%s"\n' "$LOG_LEVEL"
        if [ "$VM_NO_NETWORK" != 1 ]; then
            printf '\n[net.dev0]\n'
            printf 'mac = "a4:a1:c2:00:00:01"\n'
            printf 'mtu = 1500\n'
            printf 'if_name = "moto-tap"\n'
        fi
    } > "$CONFIG"
    chmod 640 "$CONFIG"
fi

exec "$SCRIPT_DIR/run-vm.sh" "--$MODE" -c "$CONFIG"
