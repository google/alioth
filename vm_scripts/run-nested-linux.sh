#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime/nested-linux"
MOTOR_OUT="$REPO_ROOT/target/motor"
TEST_GUEST_DIR="$REPO_ROOT/target/test-guest"
HOST_TARGET_DIR="$REPO_ROOT/target/x86_64-unknown-linux-musl/release"

MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
if [ ! -d "$MOTO_DIR" ]; then
    echo "run-nested-linux: Motor OS image directory '$MOTO_DIR' not found (override with MOTO_DIR)" >&2
    exit 1
fi
MOTO_DIR=$(CDPATH= cd -- "$MOTO_DIR" && pwd)
IMAGER="$MOTO_DIR/tools/imager"

LINUX_BLOBS_DIR="${LINUX_BLOBS_DIR:-$REPO_ROOT/../linux-blobs}"
if [ ! -d "$LINUX_BLOBS_DIR" ]; then
    echo "run-nested-linux: Linux blobs directory '$LINUX_BLOBS_DIR' not found (override with LINUX_BLOBS_DIR)" >&2
    exit 1
fi
LINUX_BLOBS_DIR=$(CDPATH= cd -- "$LINUX_BLOBS_DIR" && pwd)

MODE="cwasm"
L0_VMM="wasm"
INITRD_ONLY=0
L1_SMP="${MOTO_L1_SMP:-4}"
L1_MEM=""
L2_SMP="${LINUX_L2_SMP:-2}"
L2_MEM="${LINUX_L2_MEM:-256M}"
NO_NETWORK=0

usage() {
    cat >&2 <<EOF
Usage: $0 [--vmm wasm|chv] [--cwasm | --wasm] [--initrd] [--l1-cpus N] [--l1-memory SIZE] [--l2-cpus N] [--l2-memory SIZE] [--no-network]
  --vmm wasm|chv     Select L0 hypervisor: Linux Wasm VMM (default) or cloud-hypervisor-static (with virtio-iommu)
  --cwasm            Run precompiled Wasm (.cwasm) in both L0 and L1 (default)
  --wasm             Run Cranelift JIT (.wasm) in both L0 and L1 Ring 3
  --initrd           Boot BusyBox initramfs.cpio.gz instead of full Alpine Linux disk
  --l1-cpus N        L1 Motor OS vCPU count (default: 4)
  --l1-memory SIZE   L1 Motor OS RAM with M or G suffix (default: 1536M for Alpine, 1024M for --initrd)
  --l2-cpus N        L2 nested Linux vCPU count (default: 2)
  --l2-memory SIZE   L2 nested Linux RAM with M or G suffix (default: 256M)
  --no-network       Omit L0 moto-tap device (L1<->L2 IpDevice 192.168.8.0/24 still works!)
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --vmm)
            [ "$#" -ge 2 ] || { usage; exit 2; }
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
        --initrd)
            INITRD_ONLY=1
            shift
            ;;
        --l1-cpus)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            L1_SMP="$2"
            shift 2
            ;;
        --l1-memory)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            L1_MEM="$2"
            shift 2
            ;;
        --l2-cpus)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            L2_SMP="$2"
            shift 2
            ;;
        --l2-memory)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            L2_MEM="$2"
            shift 2
            ;;
        --no-network)
            NO_NETWORK=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "run-nested-linux: unknown argument '$1'" >&2
            usage
            exit 2
            ;;
    esac
done

case "$L0_VMM" in
    wasm|chv) ;;
    *)
        echo "run-nested-linux: invalid --vmm '$L0_VMM' (expected 'wasm' or 'chv')" >&2
        exit 2
        ;;
esac

if [ -z "$L1_MEM" ]; then
    if [ "$INITRD_ONLY" = 1 ]; then
        L1_MEM="${MOTO_L1_MEM:-1024M}"
    else
        L1_MEM="${MOTO_L1_MEM:-1536M}"
    fi
fi

banner() {
    printf '\n================================================================================\n'
    printf '%s\n' "$1"
    printf '================================================================================\n'
}

banner "[Step 1/4] Building L0 Linux hosts, L1 Ring-0 kernel, and L1 Ring-3 motor-io-host"
cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-tests --bin build_test_guest
MOTO_VMM_OUT="$MOTOR_OUT" "$REPO_ROOT/tests/motor-io-host/build.sh"

banner "[Step 2/4] Staging scratch L1 Motor OS & L2 Linux artifacts via imager"
rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR"

L1_RAW="$RUNTIME_DIR/l1-motor-os.raw"
if [ "$INITRD_ONLY" = 1 ]; then
    qemu-img convert -f qcow2 -O raw "$MOTO_DIR/motor-os.qcow2" "$L1_RAW"
else
    "$IMAGER" resize -i "$MOTO_DIR/motor-os.qcow2" -o "$L1_RAW" --size 2G
fi

cat > "$RUNTIME_DIR/l1-sys-init.cfg" <<EOF
tty:/system/services/sys-tty
strobe:/system/services/strobe
svc:328:/system/services/dns-resolver
svc:17404:/system/services/russhd /system/cfg/sshd.toml
EOF
"$IMAGER" put "$L1_RAW" "$RUNTIME_DIR/l1-sys-init.cfg" /system/cfg/sys-init.cfg
"$IMAGER" mkdir --mode rwxrwxr-x "$L1_RAW" /user/vm

if [ "$INITRD_ONLY" = 1 ]; then
    cat > "$RUNTIME_DIR/vm-l2.toml" <<EOF
log_file = "/user/tmp/vmm-l2.log"
log_level = "info"
kernel = "/user/vm/bzImage"
initramfs = "/user/vm/initramfs.cpio.gz"
cmd_line = "console=ttyS0 rdinit=/init"
num_cpus = $L2_SMP
mem_size = "$L2_MEM"
EOF
    "$IMAGER" put "$L1_RAW" "$LINUX_BLOBS_DIR/initramfs.cpio.gz" /user/vm/initramfs.cpio.gz
else
    L2_ALPINE="$RUNTIME_DIR/alpine.raw"
    cp --sparse=always "$LINUX_BLOBS_DIR/alpine.raw" "$L2_ALPINE"
    ssh-keygen -y -f "$MOTO_DIR/test.key" > "$RUNTIME_DIR/authorized_keys"
    python3 - "$L2_ALPINE" "$RUNTIME_DIR/authorized_keys" "$RUNTIME_DIR/part3.ext4" <<'PY'
import os, subprocess, sys
raw_path, ak_path, part3_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(raw_path, "rb") as f:
    f.seek(0x1BE + 2 * 16 + 8)
    start_sec = int.from_bytes(f.read(4), "little")
    num_sec = int.from_bytes(f.read(4), "little")
off, size = start_sec * 512, num_sec * 512
with open(raw_path, "rb") as src, open(part3_path, "wb") as dst:
    os.copy_file_range(src.fileno(), dst.fileno(), size, offset_src=off, offset_dst=0)
subprocess.run(["/usr/sbin/e2fsck", "-fy", part3_path], capture_output=True)
cmds = "\n".join([
    "mkdir /root/.ssh",
    "set_inode_field /root/.ssh mode 040700",
    "set_inode_field /root/.ssh uid 0",
    "set_inode_field /root/.ssh gid 0",
    f"write {ak_path} /root/.ssh/authorized_keys",
    "set_inode_field /root/.ssh/authorized_keys mode 0100600",
    "set_inode_field /root/.ssh/authorized_keys uid 0",
    "set_inode_field /root/.ssh/authorized_keys gid 0",
]) + "\n"
subprocess.run(["/usr/sbin/debugfs", "-w", part3_path], input=cmds, text=True, check=True, capture_output=True)
subprocess.run(["/usr/sbin/e2fsck", "-fy", part3_path], capture_output=True)
with open(part3_path, "rb") as src, open(raw_path, "r+b") as dst:
    os.copy_file_range(src.fileno(), dst.fileno(), size, offset_src=0, offset_dst=off)
os.remove(part3_path)
PY

    cat > "$RUNTIME_DIR/vm-l2.toml" <<EOF
log_file = "/user/tmp/vmm-l2.log"
log_level = "info"
kernel = "/user/vm/bzImage"
cmd_line = "console=ttyS0 root=/dev/vda3 rw"
num_cpus = $L2_SMP
mem_size = "$L2_MEM"
blk = ["/user/vm/alpine.raw"]

[net.dev0]
mac = "a4:a1:c2:00:00:02"
mtu = 1500
if_name = "vmm0:192.168.8.1/24"
EOF
    "$IMAGER" put --mode rw-rw-r-- "$L1_RAW" "$L2_ALPINE" /user/vm/alpine.raw
    rm -f "$L2_ALPINE"
fi

if [ "$MODE" = "wasm" ]; then
    L1_LAUNCH_CMD="MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-wasm -c /user/vm/vm-l2.toml -w /user/vm/vmm-io.wasm --core-wasm /user/vm/vmm-core.cwasm"
else
    L1_LAUNCH_CMD="MOTOR_OS_CAPS=0x434c /user/vm/motor-io-host-cwasm -c /user/vm/vm-l2.toml -w /user/vm/vmm-io.cwasm --core-wasm /user/vm/vmm-core.cwasm"
fi

cat > "$RUNTIME_DIR/run-l2.sh" <<EOF
#!/system/bin/rush
$L1_LAUNCH_CMD
EOF
chmod +x "$RUNTIME_DIR/run-l2.sh"

"$IMAGER" put "$L1_RAW" "$MOTOR_OUT/motor-io-host-cwasm" /user/vm/motor-io-host-cwasm
"$IMAGER" put "$L1_RAW" "$MOTOR_OUT/motor-io-host-wasm" /user/vm/motor-io-host-wasm
"$IMAGER" put "$L1_RAW" "$MOTOR_OUT/vmm-core.cwasm" /user/vm/vmm-core.cwasm
"$IMAGER" put "$L1_RAW" "$MOTOR_OUT/vmm-io.cwasm" /user/vm/vmm-io.cwasm
"$IMAGER" put "$L1_RAW" "$MOTOR_OUT/vmm-io.wasm" /user/vm/vmm-io.wasm
"$IMAGER" put "$L1_RAW" "$LINUX_BLOBS_DIR/bzImage" /user/vm/bzImage
"$IMAGER" put "$L1_RAW" "$RUNTIME_DIR/vm-l2.toml" /user/vm/vm-l2.toml
"$IMAGER" put "$L1_RAW" "$RUNTIME_DIR/run-l2.sh" /user/vm/run-l2.sh

L0_CONFIG="$RUNTIME_DIR/vm-l0.toml"
cat > "$L0_CONFIG" <<EOF
log_file = "$RUNTIME_DIR/vmm-l0.log"
log_level = "info"
pvh = "$TEST_GUEST_DIR/kloader"
initramfs = "$MOTO_DIR/initrd"
cmd_line = "system-tty"
num_cpus = $L1_SMP
mem_size = "$L1_MEM"
iommu = true
blk = ["$L1_RAW"]
EOF

if [ "$NO_NETWORK" = 0 ] && [ "$INITRD_ONLY" = 0 ]; then
    cat >> "$L0_CONFIG" <<EOF

[net.dev0]
mac = "a4:a1:c2:00:00:01"
mtu = 1500
if_name = "moto-tap"
EOF
fi

if [ "$L0_VMM" = "chv" ]; then
    L0_EXIT_HINT="exit       -> Type 'exit' in L1 rush to shut down L0 cloud-hypervisor-static"
else
    L0_EXIT_HINT="Ctrl-a q   -> Shut down L0 Linux Wasm VMM and return to host shell"
fi

banner "[Step 3/4] Nested Linux inside Motor OS Quick Reference"
cat <<EOF
  1. At L1's 'motor-os:/user$' prompt, boot L2 Linux ($MODE mode):
       /user/vm/run-l2.sh
     (runs: $L1_LAUNCH_CMD)

  2. Escape / shutdown keys:
       Ctrl-b q   -> Shut down L2 MotorIoHost and return to L1 rush
       $L0_EXIT_HINT
EOF
if [ "$INITRD_ONLY" = 0 ]; then
    cat <<EOF

  3. From the Linux host, SSH into L1 or nested L2 Alpine OpenSSH:
       $SCRIPT_DIR/ssh-into-motor-os.sh           # -> L1 russhd (motor@192.168.4.2:2222)
       $SCRIPT_DIR/ssh-into-nested-linux.sh       # -> L2 Alpine (root@192.168.8.2:22 via L1)
EOF
fi

if [ "$L0_VMM" = "chv" ]; then
    CHV_BIN="${CHV_BIN:-$(command -v cloud-hypervisor-static 2>/dev/null || echo /usr/local/google/home/posk/bin/cloud-hypervisor-static)}"
    if [ ! -x "$CHV_BIN" ]; then
        echo "run-nested-linux: cloud-hypervisor-static not found at '$CHV_BIN' (override with CHV_BIN)" >&2
        exit 1
    fi
    banner "[Step 4/4] Launching L0 cloud-hypervisor-static (virtio-iommu) -> L1 Motor OS ($MODE)"
    set -- \
        --cpus "boot=$L1_SMP,nested=on" \
        --memory "size=$L1_MEM,thp=on" \
        --console off --serial tty \
        --log-file "$RUNTIME_DIR/chv-l0.log" \
        --kernel "$TEST_GUEST_DIR/kloader" \
        --initramfs "$MOTO_DIR/initrd" \
        --cmdline "system-tty" \
        --rng "src=/dev/urandom,iommu=virtio,pci_device_id=4" \
        --disk "path=$L1_RAW,image_type=raw,iommu=virtio,pci_device_id=2"
    if [ "$NO_NETWORK" = 0 ] && [ "$INITRD_ONLY" = 0 ]; then
        set -- "$@" --net "tap=moto-tap,mac=a4:a1:c2:00:00:01,iommu=virtio,pci_device_id=3"
    fi
    exec "$CHV_BIN" "$@"
else
    banner "[Step 4/4] Launching L0 Linux Wasm VMM (virtio-iommu) -> L1 Motor OS ($MODE)"
    if [ "$MODE" = "wasm" ]; then
        exec "$HOST_TARGET_DIR/vmm-io-host-wasm" \
            -c "$L0_CONFIG" \
            -w "$HOST_TARGET_DIR/vmm-io.wasm" \
            --core-host "$HOST_TARGET_DIR/vmm-core-host-wasm" \
            --core-wasm "$HOST_TARGET_DIR/vmm-core.wasm"
    else
        exec "$HOST_TARGET_DIR/vmm-io-host-cwasm" \
            -c "$L0_CONFIG" \
            -w "$HOST_TARGET_DIR/vmm-io.cwasm" \
            --core-host "$HOST_TARGET_DIR/vmm-core-host-cwasm" \
            --core-wasm "$HOST_TARGET_DIR/vmm-core.cwasm"
    fi
fi
