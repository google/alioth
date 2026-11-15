#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime/passthrough-net-linux"
MOTOR_OUT="$REPO_ROOT/target/motor"
TEST_GUEST_DIR="$REPO_ROOT/target/test-guest"
HOST_TARGET_DIR="$REPO_ROOT/target/x86_64-unknown-linux-musl/release"

MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
if [ ! -d "$MOTO_DIR" ]; then
    echo "run-passthrough-net-linux: Motor OS image directory '$MOTO_DIR' not found (override with MOTO_DIR)" >&2
    exit 1
fi
MOTO_DIR=$(CDPATH= cd -- "$MOTO_DIR" && pwd)
IMAGER="$MOTO_DIR/tools/imager"

LINUX_BLOBS_DIR="${LINUX_BLOBS_DIR:-$REPO_ROOT/../linux-blobs}"
if [ ! -d "$LINUX_BLOBS_DIR" ]; then
    echo "run-passthrough-net-linux: Linux blobs directory '$LINUX_BLOBS_DIR' not found (override with LINUX_BLOBS_DIR)" >&2
    exit 1
fi
LINUX_BLOBS_DIR=$(CDPATH= cd -- "$LINUX_BLOBS_DIR" && pwd)

MODE="cwasm"
L0_VMM="wasm"
L1_SMP="${MOTO_L1_SMP:-4}"
L1_MEM="${MOTO_L1_MEM:-1536M}"
L2_SMP="${LINUX_L2_SMP:-2}"
L2_MEM="${LINUX_L2_MEM:-256M}"
TAP_IF="${PUFF_TAP_IF:-puff-tap}"

usage() {
    cat >&2 <<EOF
Usage: $0 [--vmm wasm|chv] [--cwasm | --wasm] [--l1-cpus N] [--l1-memory SIZE] [--l2-cpus N] [--l2-memory SIZE] [--tap IFACE]
  --vmm wasm|chv     Select L0 hypervisor: Linux Wasm VMM (default) or cloud-hypervisor-static (with virtio-iommu)
  --cwasm            Run precompiled Wasm (.cwasm) in both L0 and L1 (default)
  --wasm             Run Cranelift JIT (.wasm) in both L0 and L1 Ring 3
  --l1-cpus N        L1 Motor OS vCPU count (default: 4)
  --l1-memory SIZE   L1 Motor OS RAM with M or G suffix (default: 1536M)
  --l2-cpus N        L2 nested Alpine Linux vCPU count (default: 2)
  --l2-memory SIZE   L2 nested Alpine Linux RAM with M or G suffix (default: 256M)
  --tap IFACE        Host TAP interface passed through to L2 at 00:03.0 (default: puff-tap)
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
        --tap)
            [ "$#" -ge 2 ] || { usage; exit 2; }
            TAP_IF="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "run-passthrough-net-linux: unknown argument '$1'" >&2
            usage
            exit 2
            ;;
    esac
done

case "$L0_VMM" in
    wasm|chv) ;;
    *)
        echo "run-passthrough-net-linux: invalid --vmm '$L0_VMM' (expected 'wasm' or 'chv')" >&2
        exit 2
        ;;
esac

if [ ! -e "/sys/class/net/$TAP_IF" ]; then
    echo "run-passthrough-net-linux: host TAP '$TAP_IF' not found (run ./vm_scripts/create-tap.sh)" >&2
    exit 1
fi

banner() {
    printf '\n================================================================================\n'
    printf '%s\n' "$1"
    printf '================================================================================\n'
}

banner "[Step 1/4] Building L0 Linux hosts, L1 Ring-0 kernel, and L1 Ring-3 motor-io-host"
cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-tests --bin build_test_guest
MOTO_VMM_OUT="$MOTOR_OUT" "$REPO_ROOT/tests/motor-io-host/build.sh"

banner "[Step 2/4] Staging Topology A (virtio-net 00:03.0 passthrough) L1 & L2 artifacts"
rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR"

L1_RAW="$RUNTIME_DIR/l1-motor-os.raw"
"$IMAGER" resize -i "$MOTO_DIR/motor-os.qcow2" -o "$L1_RAW" --size 2G

cat > "$RUNTIME_DIR/l1-sys-init.cfg" <<EOF
tty:/system/services/sys-tty
strobe:/system/services/strobe
EOF
"$IMAGER" put "$L1_RAW" "$RUNTIME_DIR/l1-sys-init.cfg" /system/cfg/sys-init.cfg
"$IMAGER" mkdir --mode rwxrwxr-x "$L1_RAW" /user/vm

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
pci = ["00:03.0"]
blk = ["/user/vm/alpine.raw"]
EOF

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
"$IMAGER" put --mode rw-rw-r-- "$L1_RAW" "$L2_ALPINE" /user/vm/alpine.raw
rm -f "$L2_ALPINE"
"$IMAGER" put "$L1_RAW" "$RUNTIME_DIR/vm-l2.toml" /user/vm/vm-l2.toml
"$IMAGER" put "$L1_RAW" "$RUNTIME_DIR/run-l2.sh" /user/vm/run-l2.sh

L1_CMDLINE="system-tty pci_passthrough=00:03.0"
L0_CONFIG="$RUNTIME_DIR/vm-l0.toml"
cat > "$L0_CONFIG" <<EOF
log_file = "$RUNTIME_DIR/vmm-l0.log"
log_level = "info"
pvh = "$TEST_GUEST_DIR/kloader"
initramfs = "$MOTO_DIR/initrd"
cmd_line = "$L1_CMDLINE"
num_cpus = $L1_SMP
mem_size = "$L1_MEM"
iommu = true
blk = ["$L1_RAW"]

[net.dev0]
mac = "a4:a1:c2:00:00:01"
mtu = 1500
if_name = "$TAP_IF"
EOF

if [ "$L0_VMM" = "chv" ]; then
    L0_EXIT_HINT="exit       -> Type 'exit' in L1 rush to shut down L0 cloud-hypervisor-static"
else
    L0_EXIT_HINT="Ctrl-a q   -> Shut down L0 Linux Wasm VMM and return to host shell"
fi

banner "[Step 3/4] Topology A: virtio-net (00:03.0) PCI Passthrough Quick Reference"
cat <<EOF
  * L1 Motor OS runs with 'pci_passthrough=00:03.0' behind virtio-iommu:
    L1 has ZERO network interfaces; L2 gets L0's '$TAP_IF' (192.168.8.0/24) directly!

  1. At L1's 'motor-os:/user$' prompt, boot L2 Alpine Linux ($MODE mode):
       /user/vm/run-l2.sh
     (runs: $L1_LAUNCH_CMD)

  2. From the Linux host, SSH DIRECTLY into L2 Alpine (no L1 jump host!):
       $SCRIPT_DIR/ssh-into-alpine.sh

  3. Escape / shutdown keys:
       Ctrl-b q   -> Shut down L2 MotorIoHost and return to L1 rush
       $L0_EXIT_HINT
EOF

if [ "$L0_VMM" = "chv" ]; then
    CHV_BIN="${CHV_BIN:-$(command -v cloud-hypervisor-static 2>/dev/null || echo /usr/local/google/home/posk/bin/cloud-hypervisor-static)}"
    if [ ! -x "$CHV_BIN" ]; then
        echo "run-passthrough-net-linux: cloud-hypervisor-static not found at '$CHV_BIN' (override with CHV_BIN)" >&2
        exit 1
    fi
    banner "[Step 4/4] Launching L0 cloud-hypervisor-static (virtio-iommu) -> L1 Motor OS ($MODE)"
    exec "$CHV_BIN" \
        --cpus "boot=$L1_SMP,nested=on" \
        --memory "size=$L1_MEM,thp=on" \
        --console off --serial tty \
        --log-file "$RUNTIME_DIR/chv-l0.log" \
        --kernel "$TEST_GUEST_DIR/kloader" \
        --initramfs "$MOTO_DIR/initrd" \
        --cmdline "$L1_CMDLINE" \
        --rng "src=/dev/urandom,iommu=virtio,pci_device_id=4" \
        --disk "path=$L1_RAW,image_type=raw,iommu=virtio,pci_device_id=2" \
        --net "tap=$TAP_IF,mac=a4:a1:c2:00:00:01,iommu=virtio,pci_device_id=3"
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
