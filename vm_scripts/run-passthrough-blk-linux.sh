#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime/passthrough-blk-linux"
TEST_GUEST_DIR="$REPO_ROOT/target/test-guest"
HOST_TARGET_DIR="$REPO_ROOT/target/x86_64-unknown-linux-musl/release"

MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
if [ ! -d "$MOTO_DIR" ]; then
    echo "run-passthrough-blk-linux: Motor OS image directory '$MOTO_DIR' not found (override with MOTO_DIR)" >&2
    exit 1
fi
MOTO_DIR=$(CDPATH= cd -- "$MOTO_DIR" && pwd)

LINUX_BLOBS_DIR="${LINUX_BLOBS_DIR:-$REPO_ROOT/../linux-blobs}"
if [ ! -d "$LINUX_BLOBS_DIR" ]; then
    echo "run-passthrough-blk-linux: Linux blobs directory '$LINUX_BLOBS_DIR' not found (override with LINUX_BLOBS_DIR)" >&2
    exit 1
fi
LINUX_BLOBS_DIR=$(CDPATH= cd -- "$LINUX_BLOBS_DIR" && pwd)

MODE="cwasm"
L0_VMM="wasm"
L1_SMP="${MOTO_L1_SMP:-4}"
L1_MEM="${MOTO_L1_MEM:-768M}"
L2_SMP="${LINUX_L2_SMP:-2}"
L2_MEM="${LINUX_L2_MEM:-256M}"
NO_NETWORK=0
TAP_IF="${PUFF_TAP_IF:-puff-tap}"

usage() {
    cat >&2 <<EOF
Usage: $0 [--vmm wasm|chv] [--cwasm | --wasm] [--l1-cpus N] [--l1-memory SIZE] [--l2-cpus N] [--l2-memory SIZE] [--tap IFACE] [--no-network]
  --vmm wasm|chv     Select L0 hypervisor: Linux Wasm VMM (default) or cloud-hypervisor-static (with virtio-iommu)
  --cwasm            Run precompiled Wasm (.cwasm) in L0 Wasm VMM (default; L1 Ring 0 always runs vmm-core-motor.cwasm)
  --wasm             Run Cranelift JIT (.wasm) in L0 Wasm VMM
  --l1-cpus N        L1 initrd-only Motor OS vCPU count (default: 4)
  --l1-memory SIZE   L1 initrd-only Motor OS RAM with M or G suffix (default: 768M)
  --l2-cpus N        L2 nested Alpine Linux vCPU count (default: 2)
  --l2-memory SIZE   L2 nested Alpine Linux RAM with M or G suffix (default: 256M)
  --tap IFACE        Host TAP interface passed through to L2 at 00:03.0 (default: puff-tap)
  --no-network       Pass through only virtio-blk (00:02.0), omitting 00:03.0
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
        --no-network)
            NO_NETWORK=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "run-passthrough-blk-linux: unknown argument '$1'" >&2
            usage
            exit 2
            ;;
    esac
done

case "$L0_VMM" in
    wasm|chv) ;;
    *)
        echo "run-passthrough-blk-linux: invalid --vmm '$L0_VMM' (expected 'wasm' or 'chv')" >&2
        exit 2
        ;;
esac

if [ "$NO_NETWORK" = 0 ] && [ ! -e "/sys/class/net/$TAP_IF" ]; then
    echo "run-passthrough-blk-linux: host TAP '$TAP_IF' not found (run ./vm_scripts/create-tap.sh or pass --no-network)" >&2
    exit 1
fi

banner() {
    printf '\n================================================================================\n'
    printf '%s\n' "$1"
    printf '================================================================================\n'
}

banner "[Step 1/4] Building L0 Linux hosts and L1 initrd-only Ring-0 VMM artifacts"
cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-tests --bin build_test_guest

banner "[Step 2/4] Packing InitrdBundle (vm-l2.toml + vmm-core-motor.cwasm + bzImage) & scratch alpine.raw"
rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR"

ALPINE_RAW="$RUNTIME_DIR/alpine.raw"
cp --sparse=always "$LINUX_BLOBS_DIR/alpine.raw" "$ALPINE_RAW"
ssh-keygen -y -f "$MOTO_DIR/test.key" > "$RUNTIME_DIR/authorized_keys"
python3 - "$ALPINE_RAW" "$RUNTIME_DIR/authorized_keys" "$RUNTIME_DIR/part3.ext4" <<'PY'
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

if [ "$NO_NETWORK" = 0 ]; then
    L2_PCI_ARRAY='["00:02.0", "00:03.0"]'
    L1_CMDLINE="vmm-passthrough pci_passthrough=00:02.0,00:03.0"
else
    L2_PCI_ARRAY='["00:02.0"]'
    L1_CMDLINE="vmm-passthrough pci_passthrough=00:02.0"
fi

cat > "$RUNTIME_DIR/vm-l2.toml" <<EOF
kernel = "bzImage"
cmd_line = "console=ttyS0 root=/dev/vda3 rw"
num_cpus = $L2_SMP
mem_size = "$L2_MEM"
pci = $L2_PCI_ARRAY
EOF

PASSTHROUGH_INITRD="$RUNTIME_DIR/initrd-passthrough"
python3 - \
    "$TEST_GUEST_DIR/test-init" \
    "$RUNTIME_DIR/vm-l2.toml" \
    "$TEST_GUEST_DIR/vmm-core-motor.cwasm" \
    "$LINUX_BLOBS_DIR/bzImage" \
    "$PASSTHROUGH_INITRD" <<'PY'
import pathlib, struct, sys

elf = pathlib.Path(sys.argv[1]).read_bytes()
toml = pathlib.Path(sys.argv[2]).read_bytes()
cwasm = pathlib.Path(sys.argv[3]).read_bytes()
kernel = pathlib.Path(sys.argv[4]).read_bytes()
out_path = pathlib.Path(sys.argv[5])

sys_io_start = 4096
sys_io_end = sys_io_start + len(elf)

buf = bytearray(4096)
struct.pack_into("<I", buf, 0, 0xF402100F)
struct.pack_into("<II", buf, 20, sys_io_start, sys_io_end)
buf.extend(elf)

pad0 = (-len(buf)) % 4096
if pad0:
    buf.extend(b"\x00" * pad0)

bundle_hdr = struct.pack(
    "<8sIIQQQQQQ",
    b"MVMMBNDL",
    1,
    0,
    len(toml),
    len(cwasm),
    len(kernel),
    0,
    0,
    0,
)
buf.extend(bundle_hdr)
buf.extend(toml)
buf.extend(cwasm)
buf.extend(kernel)

pad1 = (-len(buf)) % 4096
if pad1:
    buf.extend(b"\x00" * pad1)

out_path.write_bytes(buf)
PY

L0_CONFIG="$RUNTIME_DIR/vm-l0.toml"
cat > "$L0_CONFIG" <<EOF
log_file = "$RUNTIME_DIR/vmm-l0.log"
log_level = "info"
pvh = "$TEST_GUEST_DIR/kloader"
initramfs = "$PASSTHROUGH_INITRD"
cmd_line = "$L1_CMDLINE"
num_cpus = $L1_SMP
mem_size = "$L1_MEM"
iommu = true
blk = ["$ALPINE_RAW"]
EOF

if [ "$NO_NETWORK" = 0 ]; then
    cat >> "$L0_CONFIG" <<EOF

[net.dev0]
mac = "a4:a1:c2:00:00:01"
mtu = 1500
if_name = "$TAP_IF"
EOF
fi

banner "[Step 3/4] Topology B: Diskless L1 (initrd-only) virtio-blk + virtio-net Passthrough Quick Reference"
cat <<EOF
  * L1 Motor OS boots diskless ('initrd-only', zero Ring-3 Wasmtime or vmm-io!)
    and passes L0's PCI devices ($L2_PCI_ARRAY) straight through to L2 Alpine Linux!
  * L2 Alpine boots automatically on this serial console (root login, no password).
EOF
if [ "$NO_NETWORK" = 0 ]; then
    cat <<EOF

  * From the Linux host, SSH DIRECTLY into L2 Alpine over '$TAP_IF':
      $SCRIPT_DIR/ssh-into-alpine.sh
EOF
fi
cat <<EOF

  * Shutdown / escape keys:
      poweroff   -> Inside L2 Alpine shuts down L2 -> L1 -> L0 cleanly!
      Ctrl-b q   -> Shut down L2 from L1 PID 2 (and exit L1 -> L0 via ACPI S5)
      Ctrl-a q   -> Force-exit L0 Linux Wasm VMM (when --vmm wasm)
EOF

if [ "$L0_VMM" = "chv" ]; then
    CHV_BIN="${CHV_BIN:-$(command -v cloud-hypervisor-static 2>/dev/null || echo /usr/local/google/home/posk/bin/cloud-hypervisor-static)}"
    if [ ! -x "$CHV_BIN" ]; then
        echo "run-passthrough-blk-linux: cloud-hypervisor-static not found at '$CHV_BIN' (override with CHV_BIN)" >&2
        exit 1
    fi
    banner "[Step 4/4] Launching L0 cloud-hypervisor-static (virtio-iommu) -> L1 initrd-only -> L2 Alpine"
    set -- \
        --cpus "boot=$L1_SMP,nested=on" \
        --memory "size=$L1_MEM,thp=on" \
        --console off --serial tty \
        --log-file "$RUNTIME_DIR/chv-l0.log" \
        --kernel "$TEST_GUEST_DIR/kloader" \
        --initramfs "$PASSTHROUGH_INITRD" \
        --cmdline "$L1_CMDLINE" \
        --rng "src=/dev/urandom,iommu=virtio,pci_device_id=4" \
        --disk "path=$ALPINE_RAW,image_type=raw,iommu=virtio,pci_device_id=2"
    if [ "$NO_NETWORK" = 0 ]; then
        set -- "$@" --net "tap=$TAP_IF,mac=a4:a1:c2:00:00:01,iommu=virtio,pci_device_id=3"
    fi
    exec "$CHV_BIN" "$@"
else
    banner "[Step 4/4] Launching L0 Linux Wasm VMM ($MODE, virtio-iommu) -> L1 initrd-only -> L2 Alpine"
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
