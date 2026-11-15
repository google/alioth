#!/bin/sh
set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
RUNTIME_DIR="$REPO_ROOT/target/vm-runtime/airlock-linux-motor-os"
AIRLOCK_DIR="$REPO_ROOT/target/airlock"
HOST_TARGET_DIR="$REPO_ROOT/target/x86_64-unknown-linux-musl/release"

MOTO_ROOT="${MOTO_ROOT:-$REPO_ROOT/../motor-dev/motor-os}"
MOTO_DIR="${MOTO_DIR:-$MOTO_ROOT/vm_images/release}"
if [ ! -d "$MOTO_DIR" ]; then
    echo "run-airlock-linux-motor-os: Motor OS image directory '$MOTO_DIR' not found (override with MOTO_DIR)" >&2
    exit 1
fi
MOTO_DIR=$(CDPATH= cd -- "$MOTO_DIR" && pwd)
IMAGER="$MOTO_DIR/tools/imager"

LINUX_BLOBS_DIR="${LINUX_BLOBS_DIR:-$REPO_ROOT/../linux-blobs}"
if [ ! -d "$LINUX_BLOBS_DIR" ]; then
    echo "run-airlock-linux-motor-os: Linux blobs directory '$LINUX_BLOBS_DIR' not found (override with LINUX_BLOBS_DIR)" >&2
    exit 1
fi
LINUX_BLOBS_DIR=$(CDPATH= cd -- "$LINUX_BLOBS_DIR" && pwd)

MODE="cwasm"
L0_VMM="wasm"
PT_MODE="none"
WITH_KVM=0
L1_SMP="${AIRLOCK_L1_SMP:-4}"
L1_MEM="${AIRLOCK_L1_MEM:-1024M}"
L2_SMP="${MOTO_L2_SMP:-2}"
L2_MEM="${MOTO_L2_MEM:-256M}"
NO_NETWORK=0

usage() {
    cat >&2 <<EOF
Usage: $0 [--vmm wasm|chv] [--cwasm | --wasm] [--passthrough-net | --passthrough-all] [--with-kvm-loaded] [--l1-cpus N] [--l1-memory SIZE] [--l2-cpus N] [--l2-memory SIZE] [--no-network]
  --vmm wasm|chv       Select L0 hypervisor: Linux Wasm VMM (default) or cloud-hypervisor-static (with virtio-iommu)
  --cwasm              Run precompiled Wasm (.cwasm) in L0 and L1 Ring 3 (default)
  --wasm               Run Cranelift JIT (.wasm) in L0 and L1 Ring 3
  --passthrough-net    Pass L0's 00:03.0 virtio-net (moto-tap) directly through to L2 behind virtio-iommu
  --passthrough-all    Boot diskless initramfs-only L1 Linux and pass ALL PCI devices (00:02.0 + 00:03.0) to L2 Motor OS
  --with-kvm-loaded    Also load kvm.ko + kvm-amd.ko in L1 alongside airlock.ko to demonstrate coexistence
  --l1-cpus N          L1 Linux vCPU count (default: 4)
  --l1-memory SIZE     L1 Linux RAM with M or G suffix (default: 1024M)
  --l2-cpus N          L2 nested Motor OS vCPU count (default: 2)
  --l2-memory SIZE     L2 nested Motor OS RAM with M or G suffix (default: 256M)
  --no-network         Omit L0 host TAP device (emulated L1<->L2 tap0 192.168.5.0/24 still works!)
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
        --passthrough-net)
            PT_MODE="net"
            shift
            ;;
        --passthrough-all)
            PT_MODE="all"
            shift
            ;;
        --with-kvm-loaded)
            WITH_KVM=1
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
            echo "run-airlock-linux-motor-os: unknown argument '$1'" >&2
            usage
            exit 2
            ;;
    esac
done

case "$L0_VMM" in
    wasm|chv) ;;
    *)
        echo "run-airlock-linux-motor-os: invalid --vmm '$L0_VMM' (expected 'wasm' or 'chv')" >&2
        exit 2
        ;;
esac

if [ "$PT_MODE" != "none" ] && [ "$NO_NETWORK" = 1 ]; then
    echo "run-airlock-linux-motor-os: --no-network cannot be combined with passthrough modes" >&2
    exit 2
fi

banner() {
    printf '\n================================================================================\n'
    printf '%s\n' "$1"
    printf '================================================================================\n'
}

banner "[Step 1/4] Building L0 Wasm VMM, L1 Linux bzImage, and out-of-tree airlock.ko"
cargo build --release --target=x86_64-unknown-linux-musl --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-core-host -p vmm-io-host
"$REPO_ROOT/vmm-core-kmod/build.sh"

rm -rf "$RUNTIME_DIR"
mkdir -p "$RUNTIME_DIR/stage"

if [ "$MODE" = "wasm" ]; then
    IO_HOST_BIN="vmm-io-host-wasm"
    IO_MOD_NAME="vmm-io.wasm"
else
    IO_HOST_BIN="vmm-io-host-cwasm"
    IO_MOD_NAME="vmm-io.cwasm"
fi

KVM_LOAD_CMDS=""
if [ "$WITH_KVM" = 1 ]; then
    KVM_LOAD_CMDS="insmod /opt/airlock/irqbypass.ko 2>/dev/null || true
insmod /opt/airlock/kvm.ko 2>/dev/null || true
insmod /opt/airlock/kvm-amd.ko 2>/dev/null || true"
fi

if [ "$PT_MODE" = "all" ]; then
    banner "[Step 2/4] Staging diskless initramfs-only L1 Linux + passthrough L2 Motor OS disk"
    L2_RAW="$RUNTIME_DIR/motor-os.raw"
    qemu-img convert -f qcow2 -O raw "$MOTO_DIR/motor-os.qcow2" "$L2_RAW"

    cat > "$RUNTIME_DIR/stage/vm-l2.toml" <<EOF
log_file = "/tmp/vmm-l2.log"
log_level = "info"
pvh = "/opt/airlock/kloader"
initramfs = "/opt/airlock/initrd"
cmd_line = "system-tty"
num_cpus = $L2_SMP
mem_size = "$L2_MEM"
pci = ["00:02.0", "00:03.0"]
blk = []
EOF

    cat > "$RUNTIME_DIR/stage/init" <<EOF
#!/bin/sh
set -e
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
dmesg -n 4 2>/dev/null || true
if [ -c /dev/ttyS0 ]; then
    exec < /dev/ttyS0 > /dev/ttyS0 2>&1
fi
mkdir -p /tmp
mount -t tmpfs tmpfs /tmp
$KVM_LOAD_CMDS
insmod /opt/airlock/airlock.ko
echo "airlock-l1 (initramfs-only): passing ALL PCI devices [00:02.0, 00:03.0] to L2 Motor OS..."
/opt/airlock/$IO_HOST_BIN --airlock -c /opt/airlock/vm-l2.toml
echo "airlock-l1: L2 Motor OS exited cleanly; unloading airlock.ko and powering off L1..."
rmmod airlock
poweroff -f
EOF

    L1_INITRD="$RUNTIME_DIR/initramfs-airlock-pt-all-motor-os.cpio"
    cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-tests --bin stage_airlock_guest -- \
        pack-cpio-overlay \
        --base "$LINUX_BLOBS_DIR/initramfs.cpio.gz" \
        --dst "$L1_INITRD" \
        --mkdir opt \
        --mkdir opt/airlock \
        --put "$AIRLOCK_DIR/airlock.ko:opt/airlock/airlock.ko:0644" \
        --put "$AIRLOCK_DIR/irqbypass.ko:opt/airlock/irqbypass.ko:0644" \
        --put "$AIRLOCK_DIR/kvm.ko:opt/airlock/kvm.ko:0644" \
        --put "$AIRLOCK_DIR/kvm-amd.ko:opt/airlock/kvm-amd.ko:0644" \
        --put "$HOST_TARGET_DIR/$IO_HOST_BIN:opt/airlock/$IO_HOST_BIN:0755" \
        --put "$HOST_TARGET_DIR/$IO_MOD_NAME:opt/airlock/$IO_MOD_NAME:0644" \
        --put "$HOST_TARGET_DIR/vmm-core-motor.cwasm:opt/airlock/vmm-core-motor.cwasm:0644" \
        --put "$MOTO_DIR/kloader:opt/airlock/kloader:0644" \
        --put "$MOTO_DIR/initrd:opt/airlock/initrd:0644" \
        --put "$RUNTIME_DIR/stage/vm-l2.toml:opt/airlock/vm-l2.toml:0644" \
        --put "$RUNTIME_DIR/stage/init:init:0755"

    L1_CMDLINE="console=ttyS0 rdinit=/init pci-stub.ids=1af4:1042,1af4:1041,1af4:1044"
    L0_DISK="$L2_RAW"
    L0_TAP="moto-tap"
    rm -rf "$RUNTIME_DIR/stage"

    banner "[Step 3/4] All-PCI Passthrough Motor OS Quick Reference"
    cat <<EOF
  * L1 Linux boots diskless from initramfs (pci-stub claims 00:02.0 + 00:03.0),
    loads airlock.ko, and automatically boots L2 Motor OS with ZERO L1 Ring-3 VM-exits!
  * Escape / shutdown keys:
      Ctrl-b q   -> Shut down L2 Motor OS (L1 automatically unloads airlock.ko & powers off)
      Ctrl-a q   -> Immediate L0 Wasm VMM exit (when --vmm wasm)
  * Direct SSH from host into L2 Motor OS over passed-through 00:03.0 (moto-tap):
      $SCRIPT_DIR/ssh-into-motor-os.sh
EOF

    if [ "$L0_VMM" = "chv" ]; then
        CHV_BIN="${CHV_BIN:-$(command -v cloud-hypervisor-static 2>/dev/null || echo /usr/local/google/home/posk/bin/cloud-hypervisor-static)}"
        banner "[Step 4/4] Launching L0 cloud-hypervisor-static (virtio-iommu, 0 rng) -> L1 initramfs -> L2 Motor OS"
        exec "$CHV_BIN" \
            --cpus "boot=$L1_SMP,nested=on" \
            --memory "size=$L1_MEM,thp=on" \
            --console off --serial tty \
            --log-file "$RUNTIME_DIR/chv-l0.log" \
            --kernel "$AIRLOCK_DIR/bzImage" \
            --initramfs "$L1_INITRD" \
            --cmdline "$L1_CMDLINE" \
            --disk "path=$L0_DISK,image_type=raw,iommu=virtio,pci_device_id=2" \
            --net "tap=$L0_TAP,mac=a4:a1:c2:00:00:01,iommu=virtio,pci_device_id=3"
    else
        L0_CONFIG="$RUNTIME_DIR/vm-l0.toml"
        cat > "$L0_CONFIG" <<EOF
log_file = "$RUNTIME_DIR/vmm-l0.log"
log_level = "info"
kernel = "$AIRLOCK_DIR/bzImage"
initramfs = "$L1_INITRD"
cmd_line = "$L1_CMDLINE"
num_cpus = $L1_SMP
mem_size = "$L1_MEM"
iommu = true
blk = ["$L0_DISK"]

[net.dev0]
mac = "a4:a1:c2:00:00:01"
mtu = 1500
if_name = "$L0_TAP"
EOF
        banner "[Step 4/4] Launching L0 Linux Wasm VMM (virtio-iommu) -> L1 initramfs -> L2 Motor OS ($MODE)"
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
fi

banner "[Step 2/4] Staging scratch L1 Alpine Linux & L2 Motor OS disks"
L2_RAW="$RUNTIME_DIR/stage/l2-motor-os.raw"
L1_RAW="$RUNTIME_DIR/l1-alpine.raw"
qemu-img convert -f qcow2 -O raw "$MOTO_DIR/motor-os.qcow2" "$L2_RAW"

if [ "$PT_MODE" = "net" ]; then
    L0_TAP="moto-tap"
    cat > "$RUNTIME_DIR/stage/interfaces" <<EOF
auto lo
iface lo inet loopback
EOF
    cat > "$RUNTIME_DIR/stage/vm-l2.toml" <<EOF
log_file = "/tmp/vmm-l2.log"
log_level = "info"
pvh = "/opt/airlock/kloader"
initramfs = "/opt/airlock/initrd"
cmd_line = "system-tty"
num_cpus = $L2_SMP
mem_size = "$L2_MEM"
pci = ["00:03.0"]
blk = ["/opt/airlock/l2-motor-os.raw"]
EOF
    UNBIND_CMD="if [ -e /sys/bus/pci/devices/0000:00:03.0/driver/unbind ]; then echo 0000:00:03.0 > /sys/bus/pci/devices/0000:00:03.0/driver/unbind; fi"
    IFACES_ARG="--interfaces-file $RUNTIME_DIR/stage/interfaces"
    SSH_HINTS="       $SCRIPT_DIR/ssh-into-motor-os.sh                    # -> Direct L0->L2 russhd (motor@192.168.4.2:2222)"
else
    L0_TAP="puff-tap"
    cat > "$RUNTIME_DIR/stage/l2-sys-net.toml" <<EOF
auto_icmp_echo_reply = true
loopback = true
max_icmp_error_rate = 200
max_rst_rate = 200
max_syn_cookie_rate = 1000

[devices.net0]
mac = "a4:a1:c2:00:00:02"
cidrs = ["192.168.5.2/24"]
dns_servers = ["8.8.8.8"]

[[devices.net0.routes]]
ip_network = "0.0.0.0/0"
gateway = "192.168.5.1"
EOF
    "$IMAGER" put "$L2_RAW" "$RUNTIME_DIR/stage/l2-sys-net.toml" /system/cfg/sys-net.toml

    cat > "$RUNTIME_DIR/stage/vm-l2.toml" <<EOF
log_file = "/tmp/vmm-l2.log"
log_level = "info"
pvh = "/opt/airlock/kloader"
initramfs = "/opt/airlock/initrd"
cmd_line = "system-tty"
num_cpus = $L2_SMP
mem_size = "$L2_MEM"
blk = ["/opt/airlock/l2-motor-os.raw"]

[net.dev0]
mac = "a4:a1:c2:00:00:02"
mtu = 1500
if_name = "tap0:192.168.5.1/24"
EOF
    UNBIND_CMD=""
    IFACES_ARG=""
    SSH_HINTS="       $SCRIPT_DIR/ssh-into-airlock-l1.sh                  # -> L1 OpenSSH (root@192.168.8.2:22)
       $SCRIPT_DIR/ssh-into-airlock-nested-motor-os.sh     # -> L2 russhd (motor@192.168.5.2:2222 via L1)"
fi

cat > "$RUNTIME_DIR/stage/l1-shell.sh" <<EOF
#!/bin/sh
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
cd /opt/airlock 2>/dev/null || true
echo ""
echo "L1 Linux ($(uname -r)) ready! Run '/opt/airlock/run-l2.sh' to launch L2 Motor OS on airlock.ko."
exec /bin/sh
EOF

cat > "$RUNTIME_DIR/stage/run-l2.sh" <<EOF
#!/bin/sh
set -e
$KVM_LOAD_CMDS
$UNBIND_CMD
lsmod | grep -q '^airlock ' || insmod /opt/airlock/airlock.ko
exec /opt/airlock/$IO_HOST_BIN --airlock -c /opt/airlock/vm-l2.toml "\$@"
EOF

# shellcheck disable=SC2086
cargo run --release --manifest-path "$REPO_ROOT/Cargo.toml" -p vmm-tests --bin stage_airlock_guest -- \
    stage-alpine \
    --src "$LINUX_BLOBS_DIR/alpine.raw" \
    --dst "$L1_RAW" \
    --stage-dir "$RUNTIME_DIR/stage/ext4" \
    --resize-mib 2048 \
    --ssh-key "$MOTO_DIR/test.key" \
    --allow-tcp-forwarding \
    --autologin /opt/airlock/l1-shell.sh \
    $IFACES_ARG \
    --mkdir /opt \
    --mkdir /opt/airlock \
    --put "$RUNTIME_DIR/stage/l1-shell.sh:/opt/airlock/l1-shell.sh:0755" \
    --put "$AIRLOCK_DIR/airlock.ko:/opt/airlock/airlock.ko:0644" \
    --put "$AIRLOCK_DIR/irqbypass.ko:/opt/airlock/irqbypass.ko:0644" \
    --put "$AIRLOCK_DIR/kvm.ko:/opt/airlock/kvm.ko:0644" \
    --put "$AIRLOCK_DIR/kvm-amd.ko:/opt/airlock/kvm-amd.ko:0644" \
    --put "$HOST_TARGET_DIR/vmm-io-host-cwasm:/opt/airlock/vmm-io-host-cwasm:0755" \
    --put "$HOST_TARGET_DIR/vmm-io-host-wasm:/opt/airlock/vmm-io-host-wasm:0755" \
    --put "$HOST_TARGET_DIR/vmm-io.cwasm:/opt/airlock/vmm-io.cwasm:0644" \
    --put "$HOST_TARGET_DIR/vmm-io.wasm:/opt/airlock/vmm-io.wasm:0644" \
    --put "$HOST_TARGET_DIR/vmm-core-motor.cwasm:/opt/airlock/vmm-core-motor.cwasm:0644" \
    --put "$MOTO_DIR/kloader:/opt/airlock/kloader:0644" \
    --put "$MOTO_DIR/initrd:/opt/airlock/initrd:0644" \
    --put "$L2_RAW:/opt/airlock/l2-motor-os.raw:0644" \
    --put "$RUNTIME_DIR/stage/vm-l2.toml:/opt/airlock/vm-l2.toml:0644" \
    --put "$RUNTIME_DIR/stage/run-l2.sh:/opt/airlock/run-l2.sh:0755"

rm -rf "$RUNTIME_DIR/stage"

if [ "$PT_MODE" = "net" ]; then
    L1_CMDLINE="console=ttyS0 root=/dev/vda3 rw pci-stub.ids=1af4:1041"
else
    L1_CMDLINE="console=ttyS0 root=/dev/vda3 rw"
fi

if [ "$L0_VMM" = "chv" ]; then
    L0_EXIT_HINT="poweroff   -> Run 'poweroff -f' in L1 shell to shut down L0 cloud-hypervisor-static"
else
    L0_EXIT_HINT="Ctrl-a q   -> Shut down L0 Linux Wasm VMM (or run 'poweroff -f' in L1)"
fi

banner "[Step 3/4] Airlock Linux -> Nested Motor OS Quick Reference"
cat <<EOF
  1. At L1's root shell ('/opt/airlock #'), load airlock.ko and boot L2 Motor OS ($MODE mode):
       /opt/airlock/run-l2.sh

  2. Escape / shutdown keys:
       Ctrl-b q   -> Shut down L2 Motor OS and return to L1 Linux shell
       $L0_EXIT_HINT

  3. From the Linux host, SSH into L1 or nested L2:
$SSH_HINTS
EOF

if [ "$L0_VMM" = "chv" ]; then
    CHV_BIN="${CHV_BIN:-$(command -v cloud-hypervisor-static 2>/dev/null || echo /usr/local/google/home/posk/bin/cloud-hypervisor-static)}"
    if [ ! -x "$CHV_BIN" ]; then
        echo "run-airlock-linux-motor-os: cloud-hypervisor-static not found at '$CHV_BIN' (override with CHV_BIN)" >&2
        exit 1
    fi
    banner "[Step 4/4] Launching L0 cloud-hypervisor-static (virtio-iommu) -> L1 Linux -> L2 Motor OS ($MODE)"
    set -- \
        --cpus "boot=$L1_SMP,nested=on" \
        --memory "size=$L1_MEM,thp=on" \
        --console off --serial tty \
        --log-file "$RUNTIME_DIR/chv-l0.log" \
        --kernel "$AIRLOCK_DIR/bzImage" \
        --cmdline "$L1_CMDLINE" \
        --rng "src=/dev/urandom,iommu=virtio,pci_device_id=4" \
        --disk "path=$L1_RAW,image_type=raw,iommu=virtio,pci_device_id=2"
    if [ "$NO_NETWORK" = 0 ]; then
        set -- "$@" --net "tap=$L0_TAP,mac=a4:a1:c2:00:00:01,iommu=virtio,pci_device_id=3"
    fi
    exec "$CHV_BIN" "$@"
else
    L0_CONFIG="$RUNTIME_DIR/vm-l0.toml"
    cat > "$L0_CONFIG" <<EOF
log_file = "$RUNTIME_DIR/vmm-l0.log"
log_level = "info"
kernel = "$AIRLOCK_DIR/bzImage"
cmd_line = "$L1_CMDLINE"
num_cpus = $L1_SMP
mem_size = "$L1_MEM"
iommu = true
blk = ["$L1_RAW"]
EOF
    if [ "$NO_NETWORK" = 0 ]; then
        cat >> "$L0_CONFIG" <<EOF

[net.dev0]
mac = "a4:a1:c2:00:00:01"
mtu = 1500
if_name = "$L0_TAP"
EOF
    fi
    banner "[Step 4/4] Launching L0 Linux Wasm VMM (virtio-iommu) -> L1 Linux -> L2 Motor OS ($MODE)"
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
