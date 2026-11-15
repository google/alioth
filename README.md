# WASM VMM

WASM VMM (`wasm-vmm` branch, forked from [Alioth](https://github.com/google/alioth)
v0.2.0) splits a virtual machine monitor into two isolated WebAssembly guest
modules connected by shared Guest RAM and a lock-free shared-memory bridge
(`BridgeShm`):

- **`vmm-core`** (`wasm32-unknown-unknown`, `#![no_std] + alloc`, zero WASI):
  Chipset, boot loader, ACPI tables, PCIe bus, VirtIO PCI transport, `virtio-iommu`
  PCI front-end, PCI passthrough config virtualization, emulated `IoApic`, serial
  UART, and fallback MMIO decoder.
- **`vmm-io`** (`wasm32-wasip1`): Userspace device I/O plane (`vm.toml` parsing,
  VirtIO `SplitQueue` descriptor-ring processing, `virtio-blk`, `virtio-net`,
  `virtio-iommu` translation state, and serial console I/O).

The exact same `vmm-core` and `vmm-io` WebAssembly modules run across **three
hypervisor core hosts** (Linux Ring-3 KVM `vmm-core-host`, Motor OS Ring-0
kernel VMM, and Linux Ring-0 out-of-tree `airlock.ko`) and **two Ring-3 I/O
hosts** (Linux `vmm-io-host` and Motor OS `motor-io-host`), with support for
emulated `virtio-iommu` and direct IOMMU-backed PCI/MSI-X device passthrough.

See [`architecture.md`](architecture.md) for a detailed guide to all components,
data/control paths, passthrough/IOMMU mechanics, hosts, and build artifacts.

## Repository Layout

- `vmm-core/`: `#![no_std] + alloc` core VMM guest crate (`vmm-core.wasm`).
- `vmm-io/`: WASI userspace I/O guest crate (`vmm-io.wasm`).
- `vmm-core-host/`: Linux Ring-3 `/dev/kvm` core host (`vmm-core-host-{cwasm,wasm}`)
  and AOT `.cwasm` build script (`vmm-core.cwasm`, `vmm-core-motor.cwasm`).
- `vmm-io-host/`: Linux Ring-3 I/O host (`vmm-io-host-{cwasm,wasm}`), supporting
  both `vmm-core-host` (KVM) and `/dev/airlock` (`--airlock` Ring-0 `airlock.ko`).
- `vmm-core-kmod/`: Out-of-tree, KVM-independent Linux Ring-0 kernel module
  (`target/airlock/airlock.ko`) embedding `#![no_std]` Wasmtime.
- `derive-layout/`: Procedural macro crate for struct field/offset layouts.
- `tests/`: End-to-end integration test suite (`tests/tests/boot_vms.rs`), plus
  the Motor OS Ring-0 VMM kernel (`tests/{kernel,kloader,moto-sys}`), Ring-3
  `motor-io-host` (`tests/motor-io-host/`), and minimal `initrd` launcher
  (`tests/test-init/`).
- `vm_scripts/`: Interactive scripts for booting direct and nested Linux and
  Motor OS VMs (with companion `ssh-into-*.sh` helpers).

## Prerequisites

1. **Sibling Checkouts**:
   - `../wasmtime`: Wasmtime checkout on branch `posk/nostd-threads` (`#![no_std]`
     shared-memory support used by both userspace and Ring-0 hosts).
   - Optional (for guest builds and integration tests): `../linux-blobs/`
     (Alpine disk & `initramfs`), `../linux-stable/` (Linux kernel source for L1
     `airlock.ko` builds), and `../motor-dev/motor-os/` (Motor OS images; see the
     [Motor OS build guide](https://github.com/moturus/motor-os/blob/main/docs/build.md)).
2. **Rust Toolchain Targets**:
   ```sh
   rustup component add rust-src
   rustup target add wasm32-unknown-unknown wasm32-wasip1 x86_64-unknown-linux-musl
   ```
3. **Host TAP Interfaces** (for networked VM scripts and tests):
   ```sh
   ./vm_scripts/create-tap.sh   # sets up puff-tap (192.168.8.1/24)
   ```

## Building & Testing

```sh
# 1. Build Linux hosts (vmm-{core,io}-host-{cwasm,wasm}) + Wasm/cwasm artifacts
cargo build --release --target=x86_64-unknown-linux-musl

# (Optional) Stage release Linux hosts, Wasm/cwasm modules, and a standalone run-vm.sh
./publish.sh /path/to/stage-dir

# 2. Build Linux Ring-0 airlock.ko + L1 guest kernel (in target/airlock/)
./vmm-core-kmod/build.sh
# Or build only airlock.ko against an existing kernel build directory:
./vmm-core-kmod/build.sh --kmod-only --kdir /lib/modules/$(uname -r)/build

# 3. Build Motor OS Ring-0 VMM guest image and Ring-3 motor-io-host
./tests/kernel/build.sh --release
./tests/motor-io-host/build.sh

# 4. Run unit and end-to-end integration tests
cargo test --release
```

## Example Command Lines

### Direct `vmm-io-host` Invocation

```sh
# Run a VM over Linux KVM using AOT-precompiled .cwasm modules
./target/x86_64-unknown-linux-musl/release/vmm-io-host-cwasm -c path/to/vm.toml

# Run a VM over Linux KVM using Cranelift JIT (.wasm modules)
./target/x86_64-unknown-linux-musl/release/vmm-io-host-wasm -c path/to/vm.toml

# Run a VM over Linux Ring-0 airlock.ko (/dev/airlock, no KVM or vmm-core-host process)
sudo insmod ./target/airlock/airlock.ko
./target/x86_64-unknown-linux-musl/release/vmm-io-host-cwasm --airlock -c path/to/vm.toml
```

### Direct L1 Guests (`vm_scripts/`)

```sh
# Boot Alpine Linux (virtio-blk + virtio-net on puff-tap) and SSH in
./vm_scripts/run-linux.sh --cwasm          # or --wasm
./vm_scripts/ssh-into-alpine.sh

# Boot Linux kernel with BusyBox initramfs
./vm_scripts/run-linux-initrd.sh --cwasm

# Boot Motor OS and SSH in
./vm_scripts/run-motor-os.sh --cwasm       # or --wasm
./vm_scripts/ssh-into-motor-os.sh
```

### Nested `L0 -> L1 -> L2` on Linux Ring-0 (`airlock.ko`)

```sh
# L1 Linux + airlock.ko booting L2 Alpine Linux (emulated L1<->L2 bridge)
./vm_scripts/run-airlock-linux-alpine.sh
./vm_scripts/ssh-into-airlock-l1.sh              # SSH into L1 Linux
./vm_scripts/ssh-into-airlock-nested-alpine.sh   # SSH into L2 Alpine

# Pass L0's virtio-net PCI device directly to L2 behind virtio-iommu
./vm_scripts/run-airlock-linux-alpine.sh --passthrough-net

# Full passthrough: diskless initramfs-only L1 passing ALL PCI devices to L2
# (zero Ring-3 VM-exits in L1 during steady-state disk & network I/O)
./vm_scripts/run-airlock-linux-alpine.sh --passthrough-all
./vm_scripts/run-airlock-linux-motor-os.sh --passthrough-all --vmm chv
./vm_scripts/ssh-into-airlock-nested-motor-os.sh
```

Both `run-airlock-linux-*.sh` scripts also accept `--wasm`, `--vmm chv` (use
`cloud-hypervisor-static` with `virtio-iommu` as L0), `--with-kvm-loaded` (load
`kvm` alongside `airlock.ko` in L1), and `--no-network`.

### Nested `L0 -> L1 -> L2` on Motor OS Ring 0

```sh
# L1 Motor OS (Ring-0 VMM + Ring-3 motor-io-host) booting L2 Motor OS or L2 Alpine Linux
./vm_scripts/run-nested-motor-os.sh --cwasm
./vm_scripts/ssh-into-nested-motor-os.sh

./vm_scripts/run-nested-linux.sh --cwasm
./vm_scripts/ssh-into-nested-linux.sh

# PCI passthrough from L0 through Motor OS Ring-0 IOMMU + VMM to L2 Alpine Linux
./vm_scripts/run-passthrough-net-linux.sh --cwasm          # passthrough virtio-net
./vm_scripts/run-passthrough-blk-linux.sh --vmm chv        # diskless L1, passthrough blk + net
./vm_scripts/ssh-into-alpine.sh
```

### Serial Console Escape Keys

- Press `Ctrl-a` then `q` (or `x`) to shut down the outer L0 VM and exit.
- Press `Ctrl-b` then `q` (or `x`) to shut down a nested L2 VM and return to L1.
