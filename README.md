# WASM VMM

WASM VMM is a fork of v0.2.0 of Lencerf's
[Alioth](https://github.com/google/alioth), refactored to split the VMM into two
isolated WebAssembly guest modules (`#![no_std]` `vmm-core` targeting
`wasm32-unknown-unknown` and `vmm-io` targeting `wasm32-wasip1`) driven
by privileged core and userspace I/O hosts across a lock-free shared-memory
bridge (`BridgeShm`).

See [`architecture.md`](architecture.md) for the core/I/O split and bridge
specification, and [`airlock-motor-os.md`](airlock-motor-os.md) for the Motor OS
Ring-0 `vmm-core-host` + Ring-3 `vmm-io-host` roadmap and kernel ABI.

## Workspace Layout

- **`vmm-core`** (`vmm-core/`): `#![no_std] + alloc` core VMM logic (x86_64
  board, guest physical memory layout, ACPI tables, Linux `bzImage`/ELF/PVH
  loader, 16450 UART, PCIe ECAM bus, Virtio PCI modern transport + MSI-X,
  emulated `IoApic`, and x86_64 MMIO instruction decoder). Host-driven via
  non-blocking exports (`vmm_init`, `vmm_on_vcpu_exit`, `vmm_on_bridge_rx`) over
  `VcpuCommPage`. Compiles to `vmm-core.wasm` and AOT-precompiled `.cwasm`
  artifacts (`vmm-core.cwasm` for Linux, `vmm-core-motor.cwasm` for Ring-0 Motor
  OS) with zero floating-point or SIMD instructions.
- **`vmm-io`** (`vmm-io/`): Userspace device I/O plane (`vm.toml` parsing,
  Virtio `SplitQueue` descriptor-ring traversal over shared Guest RAM,
  `virtio-blk` file backend, `virtio-net` TAP backend, serial console handling,
  and I/O event loop). Compiles to `vmm-io.wasm` and `vmm-io.cwasm` with zero
  floating-point or SIMD instructions.
- **`vmm-core-host`** (`vmm-core-host/`): Native Linux KVM host implementing
  `VmmHostCore` and `VmmCoreBridge` (`/dev/kvm` ioctls, Guest RAM mapping,
  `KVM_CAP_SPLIT_IRQCHIP` MSI injection, `KVM_IOEVENTFD` doorbells, and the core
  side of `BridgeShm`). Builds `vmm-core-host-cwasm` (no compiler) and
  `vmm-core-host-wasm` (with Cranelift JIT).
- **`vmm-io-host`** (`vmm-io-host/`): Native Linux I/O host implementing
  `IoHost` (`/dev/net/tun` TAP devices, block image `pread`/`pwrite`, raw
  terminal serial I/O, `mio` polling, and the I/O side of `BridgeShm`). Spawns
  `vmm-core-host-*` sharing `BridgeShm`, Guest RAM `memfd`, and `eventfd`s.
  Builds `vmm-io-host-cwasm` and `vmm-io-host-wasm`.
- **`derive-layout`** (`derive-layout/`): Procedural macro helper crate for
  register/memory layout offsets.
- **`tests`** (`tests/`): End-to-end VM integration tests (`tests/tests/boot_vms.rs`)
  plus the Motor OS Ring-0 Airlock VMM host and guest test harness
  (`tests/{kernel,kloader,moto-sys,test-init}`).

## Prerequisites

1. **Sibling Checkouts**:
   - `../wasmtime`: Wasmtime checkout on branch `posk/nostd-threads` (`no_std`-compatible
     `threads` support used by both the Linux hosts and Motor OS Ring 0).
   - `../linux-blobs/` and `../motor-dev/motor-os/` (for end-to-end guest boot
     tests and Motor OS guest builds; see the
     [Motor OS build guide](https://github.com/moturus/motor-os/blob/main/docs/build.md)).
2. **Rust Targets & Components**:
   ```sh
   rustup component add rust-src
   rustup target add wasm32-unknown-unknown
   rustup target add wasm32-wasip1
   rustup target add x86_64-unknown-linux-musl
   ```

## Building & Testing

### Option A: Build & Stage with `./publish.sh`

[`./publish.sh`](publish.sh) builds the Linux host and Wasm guest release
artifacts (`vmm-core-host-{cwasm,wasm}`, `vmm-io-host-{cwasm,wasm}`,
`vmm-core.{cwasm,wasm}`, `vmm-io.{cwasm,wasm}`), copies them to `$DIR`, and
generates `$DIR/run-vm.sh`:

```sh
./publish.sh /path/to/stage-dir
```

### Option B: Build & Test with `cargo`

Running `cargo build` automatically compiles the Wasm guest modules and AOT
`.cwasm` artifacts via [`vmm-core-host/build.rs`](vmm-core-host/build.rs) and
[`vmm-io-host/build.rs`](vmm-io-host/build.rs):

```sh
cargo build --release --target=x86_64-unknown-linux-musl
```

To build the Motor OS Ring-0 VMM guest image (`tests/{kernel,kloader,test-init}`):

```sh
./tests/kernel/build.sh --release
```

To run workspace unit tests and end-to-end VM boot tests (full Alpine Linux,
Linux `initrd`, full Motor OS, minimal Motor OS `test-guest`, and nested
`L0 -> L1 -> L2` Motor OS Ring-0 `test-guest` in both `--cwasm` and `--wasm`
modes; note that the TAP-backed tests expect `puff-tap` / `moto-tap` configured
on the host):

```sh
cargo test --release
```

## Running VMs Interactively (`vm_scripts/`)

- **Boot Full Alpine Linux (`virtio-blk` + `virtio-net` on `puff-tap`)**:
  ```sh
  ./vm_scripts/run-linux.sh --cwasm     # or --wasm
  ```
- **Boot Linux Kernel + BusyBox `initramfs`**:
  ```sh
  ./vm_scripts/run-linux-initrd.sh --cwasm   # or --wasm
  ```
- **Boot Full Motor OS (`kloader` + `initrd` + `motor-os.qcow2` + `moto-tap`)**:
  ```sh
  ./vm_scripts/run-motor-os.sh --cwasm  # or --wasm
  ```
- **Boot Minimal Motor OS `test-guest` (`kloader` + `kernel` + `test-init`)**:
  ```sh
  ./vm_scripts/run-test-guest.sh --cwasm     # or --wasm
  ```
- **Boot Nested `L0 -> L1 -> L2` Motor OS Ring-0 VMM (`test-guest` in L1 booting `test-guest` in L2)**:
  ```sh
  ./vm_scripts/run-nested-test-guest.sh --cwasm   # or --wasm
  ```
- Press `Ctrl-a` followed by `q` (or `x`) in the serial console to shut down the
  VM and exit.
