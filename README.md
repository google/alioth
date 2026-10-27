# WASM VMM

WASM VMM is a fork of v0.2.0 of Lencerf's
[Alioth](https://github.com/google/alioth), refactored to split the VMM into two
isolated multithreaded WebAssembly guest modules (`vmm-core` and `vmm-io`)
targeting `wasm32-wasip1-threads` and two corresponding native Wasmtime hosts
(`vmm-core-host` and `vmm-io-host`). See [`split-vmm.md`](split-vmm.md) for the
full architecture and cross-split bridge design.

## Architecture

The workspace consists of five crates:

- **`vmm-core`** (`vmm-core/`): The core VMM architecture logic (x86_64 board,
  guest physical memory layout, ACPI tables, Linux `bzImage`/ELF/PVH loader,
  16450 UART register emulation, PCIe bus, Virtio PCI transport (`CommonCfg`,
  `NotifyCfg`, `IsrStatus`, `DeviceCfg`, MSI-X table), and vCPU run loops).
  Compiles to `vmm-core.wasm` and AOT-precompiled `vmm-core.cwasm` with zero
  floating-point or SIMD instructions.
- **`vmm-io`** (`vmm-io/`): The device I/O backend logic (`vm.toml` parsing,
  Virtio `SplitQueue` descriptor-ring traversal over shared guest RAM,
  `virtio-blk` file backend, `virtio-net` TAP backend, host serial console
  handling, and I/O event loop). Compiles to `vmm-io.wasm` and AOT-precompiled
  `vmm-io.cwasm` with zero floating-point or SIMD instructions.
- **`vmm-core-host`** (`vmm-core-host/`): Native Linux KVM host implementing the
  `VmmHostCore` trait (`/dev/kvm` ioctls, guest RAM mapping, MSI-X / INTx
  injection, and the core side of the shared-memory `BridgeShm` + `eventfd`
  bridge). Builds both `vmm-core-host-cwasm` (no compiler) and
  `vmm-core-host-wasm` (with Cranelift JIT).
- **`vmm-io-host`** (`vmm-io-host/`): Native Linux I/O host implementing the
  `VmmHostIo` trait (`/dev/net/tun` TAP devices, block image `pread`/`pwrite`,
  raw terminal serial I/O, `mio` polling, and the I/O side of the shared-memory
  bridge). Spawns `vmm-core-host-*` as a child process sharing `BridgeShm`,
  guest RAM `memfd`, and `eventfd`s. Builds both `vmm-io-host-cwasm` and
  `vmm-io-host-wasm`.
- **`derive-layout`** (`derive-layout/`): Procedural macro helper crate for
  register/memory layout offsets.

## Prerequisites

Install the required Rust compilation targets:

```sh
rustup target add wasm32-wasip1-threads
rustup target add x86_64-unknown-linux-musl
```

## Building

### Option A: Build & Stage with `./publish.sh` (Recommended)

Use [`./publish.sh`](publish.sh) to build all eight artifacts
(`vmm-core-host-cwasm`, `vmm-core-host-wasm`, `vmm-io-host-cwasm`,
`vmm-io-host-wasm`, `vmm-core.cwasm`, `vmm-core.wasm`, `vmm-io.cwasm`, and
`vmm-io.wasm`) as static `musl` / `wasm32-wasip1-threads` release binaries, copy
them to a destination directory `$DIR`, and generate a `$DIR/run-vm.sh` launcher
script:

```sh
./publish.sh /path/to/stage-dir
```

### Option B: Build with `cargo`

Running `cargo build` or `cargo build --release` (or with
`--target=x86_64-unknown-linux-musl`) automatically builds all eight host and
guest artifacts via [`vmm-core-host/build.rs`](vmm-core-host/build.rs) and
[`vmm-io-host/build.rs`](vmm-io-host/build.rs):

```sh
cargo build --release --target=x86_64-unknown-linux-musl
```

To run workspace unit tests:
```sh
cargo test --workspace
```

## Running Local Tests

- **Boot Alpine Linux (`virtio-blk` + `virtio-net`)**:
  ```sh
  ./local_test/run-vm.sh --cwasm
  # or with JIT compilation:
  ./local_test/run-vm.sh --wasm
  ```
- **Boot Linux Kernel + BusyBox `initramfs` (`../busybox-*/`)**:
  ```sh
  ./local_test/run-vm-initrd.sh --cwasm
  # or with JIT compilation:
  ./local_test/run-vm-initrd.sh --wasm
  ```
- Press `Ctrl-a` followed by `q` (or `x`) in the serial console to shut down the
  VM and exit.
