# WASM VMM

WASM VMM is a fork of v0.2.0 of Lencerf's
[Alioth](https://github.com/google/alioth), refactored to split the VMM into a
WebAssembly guest component (`vmm-runner`) and a thin native Wasmtime/KVM host
(`vmm-host`).

## Architecture

The workspace consists of three crates and a WIT component interface:

- **`vmm-runner`** (`vmm-runner/`): The core VMM logic (x86_64 board, memory
  management, ACPI tables, Linux `bzImage`/ELF/PVH loader, 16450 serial console,
  PCI bus, `virtio-blk`, and `virtio-net`). It compiles to the
  `wasm32-wasip2` target as a WASI Preview 2 component.
- **`vmm-host`** (`vmm-host/`): A thin native Linux host binary using
  `wasmtime` and `wasmtime-wasi` to load and execute the `vmm-runner` WASI
  Preview 2 component. It implements all host-side OS and KVM interactions
  (`/dev/kvm` ioctls, vCPU worker threads, anonymous `mmap` guest RAM, raw
  terminal serial I/O, `/dev/net/tun` TAP device, and `mio` event polling).
- **`wit/vmm.wit`**: The WebAssembly Interface Type (WIT) definition for the
  `vmm:host/api` interface and `vmm-world` component world connecting
  `vmm-runner` and `vmm-host`.
- **`derive-layout`** (`derive-layout/`): Procedural macro helper crate for
  register/memory layout offsets.

## Prerequisites

Install the required Rust compilation targets:

```sh
rustup target add wasm32-wasip2
rustup target add x86_64-unknown-linux-musl
```

## Building

### 1. Build `vmm-runner` (`wasm32-wasip2` component)

To explicitly build the `vmm-runner` WASI Preview 2 component by itself:

```sh
cargo build -p vmm-runner --target=wasm32-wasip2 --release
```

This produces the component binary at:
`target/wasm32-wasip2/release/vmm-runner.wasm`

### 2. Build `vmm-host` (and embedded `vmm-runner`)

Building `vmm-host` automatically invokes a build script (`vmm-host/build.rs`)
that compiles `vmm-runner` for `wasm32-wasip2` in release mode and embeds the
resulting `.wasm` component into the `vmm-host` binary.

To build the static `x86_64-unknown-linux-musl` release binary (recommended for
copying to other hosts, and used by `local_test/run-vm.sh`):

```sh
cargo build --release --target=x86_64-unknown-linux-musl
```

Or to build for the default host target:

```sh
cargo build --release
```

### 3. Run Tests

```sh
cargo test --workspace
```

## Required Artifacts & Deploying to Another Host

Because `vmm-host` is statically linked when built with
`--target=x86_64-unknown-linux-musl`, it has no dynamic library (`glibc`, etc.)
dependencies and can be copied directly to any `x86_64` Linux machine with KVM
enabled (`/dev/kvm`).

### List of Required Artifacts

| Artifact | Source Path in Repo | Required? | Purpose |
| :--- | :--- | :--- | :--- |
| **`vmm-host`** | `target/x86_64-unknown-linux-musl/release/vmm-host` | **Yes** | Statically linked Wasmtime + KVM host binary (includes an embedded copy of `vmm-runner.wasm`). |
| **`vmm-runner.wasm`** | `target/wasm32-wasip2/release/vmm-runner.wasm` | Optional | Standalone WASI Preview 2 component. Only needed if you want to pass `-w vmm-runner.wasm` (or `VMM_RUNNER_WASM`) instead of using the copy embedded in `vmm-host`. |
| **`vm.toml`** | `local_test/vm.toml` (or root `vm.toml`) | **Yes** | VM configuration file (CPU count, RAM size, kernel/disk paths, TAP network config, log path). |
| **`bzImage`** | `local_test/bzImage` | **Yes** | Guest Linux kernel image referenced by `kernel` in `vm.toml` (plus `initramfs` if configured). |
| **`alpine.raw`** | `local_test/alpine.raw` | **Yes** | Raw disk image(s) referenced by `blk` in `vm.toml`. |
| **`create-tap.sh`** | `local_test/create-tap.sh` | Optional | Host script to create the `puff-tap` TAP interface (`192.168.8.1/24`) and `nftables` NAT rules on the target host (required if `[net.dev0]` is present in `vm.toml`). |
| **`ssh-into-alpine.sh`** | `local_test/ssh-into-alpine.sh` | Optional | Convenience script to SSH into the guest at `root@192.168.8.2`. |

### How to Stage & Copy Artifacts to Another Host (`./publish.sh`)

You can use [`./publish.sh`](publish.sh) to build `vmm-host` (static `musl`
release binary) and `vmm-runner.wasm` (`wasm32-wasip2` release component), copy
both into a target directory `$DIR`, and generate a `$DIR/run-vm.sh` launcher
script:

```sh
./publish.sh /path/to/stage-dir
```

`run-vm.sh` in `$DIR` looks for `vm.toml` in its own directory by default, or
accepts a config file path as an input parameter (`./run-vm.sh <path/to/vm.toml>`).
If `vm.toml` is not found, it prompts you to create one or pass it as an
argument.

Relative paths inside `vm.toml` (such as `kernel = "bzImage"` and
`blk = ["alpine.raw"]`) are resolved relative to the directory containing
`vm.toml`. Place `vm.toml`, `bzImage`, and `alpine.raw` in the same directory on
the destination host (or update `vm.toml` with their paths on the destination
host).

1. **Stage the VMM binaries and launcher script**:
   ```sh
   ./publish.sh /tmp/wasm-vmm-dist
   ```

2. **Copy the staged binaries and VM guest files to the target host** (using
   `rsync -S` to handle the sparse `alpine.raw` disk image efficiently):
   ```sh
   ssh user@target-host "mkdir -m 750 -p ~/wasm-vmm-run"

   rsync -avS --progress \
       /tmp/wasm-vmm-dist/ \
       local_test/vm.toml \
       local_test/bzImage \
       local_test/alpine.raw \
       local_test/create-tap.sh \
       local_test/ssh-into-alpine.sh \
       user@target-host:~/wasm-vmm-run/
   ```

   The resulting directory on `target-host` will look like:
   ```text
   ~/wasm-vmm-run/
   ├── vmm-host
   ├── vmm-runner.wasm
   ├── run-vm.sh
   ├── vm.toml
   ├── bzImage
   ├── alpine.raw
   ├── create-tap.sh
   └── ssh-into-alpine.sh
   ```

3. **Run on the target host**:
   Ensure your user has read/write access to `/dev/kvm` (and `/dev/net/tun` if
   using TAP networking):
   ```sh
   ssh -t user@target-host
   cd ~/wasm-vmm-run

   # Set up the TAP device once per host boot (if [net.dev0] is used in vm.toml):
   ./create-tap.sh

   # Run using vm.toml in ~/wasm-vmm-run:
   ./run-vm.sh

   # Or pass a custom config file path:
   ./run-vm.sh /path/to/custom-vm.toml
   ```

## Running a Linux VM from the Repository

### 1. VM Configuration (`vm.toml`)

A VM is configured via a TOML file (see `local_test/vm.toml`):

```toml
kernel = "bzImage"
cmd_line = "console=ttyS0 root=/dev/vda3 rw"
num_cpus = 4
mem_size = "256M"
blk = ["alpine.raw"]
log_file = "/tmp/wasm-vmm.log"
log_level = "info"

[net.dev0]
mac = "a4:a1:c2:00:00:01"
mtu = 1500
if_name = "puff-tap"
```

> Note: If you want to run without networking, leave `[net]` as an empty table
> (`[net]`) and omit `[net.dev0]`.

### 2. Set Up Host TAP Networking (Optional)

If your `vm.toml` configures a TAP network interface (such as `puff-tap` in
`local_test/vm.toml`), create and configure the TAP device on the host first:

```sh
cd local_test
./create-tap.sh
```

### 3. Launch the VM

From `local_test/` (where `bzImage`, `alpine.raw`, and `vm.toml` are located),
run the helper script:

```sh
cd local_test
./run-vm.sh
```

Or invoke `vmm-host` directly:

```sh
cd local_test
../target/x86_64-unknown-linux-musl/release/vmm-host -c vm.toml
```

By default, `vmm-host` executes the `vmm-runner.wasm` component embedded at
build time. To load an external `vmm-runner.wasm` component file at runtime,
pass `-w` / `--wasm` (or set the `VMM_RUNNER_WASM` environment variable):

```sh
cd local_test
../target/x86_64-unknown-linux-musl/release/vmm-host \
    -c vm.toml \
    -w ../target/wasm32-wasip2/release/vmm-runner.wasm
```

### 4. Interacting with and Exiting the VM

- **Serial Console**: The guest's `ttyS0` serial console is attached directly to
  your terminal's standard input/output.
- **SSH** (when TAP networking is active):
  ```sh
  ./local_test/ssh-into-alpine.sh
  ```
- **Shutting Down**:
  - Run `poweroff` inside the guest, or
  - Press `Ctrl-a` followed by `q` in the serial console to immediately stop the
    VM and exit.
- **Logs**: VMM logs emitted by `vmm-runner` inside Wasm are written to the path
  configured by `log_file` in `vm.toml` (default `/tmp/wasm-vmm.log`).
