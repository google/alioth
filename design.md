# WASM VMM Design Document

## 1. Overview & Motivation

**WASM VMM** splits a Linux/KVM Virtual Machine Monitor (originally based on
[Alioth](https://github.com/google/alioth) v0.2.0) into two isolated layers:

1. **`vmm-runner` (WebAssembly Guest Component)**:
   Contains all complex VMM logic—guest physical memory layout, x86_64
   architecture setup, ACPI table generation, Linux `bzImage`/ELF/PVH kernel
   loading, PCI bus emulation, 16450 UART serial emulation, and Virtio
   (`virtio-blk`, `virtio-net`) device and split-virtqueue emulation. It compiles
   to the `wasm32-wasip2` target as:
   - **`vmm-runner.wasm` (~655 KB)**: Portable WASI Preview 2 component.
   - **`vmm-runner.cwasm` (~1.8 MB)**: Ahead-of-Time (AOT) precompiled Wasmtime
     component artifact.
2. **`vmm-host` (Native Linux Host Binaries)**: A thin native wrapper embedding
   Wasmtime that exposes Linux `/dev/kvm` ioctls, host `mmap` memory allocation,
   `/dev/net/tun` TAP networking, and host terminal I/O to `vmm-runner` via a
   strongly typed WIT interface (`wit/vmm.wit`). It builds in two variants:
   - **`vmm-host-cwasm` ("small" host, ~2.9 MB static `musl`)**: Built without
     Cranelift; loads precompiled `vmm-runner.cwasm` (`--cwasm`).
   - **`vmm-host-wasm` ("safe" host, ~12.4 MB static `musl`)**: Built with
     Cranelift; validates and compiles `vmm-runner.wasm` in-process at startup
     (`--wasm`).

```text
+------------------------------------------------------------------------------+
|                  vmm-host-cwasm / vmm-host-wasm (x86_64 Linux)               |
|                                                                              |
|  +------------------------------------------------------------------------+  |
|  |                     Wasmtime Engine + WASIp2 Host                      |  |
|  |                                                                        |  |
|  |  +------------------------------------------------------------------+  |  |
|  |  |      vmm-runner.cwasm / vmm-runner.wasm (wasm32-wasip2 guest)    |  |  |
|  |  |                                                                  |  |  |
|  |  |  +----------------+  +------------------+  +------------------+  |  |  |
|  |  |  | Kernel Loader  |  |   x86_64 Board   |  |   RAM / MMIO /   |  |  |  |
|  |  |  | (bzImage/PVH)  |  | & Event Loop     |  |   PIO Bus        |  |  |  |
|  |  |  +----------------+  +------------------+  +------------------+  |  |  |
|  |  |  +----------------+  +------------------+  +------------------+  |  |  |
|  |  |  |  ACPI / E820   |  | 16450 Serial     |  | PCI + Virtio     |  |  |  |
|  |  |  |  Tables        |  | Console (COM1)   |  | (blk, net, split)|  |  |  |
|  |  |  +----------------+  +------------------+  +------------------+  |  |  |
|  |  +------------------------------------------------------------------+  |  |
|  |                 |                                    |                 |  |
|  |      WIT: vmm:host/api                     WASI Preview 2 APIs         |  |
|  +-----------------|------------------------------------|-----------------+  |
|                    v                                    v                    |
|  +-----------------------------------+  +---------------------------------+  |
|  | KVM & Host I/O Subsystems         |  | Host Filesystem & Stdio         |  |
|  | - /dev/kvm (VM, vCPU, Irqfd, MSI) |  | - vm.toml config                |  |
|  | - Host vCPU threads (KVM_RUN)     |  | - bzImage / initramfs           |  |
|  | - Anonymous mmap (MemPages)       |  | - Disk images (alpine.raw)      |  |
|  | - /dev/net/tun (HostTap)          |  | - VMM log (/tmp/wasm-vmm.log)   |  |
|  | - Raw termios stdin/stdout        |  +---------------------------------+  |
|  | - mio::Poll I/O thread            |                                       |
|  +-----------------------------------+                                       |
+------------------------------------------------------------------------------+
                                       |
                                       v
                         Linux Kernel (/dev/kvm, /dev/net/tun)
```

---

## 2. Division of Responsibilities

### 2.1 What `vmm-host` is Responsible For

`vmm-host` (`vmm-host/src/`) contains no device emulation, no guest memory
layout knowledge, and no kernel parsing. Its sole job is to bridge Wasmtime host
calls to Linux kernel primitives:

- **Wasmtime & WASI Preview 2 Hosting (`vmm-host/src/wasm_host.rs`)**:
  - In `vmm-host-cwasm` ("small" pair), deserializes the AOT-precompiled
    `vmm-runner.cwasm` via `Component::deserialize_file(&engine, path)`.
  - In `vmm-host-wasm` ("safe" pair), validates and JIT-compiles
    `vmm-runner.wasm` via `Component::from_file(&engine, path)`.
  - Configures `wasmtime-wasi` (`WasiCtxBuilder`) with preopened directories so
    the Wasm component can read `vm.toml`, the guest kernel, and raw disk images,
    and write its log file.
  - Maps WIT resources (`hypervisor`, `vm`, `vcpu`, `vm-memory`, `mem-pages`,
    `intx-sender`, `msi-sender`, `serial-console`, `tap`) in a Wasmtime
    `ResourceTable`.
- **KVM System & VM Lifecycle (`vmm-host/src/kvm/`)**:
  - Opens `/dev/kvm`, verifies `KVM_API_VERSION`, and queries
    `KVM_GET_SUPPORTED_CPUID`.
  - Creates the VM file descriptor (`KVM_CREATE_VM`), TSS, identity map,
    in-kernel PIC/IOAPIC/LAPIC (`KVM_CREATE_IRQCHIP`), and PIT2
    (`KVM_CREATE_PIT2`).
- **Host Guest-RAM Allocation & Mapping (`vmm-host/src/kvm/mem.rs`)**:
  - Allocates page-aligned anonymous host memory via `mmap(MAP_ANONYMOUS | MAP_PRIVATE)`
    wrapped in `HostMemPages`.
  - Registers/unregisters memory slots with KVM via `KVM_SET_USER_MEMORY_REGION`.
  - Provides safe `read(offset, dst)` and `write(offset, src)` operations on
    `HostMemPages` so the 32-bit Wasm guest never dereferences 64-bit host
    pointers.
- **Host vCPU Worker Threads (`vmm-host/src/kvm/vcpu.rs`, `vmm-host/src/kvm/kvm.rs`)**:
  - Creates KVM vCPU file descriptors (`KVM_CREATE_VCPU`) and `mmap`s each
    vCPU's `kvm_run` structure.
  - Because WASI Preview 2 components execute on a single thread and cannot
    spawn native OS threads for blocking `ioctl(KVM_RUN)` calls, `vmm-host`
    spawns one native host thread per vCPU (`vcpu_0`, `vcpu_1`, ...).
  - Translates KVM register ioctls (`KVM_GET_REGS`, `KVM_SET_REGS`,
    `KVM_GET_SREGS`, `KVM_SET_SREGS`, `KVM_SET_CPUID2`) and `kvm_run` exit
    reasons (`KVM_EXIT_IO`, `KVM_EXIT_MMIO`, `KVM_EXIT_SYSTEM_EVENT`,
    `KVM_EXIT_INTR`).
- **Interrupt Injection (`KvmIntxSender`, `KvmMsiSender`)**:
  - Injects legacy INTx interrupts via `KVM_IRQFD` (`eventfd`) and MSI
    interrupts via `KVM_SIGNAL_MSI`.
- **Host I/O Polling, Serial Terminal, and TAP (`vmm-host/src/serial.rs`, `vmm-host/src/tap.rs`)**:
  - Puts host `stdin` into non-blocking raw `termios` mode (`HostSerialConsole`)
    and opens/configures `/dev/net/tun` (`TUNSETIFF`, `TUNSETOFFLOAD`) for
    `HostTap`.
  - Runs a dedicated host `mio::Poll` thread (`vmm_io_poll`) that monitors host
    `stdin` and TAP file descriptors and forwards readiness notifications into
    the central VM event channel.

---

### 2.2 What `vmm-runner` is Responsible For

`vmm-runner` (`vmm-runner/src/`) is a pure-Rust crate compiled to
`wasm32-wasip2`. It interacts with the host exclusively through the traits in
`vmm-runner/src/host.rs` (backed by WIT imports in `vmm-runner/src/wasm.rs` and
WASI filesystem calls):

- **Configuration & Logging (`vmm-runner/src/config.rs`, `vmm-runner/src/lib.rs`)**:
  - Parses `vm.toml` and initializes `simplelog` to write to `log_file`.
- **x86_64 PC/Q35-like Board & Memory Map (`vmm-runner/src/hw/`)**:
  - Sets up the guest physical address space (`RamBus`, `Addressable<Box<dyn Mmio>>`,
    `Addressable<Box<dyn Pio>>`), including low RAM below the 2 GiB MMIO gap and
    high RAM above 4 GiB when needed.
  - Generates ACPI tables (`RSDP`, `XSDT`, `FADT`, `DSDT`, `MADT`, `MCFG`) in
    guest RAM so Linux discovers all vCPUs, the IOAPIC, and the PCIe ECAM region.
  - Emulates the 8254 PIT (port `0x61`), CMOS/RTC (ports `0x70`–`0x71`), ACPI
    PM/sleep control registers (`0x600`, `0x604`), and fw_cfg ports.
  - Synchronizes AP (secondary vCPU) startup with BSP (vCPU 0) initialization.
- **Kernel & Initramfs Loader (`vmm-runner/src/loader/`)**:
  - Parses Linux `bzImage` setup headers (`BootParams`, E820 table, command line,
    initial 64-bit identity page tables `PML4`/`PDPT`/`PD`, and `BOOT_GDT`) or
    Xen PVH ELF notes, loads the kernel and optional `initramfs` into guest RAM,
    and computes the initial vCPU register state (`InitState`).
- **16450 UART Serial Console (`vmm-runner/src/hw/serial.rs`)**:
  - Emulates COM1 at I/O port `0x3f8`–`0x3ff` (registers `RBR`, `THR`, `IER`,
    `IIR`, `LCR`, `MCR`, `LSR`, `MSR`, `DLL`, `DLM`), FIFO buffering, escape
    sequence detection (`Ctrl-a q` to shut down), and IRQ 4 assertion via
    `IntxSender`.
- **PCI Bus & Virtio Devices (`vmm-runner/src/virtio/`)**:
  - Emulates PCIe ECAM configuration space (`0xe000_0000`), PCI host bridge
    (`00:00.0`), Virtio PCI capabilities (Common, Notify, ISR, Device, MSI-X),
    and 64-bit BAR allocation/relocation.
  - **`virtio-blk` (`vmm-runner/src/virtio/dev/blk.rs`)**: Handles
    `VIRTIO_BLK_T_IN`, `VIRTIO_BLK_T_OUT`, `VIRTIO_BLK_T_FLUSH`, and
    `VIRTIO_BLK_T_GET_ID` directly using WASI file `seek`/`read_exact`/`write_all`
    on the disk image.
  - **`virtio-net` (`vmm-runner/src/virtio/dev/net.rs`)**: Negotiates Virtio net
    offload features (`CSUM`, `TSO4`, `TSO6`, `USO`, etc.) with `Tap`, registers
    the TAP device token for readiness events, and transfers Ethernet frames
    between RX/TX split virtqueues and the host TAP device.

---

## 3. Crossing the 32-bit Wasm / 64-bit Host Boundary

### 3.1 WIT Resource Model (`wit/vmm.wit`)

The interface between `vmm-runner` and `vmm-host` is defined in `wit/vmm.wit`
under `package vmm:host`:

```text
world vmm-world
  ├── export run(config-path: string) -> result<_, string>
  └── import api
        ├── get-hypervisor() -> result<hypervisor, string>
        └── resources:
              hypervisor
                └── create-vm() -> vm
                      ├── create-vcpu(id)           -> vcpu
                      ├── create-vm-memory()        -> vm-memory
                      │     └── alloc-anon-mem(sz)  -> mem-pages
                      ├── create-intx-sender(pin)   -> intx-sender
                      ├── create-msi-sender()       -> msi-sender
                      ├── create-serial-console()   -> serial-console
                      ├── create-tap(if-name)       -> tap
                      ├── next-event()              -> vm-event
                      ├── resume-vcpu(id, vm-entry)
                      └── stop-vcpu(id)
```

### 3.2 Guest RAM & Virtqueue Access Across Address Spaces

In a traditional native VMM, guest RAM is `mmap`ped into the VMM's own 64-bit
virtual address space, allowing the VMM and Virtio queues to cast guest physical
addresses (GPAs) directly to host pointers (`*const T` / `*mut T` / `IoSlice`).

When `vmm-runner` runs inside `wasm32-wasip2`:
1. **32-bit Wasm vs. 64-bit Host Virtual Addresses**: Wasm uses a 32-bit linear
   memory (`usize` is 32 bits), whereas host `mmap` addresses (`hva`) for
   `KVM_SET_USER_MEMORY_REGION` are 64-bit host addresses. `MemPages::addr()`
   and `VmMemory::mem_map()` therefore pass HVAs as opaque `u64` values rather
   than `usize`.
2. **Explicit Copy Access (`MemPages::read` / `MemPages::write`)**: Wasm code
   cannot dereference host virtual addresses. Instead, `RamBus` and
   `SplitQueue` read and write guest RAM via the `mem-pages` WIT resource.
   `WasmMemPages` caches `addr: u64` and `size: usize` locally inside Wasm so
   address-range lookups in `RamBus` require zero host calls, and only actual
   data reads/writes cross the WIT boundary:

```text
+-----------------------------------+       +-----------------------------------+
|     vmm-runner (wasm32-wasip2)    |       |       vmm-host (x86_64 host)      |
|                                   |       |                                   |
|  SplitQueue / VirtioDevice        |       |  HostMemPages (mmap region)       |
|   1. Read AvailRing & Desc table  |       |                                   |
|      via RamBus -> MemPages::read | ----> |   memcpy from host mmap -> Vec    |
|   2. Populate Descriptor:         |       |                                   |
|      - readable: Vec<Vec<u8>>     |       |                                   |
|      - writable: Vec<Vec<u8>>     |       |                                   |
|   3. Device processes buffers     |       |                                   |
|      (e.g. blk pread/pwrite or    |       |                                   |
|       net tap.read / tap.write)   |       |                                   |
|   4. Write back writable buffers  |       |                                   |
|      & UsedRing via               |       |                                   |
|      RamBus -> MemPages::write    | ----> |   memcpy from Vec -> host mmap    |
|   5. Trigger MSI-X / INTx IRQ     | ----> |   ioctl(KVM_SIGNAL_MSI / IRQFD)   |
+-----------------------------------+       +-----------------------------------+
```

3. **Platform-Independent Non-Blocking I/O Errors**: Linux `EAGAIN` (`errno 11`)
   differs from WASI `EAGAIN` (`errno 6`). For non-blocking `Tap` I/O,
   `wit/vmm.wit` defines an explicit `variant io-error { would-block, interrupted, other(string) }`
   so `ErrorKind::WouldBlock` is preserved across the host/Wasm boundary when
   draining Virtio RX/TX queues.

---

## 4. Threading & Event-Driven Execution Model

WASI Preview 2 components execute single-threaded and do not support spawning
threads inside Wasm. However, a multi-vCPU VM with asynchronous serial and
network I/O is inherently concurrent: all vCPUs must run in parallel inside
`ioctl(KVM_RUN)` while host `stdin` and TAP sockets are monitored for incoming
bytes/packets.

To solve this cleanly:
- **All blocking concurrency lives in `vmm-host`**, which spawns:
  - One native thread per vCPU (`vcpu_0` .. `vcpu_{N-1}`) that blocks in
    `ioctl(KVM_RUN)` and waits on a per-vCPU `Condvar` while `vmm-runner`
    handles its exit.
  - One native I/O poller thread (`vmm_io_poll`) running `mio::Poll::poll` over
    the host serial `stdin` and any registered `HostTap` file descriptors.
- **All device state and emulation live single-threaded in `vmm-runner`**, which
  drives the entire VM from a single event loop (`Board::run_event_loop`):

```text
vmm-host (Native Threads)                          vmm-runner (Single Wasm Thread)
=========================                          ===============================

[vcpu_0 thread] -- ioctl(KVM_RUN) --+
   (waits on Condvar for VmEntry)   |
                                    |
[vcpu_1 thread] -- ioctl(KVM_RUN) --+--> [mpsc::channel]
   (waits on Condvar for VmEntry)   |          |
                                    |          |  vm.next_event()
[vmm_io_poll]   -- mio::Poll -------+          +-----------------> Board::run_event_loop()
  (stdin, tap)                                                       |
                                                                     |-- VmEvent::VcpuExit { id, exit }
                                                                     |     Emulate PIO / MMIO / Shutdown
                                      vm.resume_vcpu(id, VmEntry)    |     (Serial, PCI, Virtio notify)
[vcpu_X Condvar] <---------------------------------------------------+
                                                                     |-- VmEvent::SerialInput
                                                                     |     serial.handle_input()
                                                                     |     (read stdin -> RX FIFO -> IRQ)
                                                                     |
                                                                     +-- VmEvent::Poll(PollEvent)
                                                                           pci_bus.handle_poll_event()
                                                                           (TAP <-> VirtQueue -> MSI-X)
```

---

## 5. Binary Size Analysis: `vmm-host-wasm` (~12 MB) vs. `vmm-host-cwasm` (~2.9 MB)

With default `wasmtime` features and runtime JIT compilation, a statically
linked `x86_64-unknown-linux-musl` release build of the host was originally
**18.28 MB** (despite `opt-level = 3`, `lto = "fat"`, and `strip = true`).

By stripping unused `wasmtime` / `wasmtime-wasi` features and offering both an
in-process compiler host (`vmm-host-wasm`) and an Ahead-of-Time (AOT) runtime
host (`vmm-host-cwasm`), we provide two deployment options:

- **The "Safe" Pair (`./run-vm.sh --wasm`)**:
  - `vmm-host-wasm` (**~12.4 MB**) + `vmm-runner.wasm` (**~655 KB**)
  - Embeds Wasmtime's Cranelift compiler; validates and compiles the portable
    `.wasm` component from scratch in-process at startup (`Component::from_file`).
- **The "Small" Pair (`./run-vm.sh --cwasm`)**:
  - `vmm-host-cwasm` (**~2.9 MB**) + `vmm-runner.cwasm` (**~1.8 MB**)
  - Excludes Cranelift from the host binary; loads the precompiled `.cwasm`
    artifact (`Component::deserialize_file`), reducing the host binary size by
    **84.5%** and making startup instantaneous.

### 5.1 ELF Section Breakdown Across Host Variants

Inspecting `size -A` on the static `x86_64-unknown-linux-musl` release binaries:

| ELF Section | Initial Default JIT | `vmm-host-wasm` ("Safe" JIT) | `vmm-host-cwasm` ("Small" AOT) | Contents |
| :--- | ---: | ---: | ---: | :--- |
| `.text` | 14.38 MB | **9.79 MB** | **2.21 MB** | Machine code (Wasmtime runtime, WASI p2 host, KVM wrapper, plus Cranelift in `-wasm`) |
| `.rodata` | 1.83 MB | **1.00 MB** | **0.16 MB** | Read-only data and ISA/lookup tables |
| `.eh_frame` + `.eh_frame_hdr` | 1.30 MB | **0.95 MB** | **0.19 MB** | Unwind tables for Wasm trap handling and stack unwinding |
| `.rela.dyn` + `.data.rel.ro` | 0.75 MB | **0.65 MB** | **0.25 MB** | Static-PIE relocation tables and vtables |
| `.data` + `.bss` + other | 0.02 MB | **0.02 MB** | **0.02 MB** | Mutable globals and metadata |
| **Total** | **18.28 MB** | **12.41 MB** | **2.97 MB (2.83 MiB)** | |

### 5.2 What Contributes to the Size—and How Each Optimization Helps

The KVM/VMM-specific code in `vmm-host/src/` is only ~1,800 lines of Rust and
accounts for **< 200 KB** of the binary. The size reductions come from four
optimizations:

1. **Minimal `wasmtime` & `wasmtime-wasi` Feature Set (applied to both hosts, ~4 MB saved)**:
   - Both `wasmtime` and `wasmtime-wasi` are configured with
     `default-features = false`:
     - `wasmtime` enables only `["runtime", "component-model", "std"]` (plus
       `["cranelift"]` for `vmm-host-wasm`), dropping `wat`, `gc` (`gc-drc`,
       `gc-copying`), `profiling`, `coredump`, `addr2line` + `gimli`,
       `demangle`, `cache` + `zstd`, `parallel-compilation`, `async`, and
       `compile-time-builtins` (`wit-parser`, `wit-component`, `wasm-compose`).
     - `wasmtime-wasi` enables only `["p2"]`, dropping WASI Preview 1 (`p1` and
       `wiggle`).
2. **Custom WASI Linker Without `wasi:sockets` (applied to both hosts, ~1 MB saved)**:
   - `vmm-runner` uses host TAP devices (`vmm:host/api.tap`) for guest
     networking and never uses WASI TCP/UDP sockets or DNS lookup.
   - Instead of calling `wasmtime_wasi::p2::add_to_linker_sync` (which registers
     `wasi:sockets` and pulls in `url`, `idna`, and `icu_normalizer` /
     `icu_properties` Unicode data tables), `vmm-host` registers only
     `wasi:clocks`, `wasi:filesystem`, `wasi:random`, `wasi:cli`, and `wasi:io`
     in `add_wasi_without_sockets_to_linker`, allowing LTO (`lto = "fat"`) to
     dead-code-eliminate the entire `wasi:sockets` and ICU/IDNA stack.
3. **External Component Artifacts (applied to both hosts, ~670 KB `.rodata` saved)**:
   - Instead of embedding a duplicate copy of the component in `.rodata` via
     `include_bytes!`, `vmm-host-wasm` loads `vmm-runner.wasm` and
     `vmm-host-cwasm` loads `vmm-runner.cwasm` from disk.
4. **Ahead-of-Time Precompilation (applied to `vmm-host-cwasm`, ~9.4 MB saved)**:
   - [`vmm-host/build.rs`](vmm-host/build.rs) uses `wasmtime` (with `cranelift`
     in `[build-dependencies]`) to AOT-precompile `vmm-runner.wasm` into
     `vmm-runner.cwasm` (~1.8 MB) during `cargo build`.
   - `vmm-host-cwasm` is compiled without the `compiler` (`wasmtime/cranelift`)
     feature and loads `vmm-runner.cwasm` directly via
     `unsafe { Component::deserialize_file(&engine, component_path) }`,
     eliminating the entire Cranelift compiler backend (`cranelift-codegen`,
     `cranelift-frontend`, `cranelift-assembler-x64`, `regalloc2`) from the host
     binary.
