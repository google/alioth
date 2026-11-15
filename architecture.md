# WASM VMM Architecture

WASM VMM (`wasm-vmm` branch) refactors a virtual machine monitor into **two
isolated WebAssembly guest modules** connected across shared Guest RAM and a
lock-free shared-memory bridge (`BridgeShm`):

1. **`vmm-core`** (`wasm32-unknown-unknown`, `#![no_std] + alloc`, zero WASI):
   Sandboxed virtual motherboard, guest RAM layout, kernel/initrd boot loaders,
   ACPI table generation, PCIe bus, modern VirtIO PCI transport, `virtio-iommu`
   PCI front-end, PCI passthrough configuration space virtualization, emulated
   `IoApic`, serial UART, and fallback MMIO instruction decoder. Driven as
   synchronous, non-blocking event handlers by a privileged core host running
   either in userspace over KVM or directly in Ring 0.
2. **`vmm-io`** (`wasm32-wasip1`): Userspace device I/O plane responsible for
   `vm.toml` parsing, opening boot payloads and host backends, VirtIO
   `SplitQueue` descriptor-ring traversal over shared Guest RAM, `virtio-blk`,
   `virtio-net`, `virtio-iommu` domain/mapping tables, and serial console I/O.

Latency-critical or privilege-requiring primitives — vCPU world switches,
Stage-2 guest-physical page tables, virtual local interrupt/timer delivery, fast
virtqueue doorbell matching, and physical IOMMU + MSI-X wiring — remain native
in the host. Every complex stateful parser, device state machine, and descriptor
walker runs inside WebAssembly.

Crucially, **a single byte-identical `vmm-core.wasm` and a single byte-identical
`vmm-io.wasm`** run unmodified across every supported host OS and privilege ring.

---

## 1. System Overview & Build Artifacts

```text
+======================================================================================+
| Userspace I/O Plane (Ring 3)                                                         |
|  Host: `vmm-io-host-{cwasm,wasm}` (Linux)  |  `motor-io-host-{cwasm,wasm}` (Motor OS)|
|  Guest: `vmm-io.{cwasm,wasm}` (`wasm32-wasip1`, 0 FP/SIMD)                           |
|   - Parses `vm.toml`, opens kernel/initrd, disk images, network backends, console    |
|   - Walks VirtIO `SplitQueue` rings in shared Guest RAM (`EndpointDmaView` / IOMMU)  |
+==========================================|===========================================+
                                           |
                   Zero-Copy Shared Guest RAM + `BridgeShm` (`#[repr(C)]`)
               Lock-Free `core_to_io` / `io_to_core` Rings + OS Wait/Wake
                                           |
+==========================================|===========================================+
| Hypervisor Core Plane (Ring 3 over KVM, or Ring 0 In-Kernel)                         |
|  Host: `vmm-core-host-{cwasm,wasm}` (Linux Ring 3 KVM)                               |
|     |  `tests/kernel` (`target/test-guest/kernel`, Motor OS Ring 0)                  |
|     |  `vmm-core-kmod` (`target/airlock/airlock.ko`, Linux Ring 0)                   |
|                                                                                      |
|  +--------------------------------------------------------------------------------+  |
|  | `vmm-core.{wasm,cwasm}` / `vmm-core-motor.cwasm` (`#![no_std]`, 0 WASI, 0 FP)  |  |
|  |  - Board init, Guest RAM layout, Linux & ELF/PVH loaders, ACPI (+ `VIOT`)      |  |
|  |  - PCIe bus, VirtIO PCI transport + MSI-X, `PassthroughPciDev`, UART, `IoApic` |  |
|  |  - Per-vCPU `VcpuCommPage` array + multi-instance `SharedMemory` workers       |  |
|  +-------------------------+----------------------------------+-------------------+  |
|          `VmmHostCore`     |                                  | `VmmCoreBridge`      |
|        (`"vmm"` imports)   v                                  v (`"vmm_bridge"`)     |
|  +------------------------------------------+  +----------------------------------+  |
|  | Native Hypervisor & Passthrough Backend  |  | Core <-> IO Bridge Driver        |  |
|  |  - vCPU run loop, Stage-2 MMU, vLAPIC    |  |  - Boot payloads & RAM slot map  |  |
|  |  - Fast Doorbell Table (0 Wasm calls) ---+--+--> pushes `VirtioNotify`         |  |
|  |  - IOMMU domains, BAR MMIO, hardirq MSI  |  |  - Direct MSI-X IRQ route table  |  |
|  +------------------------------------------+  +----------------------------------+  |
+======================================================================================+
```

### Crate & Build Artifact Map

| Directory / Crate      | Target & Artifact(s)          | Privilege & Role                        |
|------------------------|-------------------------------|-----------------------------------------|
| `vmm-core/`            | `wasm32-unknown-unknown` ->   | Wasm guest (Core): `#![no_std] + alloc` |
|                        | `vmm-core.wasm`,              | chipset, PCIe, boot loader, passthrough |
|                        | `vmm-core.cwasm`,             | PCI config, and exit handlers           |
|                        | `vmm-core-motor.cwasm`        |                                         |
| `vmm-io/`              | `wasm32-wasip1` ->            | Wasm guest (I/O): userspace config      |
|                        | `vmm-io.wasm`,                | parser, `SplitQueue` walker,            |
|                        | `vmm-io.cwasm`,               | `virtio-{blk,net,iommu}`, and console   |
|                        | `target/motor/vmm-io.cwasm`   |                                         |
| `derive-layout/`       | Host proc-macro plugin        | Build-time: compile-time struct layout  |
|                        |                               | and offset derivation                   |
| `vmm-core-host/`       | `x86_64-unknown-linux-musl`   | Linux Ring 3: `/dev/kvm` core host;     |
|                        | -> `vmm-core-host-cwasm`,     | `build.rs` also precompiles `.cwasm`    |
|                        | `vmm-core-host-wasm`          | images                                  |
| `vmm-io-host/`         | `x86_64-unknown-linux-musl`   | Linux Ring 3: I/O host driving either   |
|                        | -> `vmm-io-host-cwasm`,       | `vmm-core-host-*` (KVM) or              |
|                        | `vmm-io-host-wasm`            | `/dev/airlock` (`--airlock`)            |
| `vmm-core-kmod/`       | `x86_64-unknown-none` +       | Linux Ring 0: out-of-tree,              |
|                        | Kbuild -> `airlock.ko`,       | KVM-independent Linux kernel VMM        |
|                        | `bzImage` (`target/airlock/`) | hosting `vmm-core-motor.cwasm`          |
| `tests/kernel/`        | `x86_64-unknown-none` ->      | Motor OS Ring 0 (with `tests/kloader` & |
|                        | `kernel`, `kloader`           | `tests/moto-sys`): microkernel          |
|                        | (in `target/test-guest/`)     | embedding Ring-0 VMM, `#![no_std]`      |
|                        |                               | Wasmtime, and `vmm-core-motor.cwasm`    |
| `tests/motor-io-host/` | `x86_64-unknown-motor` ->     | Motor OS Ring 3: I/O host (`motor-fs`   |
|                        | `motor-io-host-{cwasm,wasm}`  | disk, `IpDevice` virtual Ethernet,      |
|                        | (in `target/motor/`)          | console)                                |
| `tests/test-init/`     | `x86_64-unknown-motor` ->     | Motor OS Ring 3: minimal Wasmtime-free  |
|                        | `target/test-guest/test-init` | `initrd` bootstrap launcher for         |
|                        |                               | diskless passthrough/smoke VMs          |

---

## 2. Core / I/O Split & Shared-Memory Bridge (`BridgeShm`)

### 2.1 Plane Responsibilities

- **`vmm-core` (Chipset & Control Plane)**:
  - Constructs the guest physical memory map, loads Linux kernel images or direct
    ELF/PVH binaries + `initramfs`, sets initial BSP/AP processor state, and
    generates ACPI tables (including `MCFG` for PCIe and `VIOT` when
    `virtio-iommu` is enabled).
  - Emulates the PCIe bus, VirtIO PCI transport capabilities (`CommonCfg`,
    `NotifyCfg`, `IsrStatus`, `DeviceCfg`, and `MsixCap`), `PassthroughPciDev`
    configuration headers, `IoApic` interrupt routing, and legacy serial UART.
  - Translates pin interrupts (such as UART) inside its emulated `IoApic` into
    standard message-signaled interrupts (`VmmHostCore::inject_msi`), keeping
    the host interrupt interface uniform across emulated, VirtIO, and
    passthrough devices.
  - Provides a float-free fallback MMIO instruction decoder so minimal Ring-0
    hosts can forward raw Stage-2 page-fault bytes (`VmExit::MmioFault`) while
    hosts that pre-decode MMIO (`HostCaps::DECODED_MMIO`) pass `VmExit::Mmio`.

- **`vmm-io` (Data & Backend Plane)**:
  - Parses `vm.toml`, opens kernel/initrd files, disk images, network TAP
    interfaces, and serial terminals, and publishes initial VM metadata into
    `BridgeShm` before the core host starts `vmm-core`.
  - Owns VirtIO `SplitQueue` descriptor-ring traversal directly over shared
    Guest RAM, along with `virtio-blk`, `virtio-net`, serial RX/TX framing, and
    `virtio-iommu` address-space tables (`IommuState`).

Keeping `SplitQueue` in `vmm-io` avoids bounce buffers on the core plane and
allows asynchronous I/O completions (such as incoming network packets arriving
while all vCPUs are executing in guest mode or halted) to write Guest RAM and
trigger interrupts without pausing a vCPU to run `vmm-core`.

### 2.2 Narrow Host Import Interfaces

Each Wasm module communicates with its host solely through typed host-import
traits:

- **`vmm-core` imports**:
  - `"vmm"` (`VmmHostCore` in `vmm-core/src/host.rs`): pure virtualization and
    hardware hooks — host capability discovery, vCPU state setup & wake,
    memory-object allocation and Stage-2 GPA mapping (`gpa_map` / `gpa_unmap`),
    MSI injection (`inject_msi`), fast doorbell registration
    (`register_doorbell` / `unregister_doorbell`), and narrow PCI passthrough
    operations (`pci_*`). Contains zero VirtIO or UART concepts.
  - `"vmm_bridge"` (`VmmCoreBridge`): reads boot metadata/payloads, publishes
    virtqueue parameters and resolved MSI-X routes into `BridgeShm`, and
    exchanges control messages with `vmm-io`.
- **`vmm-io` imports**:
  - `"vmm"` (`IoHost` + `GuestMemAccess` in `vmm-io/src/host.rs`): block
    read/write/flush, TAP read/write/offload/poll registration, serial console
    I/O, VM configuration registration, `io_next_event()`, zero-copy Guest RAM
    reads/writes, and interrupt/shutdown signaling.

### 2.3 `BridgeShm` & Zero-Wasm-Call Fast Paths

Bulk memory and control signaling are separated across `BridgeShm`
(`vmm-core/src/host.rs` `abi::BridgeShm`):

1. **Zero-Copy Shared Guest RAM & Boot Payloads**:
   Guest RAM and boot images are backed by shared memory objects mapped into
   both the I/O host and the core host (and pinned into Stage-2 page tables for
   the guest). `io_guest_mem_read` and `io_guest_mem_write` copy directly
   between `vmm-io` linear memory and Guest RAM via `BridgeShm::ram_slots` with
   zero IPC copies.
2. **Lock-Free Control Rings**:
   `BridgeShm` is a `#[repr(C)]` shared header holding `ShmBootInfo`, VirtIO and
   passthrough device descriptors, RAM slot descriptors, queue configurations,
   `ShmDeviceMsixRouting`, a multi-producer/single-consumer `core_to_io` ring
   (`VirtioNotify`, `VirtioStart`, `VirtioReset`, `SerialTx`, `Shutdown`), and a
   single-producer/single-consumer `io_to_core` ring (`VirtioIrq`, `SerialRx`,
   `RequestShutdown`), paired with OS wait/wake handles.
3. **Zero-Wasm-Call Doorbell & Interrupt Fast Paths**:
   - **Guest -> I/O (`QueueNotify`)**: When a guest enables a VirtIO PCI BAR,
     `vmm-core` registers each queue's notify address via `register_doorbell`.
     Subsequent guest doorbell writes are matched natively by the core host
     (`ioeventfd` on Linux KVM, or the Ring-0 `DoorbellTable` on Motor OS and
     `airlock.ko`), enqueueing `VirtioNotify` and waking `vmm-io` with **zero
     `vmm-core` Wasm calls**.
   - **I/O -> Guest (`VirtioIrq`)**: Whenever a guest updates a device's MSI-X
     table, `vmm-core` publishes the resolved `(msi_addr, msi_data)` entry into
     `BridgeShm::irq_routes`. When `vmm-io` signals `io_virtio_irq`, the core
     host reads `irq_routes` and injects the MSI directly into the target vCPU
     with **zero `vmm-core` Wasm calls**.

---

## 3. WebAssembly Execution Model

### 3.1 Execution Profiles & `VcpuCommPage`

- **`vmm-core` (Passive, Host-Driven)**:
  Compiled for `wasm32-unknown-unknown` with `#![no_std] + alloc` and zero WASI
  imports. `vmm-core` never blocks or spawns threads; the host owns vCPU threads
  and calls non-blocking exports (`vmm_init`, `vmm_on_vcpu_exit`,
  `vmm_on_bridge_rx`, `vmm_reset`). Rather than making per-register FFI calls on
  every VM exit, the host and `vmm-core` exchange architectural exit/entry state
  in place through a cache-line-aligned `[VcpuCommPage; num_cpus]` array inside
  `vmm-core` linear memory.
- **`vmm-io` (Event-Loop Driven)**:
  Compiled for `wasm32-wasip1`. Its `vmm_io_run()` export initializes devices
  from `vm.toml` and runs a single-threaded event loop over `io_next_event()`
  until VM shutdown.

### 3.2 Multi-vCPU Concurrency in `#![no_std]` `vmm-core`

To service slow-path VM exits across multiple vCPUs concurrently without WASI
threads, the core host instantiates `num_cpus + 1` lightweight Wasmtime
`(Store, Instance)` workers (`0..num_cpus` for vCPUs plus slot `num_cpus` for
`vmm_on_bridge_rx`) that all import the **same** `wasmtime::SharedMemory`
(`("env", "memory")`):

- Each worker is assigned a disjoint shadow stack (`vmm_stack_top(slot_id)`) via
  `vmm_bind_vcpu`.
- `vmm-core` is linked with `--import-memory --shared-memory`, passive data
  segments, and WebAssembly atomics (`-Z build-std=core,alloc`), so worker
  instantiation preserves initialized `.data`/`.bss` state and `core::sync::atomic`
  compiles to native atomic instructions.
- Shared chipset structures (`PciBus`, `IoApic`, UART, VirtIO PCI config, heap
  allocator) are guarded by short-hold spinlocks.

### 3.3 `.wasm` (JIT) vs. `.cwasm` (AOT) & Ring-0 Invariants

1. **Dual Host Packaging (`-wasm` vs. `-cwasm`)**:
   Userspace hosts (`vmm-core-host`, `vmm-io-host`, `motor-io-host`) build in
   two flavors: `-wasm` (includes Cranelift to JIT `.wasm` modules at startup)
   and `-cwasm` (omits the compiler, loading precompiled `.cwasm` artifacts via
   `Module::deserialize` for minimal footprint and instant startup).
2. **Ring-0 Bare-Metal AOT Image (`vmm-core-motor.cwasm`)**:
   `vmm-core-host/build.rs` also precompiles `vmm-core.wasm` into
   `vmm-core-motor.cwasm` targeting `x86_64-unknown-none` with explicit software
   bounds checks (`signals_based_traps(false)` and zero virtual guard pages).
   Wasm traps unwind cleanly in Rust without relying on kernel page-fault fixup
   tables, and Ring-0 hosts map code sections `R+X` and data sections `R+W`
   (strict `W^X`). Both Motor OS Ring 0 and Linux `airlock.ko` load this **exact
   same `vmm-core-motor.cwasm` file**.
3. **Zero Floating-Point / SIMD Invariant**:
   Both `vmm-core` and `vmm-io` are compiled with floating-point and SIMD
   disabled and verified by machine-code disassemblers (`verify_no_fp`) to emit
   zero floating-point or vector instructions. Ring-0 hosts can therefore invoke
   `vmm-core` directly on VM exits without saving or restoring FPU/vector state.

---

## 4. IOMMU Architecture

WASM VMM implements IOMMU isolation at two levels that compose cleanly in nested
topologies:

1. **Guest-Facing Emulated `virtio-iommu` (`iommu = true` in `vm.toml`)**:
   - Split across `vmm-core` and `vmm-io`: `vmm-core` exposes a PCI
     `virtio-iommu` device at `00:01.0` and emits an ACPI `VIOT` table
     advertising IOMMU translation for guest PCI endpoints (`00:02.0+`), while
     `vmm-io` implements `IommuState` (`vmm-io/src/iommu.rs`), handling
     `ATTACH`, `DETACH`, `MAP`, `UNMAP`, and `PROBE` requests on the request
     virtqueue.
   - Every emulated VirtIO device performs guest RAM accesses through an
     endpoint-scoped `EndpointDmaView`, enforcing IOVA-to-GPA translation and
     read/write permissions on all descriptor rings and DMA buffers.
   - Because standard `virtio-iommu` + ACPI `VIOT` is used, L1 guests work
     identically under L0 WASM VMM and external VMMs such as Cloud Hypervisor
     (`--vmm chv`).

2. **Host-Side Ring-0 IOMMU Enforcement for Device Passthrough**:
   - Before enabling PCI Bus Mastering on any assigned endpoint, a Ring-0 core
     host attaches the physical BDF to a dedicated IOMMU protection domain
     populated solely with that VM's pinned Guest RAM (`GPA -> HPA`), tearing
     the domain down and resetting the function on VM exit.
   - **Motor OS Ring 0** includes a native kernel `VirtioIommuDriver`
     (`tests/kernel/src/vmm/virtio_iommu.rs`) that parses ACPI `VIOT`, claims
     `00:01.0` before userspace starts, and issues synchronous `ATTACH` / `MAP`
     / `UNMAP` / `DETACH` commands.
   - **Linux Ring-0 `airlock.ko`** uses the Linux kernel's standard IOMMU
     subsystem (`iommu_paging_domain_alloc`, `iommu_attach_device`, `iommu_map`,
     `iommu_unmap`), working transparently over paravirtual `virtio-iommu` in
     nested VMs as well as bare-metal hardware IOMMUs.

---

## 5. VFIO-Style PCI Device Passthrough

PCI endpoints can be assigned directly to a VM via `pci = [{ bdf = "0000:00:03.0" }]`
in `vm.toml` without a userspace VFIO proxy:

1. **Cross-OS Config Virtualization (`PassthroughPciDev` in `vmm-core`)**:
   `vmm-core/src/hw/pci/passthrough.rs` implements all OS-independent PCI
   configuration space virtualization against narrow `VmmHostCore::pci_*`
   imports:
   - Virtualizes the Type-0 header, PCI Command register, and guest BAR sizing
     and relocation so guest BAR reprogramming updates Stage-2 GPA mappings
     rather than physical host BAR registers.
   - Sanitizes the PCI capability list: preserves safe capabilities (such as
     VirtIO vendor capabilities and MSI-X) while hiding unsafe backdoor
     capabilities such as `VIRTIO_PCI_CAP_PCI_CFG` (which would otherwise allow
     config-space window accesses to bypass MMIO traps).
   - Applies `VirtioCommonIommuFilter` on VirtIO passthrough functions so an L2
     guest without its own virtual IOMMU negotiates direct physical-address DMA
     cleanly while the L1 Ring-0 IOMMU translates `L2 GPA -> HPA` transparently.

2. **4 KiB BAR Page Carving (Direct MMIO vs. Trapped Control Pages)**:
   Each assigned MMIO BAR is partitioned at 4 KiB page granularity when mapped
   into the guest:
   - **Direct Stage-2 MMIO pages**: Pages containing device data/notify regions
     (such as VirtIO `NotifyCfg` doorbells and `IsrStatus`) are mapped directly
     into the guest's Stage-2 page tables as uncached device memory. Guest
     doorbell writes go straight to the underlying device with **zero L1 Ring-3
     exits and zero L1 Wasm calls**.
   - **Trapped control pages**: Pages overlapping the physical MSI-X Table/PBA
     or filtered VirtIO `CommonCfg` remain unmapped in Stage-2 so guest accesses
     trap to `PassthroughPciDev` in `vmm-core`. Any non-sensitive sub-ranges
     sharing a 4 KiB page with a trapped structure are forwarded by `vmm-core`
     through `pci_bar_read` / `pci_bar_write`.

3. **Ring-0 MSI-X Interrupt Forwarding**:
   Guest writes to the virtual MSI-X Table update `PassthroughPciDev`, which
   passes resolved guest `(msi_addr, msi_data)` vectors to
   `VmmHostCore::pci_configure_msix`. Physical MSI-X interrupts arrive in Ring 0
   and are injected directly into the target guest vCPU without bouncing through
   Ring 3 or Wasm.

4. **Partial vs. Full All-PCI Passthrough (Zero Ring-3 VM-Exit Guarantee)**:
   - *Partial passthrough*: L1 keeps its own block device (and optional
     management NIC) while passing dedicated PCI devices (e.g. `virtio-net`)
     straight to L2 alongside emulated `vmm-io` devices.
   - *Full all-PCI passthrough*: L1 boots from an in-memory `initramfs`/`initrd`
     and passes **all** PCI devices (`virtio-blk` + `virtio-net`) to L2 with
     zero emulated VirtIO devices (`virtio_count == 0`). In steady state, **all
     disk and network I/O runs with zero VM-exits to L1 Ring-3 userspace**: DMA
     transfers flow directly between the device and IOMMU-mapped L2 RAM,
     doorbells hit direct Stage-2 MMIO mappings, and MSI-X interrupts are
     injected inside Ring 0.

---

## 6. Implemented Hosts

### 6.1 Hypervisor Core Hosts (`vmm-core-host` Implementations)

1. **Linux Ring-3 KVM Host (`vmm-core-host/`)**
   - *Artifacts*: `vmm-core-host-cwasm`, `vmm-core-host-wasm`.
   - Spawned as a child process by `vmm-io-host`, inheriting `BridgeShm` and
     Guest RAM `memfd`s plus `eventfd` descriptors.
   - Implements `VmmHostCore` over `/dev/kvm` using `KVM_SET_USER_MEMORY_REGION`,
     per-vCPU userspace threads (`KVM_RUN`), split irqchip MSI delivery
     (`KVM_SIGNAL_MSI`), and `KVM_IOEVENTFD` fast doorbells.

2. **Motor OS Ring-0 Hypervisor (`tests/kernel/src/vmm/`)**
   - *Artifacts*: `target/test-guest/kernel` and `target/test-guest/kloader`
     (built with `tests/moto-sys/` via `./tests/kernel/build.sh`).
   - Compiled directly into the Motor OS microkernel with `#![no_std]` Wasmtime,
     executing `vmm-core-motor.cwasm` in `W^X` kernel virtual memory.
   - Implements Stage-2 page tables over pinned shared pages, kernel vCPU
     threads, virtual local interrupt/timer and paravirtual clock emulation,
     Ring-0 `DoorbellTable`, `VirtioIommuDriver`, and Ring-0 PCI/MSI-X
     passthrough (`pci_host.rs`).
   - Exposed to Ring-3 processes holding `CAP_VMM` via Motor OS kernel object
     and wait/wake syscalls (`SysObj::create("vmm:...")`, `SysCpu::wait`,
     `SysCpu::wake`).

3. **Linux Ring-0 Kernel Module (`vmm-core-kmod/`)**
   - *Artifacts*: `target/airlock/airlock.ko` (plus optional out-of-tree L1 test
     kernel `target/airlock/bzImage`, built via `./vmm-core-kmod/build.sh`).
   - Hybrid out-of-tree module combining a `#![no_std] + alloc` Rust `staticlib`
     (`vmm-core-kmod/rust/`, linking the same `#![no_std]` Wasmtime crate graph
     as Motor OS) with a thin C Kbuild shim (`vmm-core-kmod/c/`) wrapping Linux
     memory allocation, `vmap` (`W^X`), `pin_user_pages_fast`, `kthread`s,
     `eventfd` wake/poll hooks, `iommu_domain`, `pci_dev`, and MSI-X `request_irq`
     handlers.
   - **KVM-independent and KVM-coexisting**: requires zero `kvm.ko` symbols,
     runs on kernels with `CONFIG_KVM=n` or `kvm` unloaded, and reference-counts
     per-CPU hardware virtualization enablement so it can also run concurrently
     while `kvm` is loaded (`--with-kvm-loaded`).
   - Exposes `/dev/airlock` (`AIRLOCK_IOC_CREATE_VM`) and executes the **exact
     same `vmm-core-motor.cwasm`** binary used by Motor OS Ring 0.

### 6.2 Userspace I/O Hosts (`vmm-io-host` Implementations)

1. **Linux Ring-3 `vmm-io-host` (`vmm-io-host/`)**
   - *Artifacts*: `vmm-io-host-cwasm`, `vmm-io-host-wasm`.
   - Hosts `vmm-io.{cwasm,wasm}` on a `mio::Poll` event loop, providing file
     block I/O (`pread`/`pwrite`/`fsync`), `/dev/net/tun` TAP networking, and
     raw terminal serial I/O (`Ctrl-a` or nested `Ctrl-b` escape).
   - Allocates `BridgeShm` and Guest RAM `memfd`s plus `eventfd`s and attaches
     to **either** Linux core host from the same binary:
     - *Default mode*: spawns `vmm-core-host-{cwasm,wasm}` over `/dev/kvm`.
     - *`--airlock` mode*: opens `/dev/airlock`, loads `vmm-core-motor.cwasm`,
       unbinds/prepares any configured passthrough PCI BDFs via `sysfs`, and
       issues `AIRLOCK_IOC_CREATE_VM` to `airlock.ko` with no Ring-3
       `vmm-core-host` process.

2. **Motor OS Ring-3 `motor-io-host` (`tests/motor-io-host/`)**
   - *Artifacts*: `target/motor/motor-io-host-cwasm`,
     `target/motor/motor-io-host-wasm` (built via `./tests/motor-io-host/build.sh`).
   - Hosts `vmm-io.{cwasm,wasm}` on `x86_64-unknown-motor`, providing `motor-fs`
     disk backends, `MotorIpTap` virtual L2<->L3 Ethernet (in-process ARP/DHCPv4
     and TCP/UDP socket forwarding over Motor OS `sys-io`), raw serial console
     (`Ctrl-b q`), and `SysObj` / `SysCpu` coordination with Motor OS Ring 0.

3. **Motor OS Minimal Initrd Bootstrap (`tests/test-init/`)**
   - *Artifact*: `target/test-guest/test-init`.
   - Lightweight Wasmtime-free Ring-3 launcher used when a diskless `initrd`-only
     Motor OS L1 VM boots a nested VM whose I/O devices are all passed through
     (`virtio_count == 0`, e.g. `run-passthrough-blk-linux.sh`) or runs minimal
     serial-only smoke tests (`run-nested-test-guest.sh`). Unpacks an
     `InitrdBundle` into `BridgeShm` and Guest RAM, invokes
     `SysObj::create("vmm:...")`, and relays serial console I/O.

### 6.3 Host Comparison Summary

| Aspect              | Linux KVM (Ring 3)     | Motor OS (Ring 0)       | `airlock.ko` (Ring 0)   |
|---------------------|------------------------|-------------------------|-------------------------|
| Core Wasm module    | `vmm-core.cwasm` or    | `vmm-core-motor.cwasm`  | `vmm-core-motor.cwasm`  |
|                     | `vmm-core.wasm`        |                         | (byte-identical)        |
| Paired I/O host     | `vmm-io-host-*`        | `motor-io-host-*` or    | `vmm-io-host-*` with    |
|                     | (default KVM mode)     | `test-init`             | `--airlock`             |
| Shared Guest RAM    | Shared `memfd`         | Shared `SysMem` pages   | Shared `memfd` pages    |
|                     | mappings               | pinned in Ring 0        | (`pin_user_pages_fast`) |
| vCPU execution      | Userspace threads      | Ring-0 Motor OS kernel  | Ring-0 Linux `kthread`s |
|                     | calling `KVM_RUN`      | threads                 | (`airlock-vcpu`)        |
| Fast `QueueNotify`  | `KVM_IOEVENTFD` ->     | Ring-0 `DoorbellTable`  | Ring-0 `DoorbellTable`  |
|                     | `eventfd`              | -> `SysObject::wake`    | -> `eventfd_signal`     |
| Direct `VirtioIrq`  | `eventfd` ->           | `SysCpu::wake` ->       | `eventfd` poll wakeup   |
|                     | `KVM_SIGNAL_MSI`       | Ring-0 vLAPIC + IPI     | -> Ring-0 vLAPIC + IPI  |
| Passthrough & IOMMU | Emulated               | Ring-0                  | Linux `iommu_domain` +  |
|                     | `virtio-iommu` (as L0  | `VirtioIommuDriver` +   | `pci_dev` + hardirq MSI |
|                     | host)                  | `pci_host.rs`           |                         |
