# WASM VMM Architecture

WASM VMM splits a type-2 / Ring-0-capable virtual machine monitor (derived from
Alioth v0.2.0) into **two isolated WebAssembly guest modules** communicating
through shared memory and lock-free doorbell rings:

1. **`vmm-core`** (`wasm32-unknown-unknown`, `#![no_std] + alloc`, zero WASI,
   zero FP/SIMD): Sandboxed chipset, CPU/board initialization, PVH/`bzImage`
   loader, ACPI tables, PCIe ECAM bus, Virtio PCI modern transport, 16450 UART,
   `IoApic`, and x86_64 MMIO instruction decoder. Driven synchronously and
   non-blockingly by a privileged hypervisor host (`vmm-core-host` on Linux KVM,
   or `tests/kernel/src/vmm/` in Motor OS Ring 0).
2. **`vmm-io`** (`wasm32-wasip1-threads`, zero FP/SIMD): Userspace device I/O
   plane owning `vm.toml` parsing, boot payload opening, Virtio `SplitQueue`
   descriptor-ring traversal over shared Guest RAM, `virtio-blk`, `virtio-net`,
   and serial console I/O. Hosted in Ring 3 by `vmm-io-host`.

Both Wasm modules compile to portable `.wasm` binaries and AOT-precompiled
`.cwasm` images verified at build and load time to contain **zero floating-point
or SIMD/vector instructions** (`xmm`/`ymm`/`zmm`/`mm`).

---

## 1. System Overview & Responsibility Split

```text
+===================================================================================+
| Userspace I/O Plane (Ring 3: `vmm-io-host` + `vmm-io.{wasm,cwasm}`)               |
|  - Parses `vm.toml`, opens kernel/initrd payloads, disk files, TAP, & serial tty  |
|  - Walks Virtio `SplitQueue` rings directly in shared Guest RAM                   |
|  - Event loop (`mio::Poll` on Linux, `SysCpu::wait` on Motor OS)                  |
+=========================================|=========================================+
                                          |
                 Shared Guest RAM + `BridgeShm` (`#[repr(C)]`)
             Lock-Free `core_to_io` / `io_to_core` Rings + Doorbells
                                          |
+=========================================|=========================================+
| Core Plane (`vmm-core-host` on Linux KVM | `tests/kernel/src/vmm/` in Motor Ring 0)|
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | `vmm-core.{wasm,cwasm}` (`#![no_std] + alloc`, 0 WASI, 0 FP/SIMD)           |  |
|  |  - Board init, Guest RAM layout (`RamBus`), `bzImage` / Xen PVH ELF loader  |  |
|  |  - ACPI (`RSDP`, `XSDT`, `FADT`, `DSDT`, `MADT`, `MCFG`), PCIe ECAM bus     |  |
|  |  - Virtio PCI (`CommonCfg`, `NotifyCfg`, `IsrStatus`, `DeviceCfg`, MSI-X)   |  |
|  |  - 16450 UART (`0x3f8`), `IoApic` (`0xfec0_0000`), x86_64 MMIO decoder      |  |
|  |  - `[VcpuCommPage; num_cpus]` in Wasm `SharedMemory`                        |  |
|  +-----------------------+---------------------------------+-------------------+  |
|        `VmmHostCore`     |                                 | `VmmCoreBridge`      |
|      (`"vmm"` imports)   v                                 v (`"vmm_bridge"`)     |
|  +----------------------------------------+  +---------------------------------+  |
|  | Native Hypervisor Backend              |  | Core <-> IO Bridge Driver       |  |
|  |  - Host-owned vCPU run loop / threads  |  |  - Boot info & payload reads    |  |
|  |  - Stage-2 MMU (`KVM` / NPT / EPT)     |  |  - `core_to_io` / `io_to_core`  |  |
|  |  - VMCS/VMCB + LAPIC + `pvclock`       |  |  - Direct MSI-X IRQ route table |  |
|  |  - Fast Doorbell Table (0 Wasm calls) -+--+-> pushes `VirtioNotify`         |  |
|  +----------------------------------------+  +---------------------------------+  |
+===================================================================================+
```

This split keeps every latency-critical or privilege-requiring primitive in the
native host (world switch, Stage-2 page tables, LAPIC/timer/IPI, and fast
`QueueNotify` doorbell matching) while isolating every complex stateful parser
and device state machine inside Wasm.

---

## 2. Core Plane (`vmm-core` + `VmmHostCore` + `VmmCoreBridge`)

### 2.1 Host-Driven Control Flow & `VcpuCommPage`

`vmm-core` never spawns threads or blocks inside Wasm. The host owns the vCPU
execution loop and invokes `vmm-core` exports strictly as non-blocking handlers
(`vmm-core/src/wasm.rs`):

```rust
extern "C" {
    /// Initialize board, Guest RAM, ACPI, kernel/initrd, and BSP/AP initial state.
    /// Returns Wasm linear memory offset of `[VcpuCommPage; num_cpus]` (or <0 on err).
    pub fn vmm_init() -> i32;

    /// Return configured guest vCPU count (`0` before `vmm_init`).
    pub fn vmm_num_cpus() -> u32;

    /// Return 16-byte-aligned disjoint stack top in `SharedMemory` for worker
    /// `slot_id` (`0..num_cpus` for vCPUs, `num_cpus` for the bridge RX worker).
    pub fn vmm_stack_top(slot_id: u32) -> u32;

    /// Bind worker `Instance[vcpu_id]` after setting its `__stack_pointer` global.
    pub fn vmm_bind_vcpu(vcpu_id: u32, stack_top: u32);

    /// Handle one slow-path exit for `vcpu_id` via `comm_page[vcpu_id]`.
    /// Returns `VmAction` (`0` = Continue, `1` = Shutdown, `2` = Reboot, `<0` = HvError).
    pub fn vmm_on_vcpu_exit(vcpu_id: u32) -> i32;

    /// Drain pending control messages from `vmm-io` (`SerialRx`, `RequestShutdown`).
    pub fn vmm_on_bridge_rx() -> i32;

    /// Reset board and Guest RAM state across a guest reboot.
    pub fn vmm_reset() -> i32;
}
```

Each vCPU exchanges hot register and trap state with `vmm-core` in place through
a cache-line-aligned `VcpuCommPage` in Wasm linear memory (`vmm-core/src/host.rs`),
avoiding per-exit register FFI calls:

```rust
#[repr(C, align(64))]
pub struct VcpuCommPage {
    pub exit: RawVmExit,    // Io, Mmio, MmioFault, Cpuid, MsrRead/Write, Shutdown, Reboot
    pub synced_regs: u32,   // Bitmask of valid architectural fields below
    pub dirty_regs: u32,    // Bitmask of fields modified by Wasm (e.g. GPRs, RIP)
    pub gprs: [u64; 16],    // RAX..R15
    pub rip: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub efer: u64,
    pub cs: RawSegReg,      // Determines 16/32/64-bit instruction decode mode
    pub entry: RawVmEntry,  // None, Io, Mmio, Msr, Shutdown, Reboot, InjectGp
}
```

### 2.2 Core Host Traits (`vmm-core/src/host.rs`)

`vmm-core` imports two narrow modules (`"vmm"` and `"vmm_bridge"`), surfaced in
Rust via `VmmHostCore` and `VmmCoreBridge`:

- **`VmmHostCore`** (pure hardware virtualization, zero Virtio/UART concepts):
  - Capabilities & CPUID: `caps() -> HostCaps`, `supported_cpuids(...)`
  - Cold-path vCPU setup & wake: `vcpu_configure`, `vcpu_get_regs`,
    `vcpu_set_regs` (including `RegId::MpState`), `vcpu_kick`
  - Slotless memory objects & Stage-2 GPA mapping: `mem_alloc`, `mem_free`,
    `mem_read`, `mem_write`, `gpa_map`, `gpa_unmap`
  - Interrupts & fast doorbells: `inject_msi`, `set_gsi_level` (used only when
    `HostCaps::HW_IOAPIC` is advertised), `register_doorbell`,
    `unregister_doorbell`
- **`VmmCoreBridge`** (core side of `BridgeShm`):
  - `boot_info`, `read_payload`, `configure_queues`, `update_irq_route`,
    `send_cmd`, `recv_cmd`

### 2.3 Chipset, Interrupts, Doorbells, & Hybrid MMIO Decoding

1. **In-Wasm `IoApic` (`0xfec0_0000`) & Pure MSI Boundary**:
   `vmm-core` emulates a 24-pin IOAPIC in Rust. Legacy `COM1` (IRQ 4) asserts pin
   4 on `IoApic`, which formats Redirection Table Entry 4 into
   `VmmHostCore::inject_msi(addr, data)` — the exact same primitive used by
   Virtio MSI-X. Linux KVM runs with `KVM_CAP_SPLIT_IRQCHIP`; Ring-0 hosts need
   no in-kernel IOAPIC or 8259 PIC.
2. **Explicit SMP `MpState`**:
   `vmm_init()` configures `BSP = MpState::Runnable` and `APs = MpState::Uninitialized`
   (Wait-for-SIPI), matching `KVM_SET_MP_STATE` and Ring-0 LAPIC `ICR` (`INIT`/`SIPI`)
   state transitions.
3. **Fast `QueueNotify` Doorbells (`register_doorbell`)**:
   When the guest enables a `VirtioPciDevice` BAR, `vmm-core` registers each
   queue's notify address. On Linux (`KVM_IOEVENTFD`) and Motor OS Ring 0 (an
   in-kernel sorted doorbell table checked on NPT/PIO exit), guest `QueueNotify`
   writes enqueue `VirtioNotify` and wake `vmm-io` with **zero Wasm calls**.
4. **Hybrid MMIO Decoding (`VmExit::Mmio` vs. `VmExit::MmioFault`)**:
   Hosts that pre-decode MMIO (`HostCaps::DECODED_MMIO`, e.g., Linux KVM) pass
   `VmExit::Mmio`. Minimal Ring-0 hosts (e.g., Motor OS) pass `VmExit::MmioFault`
   with up to 15 instruction bytes, and `vmm-core` decodes the instruction in
   float-free Rust, updating `comm_page.gprs` and `comm_page.rip` in place.

### 2.4 Concurrent Execution in `#![no_std]` Wasm

To handle slow-path exits across vCPUs in parallel without WASI threads, the
host instantiates `num_cpus + 1` lightweight `(Store, Instance)` workers (`0..num_cpus`
for vCPUs plus `num_cpus` for `vmm_on_bridge_rx`) all importing the **same**
`wasmtime::SharedMemory` (`("env", "memory")`):

1. **Disjoint Shadow Stacks**: Each worker's private `__stack_pointer` (`global[0]`)
   is set to `vmm_stack_top(slot_id)` before any exit or RX call runs.
2. **Passive Data Segments**: Linked with `--import-memory --shared-memory --max-memory=...`
   so instantiating worker instances never overwrites initialized `.data`/`.bss`.
3. **Hardware Atomics**: Built with `+atomics,+mutable-globals` and
   `-Z build-std=core,alloc` so `core::sync::atomic` emits real `LOCK` instructions.
4. **Non-Blocking Synchronization**: Shared devices (`PciBus`, `IoApic`, `Serial`,
   Virtio PCI config, global allocator) use short-hold `spin::Mutex` locks.

---

## 3. I/O Plane (`vmm-io` + `IoHost`)

`vmm-io` (`vmm-io/src/host.rs`, `vmm-io/src/wasm.rs`) imports the `"vmm"` module
from `vmm-io-host` (`IoHost` + `GuestMemAccess`):

- **Device backends**:
  - `Tap`: `tap_open`, `tap_detected_offload`, `tap_enable_offload`,
    `tap_register`, `tap_deregister`, `tap_read`, `tap_write`, `tap_close`
  - `BlockBackend`: `blk_open`, `blk_read_at`, `blk_write_at`, `blk_flush`,
    `blk_close`
  - `SerialConsole`: `serial_open`, `serial_write_byte`, `serial_read_input`,
    `serial_shutdown`, `serial_close`
- **Cross-plane bridge & DMA**:
  - `io_register_vm_config(boot_cfg, virtio_devs)`
  - `io_next_event() -> IoBridgeEvent` (`VirtioStart`, `VirtioNotify`,
    `VirtioReset`, `Poll`, `SerialInput`, `SerialTx`, `Shutdown`)
  - `io_guest_mem_read(gpa, dst)` / `io_guest_mem_write(gpa, src)`
  - `io_virtio_irq(dev, kind)` / `io_serial_push_rx(bytes)` / `io_request_shutdown()`

### Why `SplitQueue` Lives in `vmm-io`
- Keeps `vmm-core` compact and free of descriptor-ring traversal or bounce buffers.
- Allows asynchronous device arrivals (such as incoming network packets when no
  vCPU is in a VM exit) to pop RX descriptors, write Guest RAM, and inject MSI-X
  independently on the I/O plane.
- Whenever `vmm-core` updates a device's MSI-X vector mapping, it publishes the
  resolved `(msi_addr, msi_data)` into `BridgeShm::irq_routes`. When `vmm-io`
  calls `io_virtio_irq`, the core host injects the MSI **directly** without
  entering a `vmm-core` Wasm worker.

---

## 4. Shared-Memory Bridge (`BridgeShm`)

Bulk data and control traffic are strictly separated across the Core <-> I/O
boundary (`vmm-core/src/host.rs` `abi::BridgeShm`):

1. **Zero-Copy Bulk Memory**:
   Guest RAM (`memfd` + `MAP_SHARED` on Linux, pinned shared `SysMem` pages on
   Motor OS) and boot payloads (`kernel` + `initramfs`) are mapped directly into
   both hosts. `io_guest_mem_read` and `io_guest_mem_write` translate
   `gpa -> shm_offset` via `BridgeShm::ram_slots` and `memcpy` directly between
   `vmm-io` linear memory and Guest RAM with zero IPC copies.
2. **`#[repr(C)]` Control Header & Lock-Free Rings (`BridgeShm`)**:
   - Static config tables: `ShmBootInfo`, `ShmVirtioDeviceSpec[MAX_VIRTIO_DEVS]`,
     `ShmRamSlot[MAX_RAM_SLOTS]`, `ShmVirtioQueueConfig[MAX_VIRTIO_DEVS][MAX_QUEUES_PER_DEV]`,
     and `ShmDeviceMsixRouting[MAX_VIRTIO_DEVS]`.
   - `core_to_io` ring (MPSC, vCPUs -> I/O thread): `VirtioNotify`, `VirtioStart`,
     `VirtioReset`, `SerialTx`, `Shutdown`.
   - `io_to_core` ring (SPSC, I/O thread -> Core host): `VirtioIrq`, `SerialRx`,
     `RequestShutdown`.
   - Paired with OS wait/wake handles (`eventfd` on Linux; `vm_handle: SysHandle`
     via `SysCpu::wait` / `SysCpu::wake` on Motor OS).

---

## 5. Host Mapping Summary

| Capability / Primitive | Linux Ring 3 (`vmm-core-host` + `vmm-io-host`) | Motor OS Ring 0 + Ring 3 ([`airlock-motor-os.md`](airlock-motor-os.md)) |
| :--------------------- | :--------------------------------------------- | :---------------------------------------------------------------------- |
| Core Wasm binary       | `vmm-core.wasm` / `vmm-core.cwasm`             | Byte-identical `vmm-core.wasm` -> `vmm-core-motor.cwasm`                |
| I/O Wasm binary        | `vmm-io.wasm` / `vmm-io.cwasm`                 | Byte-identical `vmm-io.wasm` -> `.cwasm` (or `vmm-io-tiny` in Step `d`) |
| Stage-2 GPA mapping    | `KVM_SET_USER_MEMORY_REGION` over `memfd`      | Ring-0 NPT/EPT over pinned `SysMem` pages                               |
| vCPU threads           | Host `std::thread`s calling `ioctl(KVM_RUN)`   | Kernel `process::Thread`s running `VMRUN` + `x2APIC` + `pvclock`        |
| Interrupt delivery     | `KVM_SIGNAL_MSI` (`KVM_CAP_SPLIT_IRQCHIP`)     | Ring-0 LAPIC IRR + `sched::poke_cpu` wakeup IPI                         |
| Fast `QueueNotify`     | `KVM_IOEVENTFD` -> `core_to_io` `eventfd`      | Ring-0 `DoorbellTable` -> `BridgeShm::core_to_io` + `SysObject::wake`   |
| MMIO exit variant      | `VmExit::Mmio` (`HostCaps::DECODED_MMIO`)      | `VmExit::MmioFault` (decoded in Wasm by `vmm-core`)                     |
