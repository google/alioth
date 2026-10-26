# Split-VMM Design Document (`vmm-core` + `vmm-io`)

## 1. Overview & Goals

We are splitting the current monolithic `vmm-runner` + `vmm-host` architecture
into two pairs of guest/host crates:

1. **`vmm-core` (Wasm) + `vmm-core-host` (Native Host, `VmmHostCore` trait)**:
   - Owns the **hot VM-exit path** and core virtualization state:
     - Guest physical address space (`RamBus`), low/high RAM layout, and KVM
       memory slot mapping (`VmMemory`, `MemPages`).
     - vCPU lifecycle, CPUID, initial x86_64 register state (`InitState`),
       BSP/AP boot synchronization, and per-vCPU `KVM_RUN` + VM-exit loops.
     - x86_64 motherboard devices: ACPI tables (`RSDP`, `XSDT`, `FADT`, `DSDT`,
       `MADT`, `MCFG`), E820 map, 8254 PIT (`0x61`), CMOS/RTC (`0x70`–`0x71`),
       ACPI PM/sleep control (`0x600`, `0x604`), and `fw_cfg`.
     - PCIe ECAM (`0xe000_0000`), PCI host bridge (`00:00.0`), PCI BAR
       allocation/relocation, MSI-X capability & table/PBA MMIO, and Virtio PCI
       transport registers (`VirtioCommonCfg`, `ISR`, `DeviceConfig` MMIO,
       `QueueNotify` MMIO).
     - Interrupt routing and injection (`IntxSender`, `MsiSender`).
   - Designed to be **minimal, deterministic, float-free (zero `xmm`), and
     filesystem/network-free**, so it can be moved cleanly into **Ring 0 (an OS
     kernel)**.

2. **`vmm-io` (Wasm) + `vmm-io-host` (Native Host, `VmmHostIo` trait)**:
   - Owns all **external I/O backends and host OS/filesystem/network
     interactions**:
     - Parsing `vm.toml` and reading kernel/initramfs images.
     - `virtio-blk` queue processing (`VIRTIO_BLK_T_IN`, `VIRTIO_BLK_T_OUT`,
       `VIRTIO_BLK_T_FLUSH`, `VIRTIO_BLK_T_GET_ID`) backed by disk files.
     - `virtio-net` RX/TX queue processing and offload negotiation backed by
       host TAP devices (`/dev/net/tun`).
     - Host serial console (`termios` `stdin`/`stdout`) and asynchronous I/O
       readiness polling (`mio::Poll`).
   - Designed to run in **Ring 3 (user space)** or an isolated I/O service
     communicating with `vmm-core-host` over a well-defined bridge.

```text
+--------------------------------------+      +--------------------------------------+
|          vmm-core (Wasm)             |      |           vmm-io (Wasm)              |
|  - Per-vCPU loops (PIO / MMIO)       |      |  - vm.toml & payload reader          |
|  - RamBus, E820, ACPI, Boot loader   |      |  - Virtio SplitQueue walker          |
|  - PCIe ECAM + Virtio PCI transport  |      |  - virtio-blk (disk files)           |
|  - MSI-X table & IRQ routing         |      |  - virtio-net (TAP sockets)          |
|  - 16450 UART registers (0x3f8)      |      |  - I/O event loop (TAP RX, stdin RX) |
+------------------+-------------------+      +------------------+-------------------+
                   |                                             |
     "vmm_core"::* | (C-ABI imports)               "vmm_io"::*   | (C-ABI imports)
                   v                                             v
+------------------+-------------------+      +------------------+-------------------+
|        vmm-core-host (Native)        |      |         vmm-io-host (Native)         |
|        implements VmmHostCore        |      |         implements VmmHostIo         |
|  - /dev/kvm (VM, vCPU, KVM_RUN)      | <==> |  - /dev/net/tun (HostTap)            |
|  - Guest RAM mmap + KVM mem slots    | Core |  - Disk image file I/O (pread/pwrite)|
|  - KVM_IRQFD & KVM_SIGNAL_MSI        |  /   |  - Raw termios stdin/stdout          |
|  - Cross-split queues & Guest RAM    |  IO  |  - mio::Poll (TAP + stdin + notify)  |
|    shared access                     |Bridge|                                      |
+--------------------------------------+      +--------------------------------------+
         (Target: Ring 0 Kernel)                      (Target: Ring 3 Userspace)
```

---

## 2. Complete Catalogue of Existing `vmm-runner` Host Imports

Today, `vmm-runner.wasm` has **72 Wasm imports** across 4 import modules:
- `env` (1 shared memory import)
- `wasi` (1 thread-spawning import)
- `vmm` (42 custom VMM host imports)
- `wasi_snapshot_preview1` (28 standard WASI Preview 1 imports)

### 2.1 Existing `"vmm"` Module Imports (42 Functions)

| #  | Current Import (`"vmm"::*`)                                     | Current Purpose                                    | Destination Trait                              |
| :- | :-------------------------------------------------------------- | :------------------------------------------------- | :--------------------------------------------- |
| 1  | `vmm_last_error_len() -> u32`                                   | Length of last thread-local host error string      | **Both** (`VmmHostCore` & `VmmHostIo`)         |
| 2  | `vmm_last_error_read(dst_ptr, dst_len) -> i32`                  | Copy last thread-local host error string           | **Both** (`VmmHostCore` & `VmmHostIo`)         |
| 3  | `hv_new() -> i32`                                               | Open `/dev/kvm` hypervisor handle                  | **`VmmHostCore`**                              |
| 4  | `hv_get_supported_cpuids(hv, dst_ptr, max) -> i32`              | Query `KVM_GET_SUPPORTED_CPUID`                    | **`VmmHostCore`**                              |
| 5  | `hv_create_vm(hv) -> i32`                                       | Create KVM VM (`KVM_CREATE_VM`, IRQCHIP, PIT2)     | **`VmmHostCore`**                              |
| 6  | `hv_close(hv)`                                                  | Drop hypervisor handle                             | **`VmmHostCore`**                              |
| 7  | `vm_close(vm)`                                                  | Drop VM handle                                     | **`VmmHostCore`**                              |
| 8  | `vm_create_vcpu(vm, id) -> i32`                                 | Create vCPU (`KVM_CREATE_VCPU`) on calling thread  | **`VmmHostCore`**                              |
| 9  | `vm_stop_vcpu(vm, id) -> i32`                                   | Kick vCPU thread out of `KVM_RUN` (`SIGRTMIN`)     | **`VmmHostCore`**                              |
| 10 | `vcpu_run(vcpu, entry_kind, entry_data, exit_out) -> i32`       | Run `ioctl(KVM_RUN)` and return `RawVmExit`        | **`VmmHostCore`**                              |
| 11 | `vcpu_get_reg(vcpu, reg, val_out) -> i32`                       | Read general-purpose vCPU register                 | **`VmmHostCore`**                              |
| 12 | `vcpu_set_regs(vcpu, vals_ptr, vals_len) -> i32`                | Write general-purpose vCPU registers               | **`VmmHostCore`**                              |
| 13 | `vcpu_get_seg_reg(vcpu, reg, val_out) -> i32`                   | Read segment register (`CS`, `DS`, `TR`, etc.)     | **`VmmHostCore`**                              |
| 14 | `vcpu_get_dt_reg(vcpu, reg, val_out) -> i32`                    | Read descriptor table register (`GDTR`, `IDTR`)    | **`VmmHostCore`**                              |
| 15 | `vcpu_get_sreg(vcpu, reg, val_out) -> i32`                      | Read special/control register (`CR0`-`CR4`, `EFER`) | **`VmmHostCore`**                              |
| 16 | `vcpu_set_sregs(vcpu, ...) -> i32`                              | Write special, segment, and descriptor registers   | **`VmmHostCore`**                              |
| 17 | `vcpu_set_cpuids(vcpu, cpuids_ptr, cpuids_len) -> i32`          | Configure vCPU `KVM_SET_CPUID2`                    | **`VmmHostCore`**                              |
| 18 | `vcpu_dump(vcpu) -> i32`                                        | Dump vCPU registers for debugging                  | **`VmmHostCore`**                              |
| 19 | `vcpu_close(vcpu)`                                              | Drop vCPU handle                                   | **`VmmHostCore`**                              |
| 20 | `vm_create_vm_memory(vm) -> i32`                                | Create KVM memory manager handle                   | **`VmmHostCore`**                              |
| 21 | `vm_memory_mem_map(mem, slot, gpa, size, hva, flags) -> i32`    | Map host pages into GPA (`KVM_SET_USER_MEMORY_..`) | **`VmmHostCore`**                              |
| 22 | `vm_memory_unmap(mem, slot, gpa, size) -> i32`                  | Unmap KVM memory slot                              | **`VmmHostCore`**                              |
| 23 | `vm_memory_max_mem_slots(mem, out_ptr) -> i32`                  | Query `KVM_CAP_NR_MEMSLOTS`                        | **`VmmHostCore`**                              |
| 24 | `vm_memory_register_encrypted_range(mem, addr, size) -> i32`    | Register SEV/encrypted memory range                | **`VmmHostCore`**                              |
| 25 | `vm_memory_deregister_encrypted_range(mem, addr, size) -> i32`  | Deregister encrypted memory range                  | **`VmmHostCore`**                              |
| 26 | `vm_memory_alloc_anon_mem(mem, size, addr_out, sz_out) -> i32`  | Allocate anonymous `mmap` guest RAM (`MemPages`)   | **`VmmHostCore`**                              |
| 27 | `vm_memory_close(mem)`                                          | Drop `VmMemory` handle                             | **`VmmHostCore`**                              |
| 28 | `mem_pages_sync(pages) -> i32`                                  | `msync` backing pages                              | **`VmmHostCore`**                              |
| 29 | `mem_pages_read(pages, offset, dst_ptr, len) -> i32`            | Read guest RAM into Wasm linear memory             | **`VmmHostCore`** (+ GPA read on `VmmHostIo`)  |
| 30 | `mem_pages_write(pages, offset, src_ptr, len) -> i32`           | Write Wasm linear memory into guest RAM            | **`VmmHostCore`** (+ GPA write on `VmmHostIo`) |
| 31 | `mem_pages_close(pages)`                                        | Unmap/drop `MemPages` handle                       | **`VmmHostCore`**                              |
| 32 | `vm_create_intx_sender(vm, pin) -> i32`                         | Create `KVM_IRQFD` legacy interrupt sender         | **`VmmHostCore`**                              |
| 33 | `intx_sender_send(sender) -> i32`                               | Trigger legacy IRQ pin                             | **`VmmHostCore`**                              |
| 34 | `intx_sender_close(sender)`                                     | Drop `IntxSender`                                  | **`VmmHostCore`**                              |
| 35 | `vm_create_msi_sender(vm) -> i32`                               | Create `KVM_SIGNAL_MSI` sender                     | **`VmmHostCore`**                              |
| 36 | `msi_sender_send(sender, addr, data) -> i32`                    | Inject MSI/MSI-X interrupt (`addr`, `data`)        | **`VmmHostCore`**                              |
| 37 | `msi_sender_close(sender)`                                      | Drop `MsiSender`                                   | **`VmmHostCore`**                              |
| 38 | `vm_next_io_event(vm, event_out_ptr) -> i32`                    | Block on `mio::Poll` for next I/O event            | **`VmmHostIo`**                                |
| 39 | `vm_stop_io_poll(vm) -> i32`                                    | Wake `mio::Waker` and stop I/O polling             | **`VmmHostIo`**                                |
| 40 | `vm_create_serial_console(vm) -> i32`                           | Initialize raw-mode `termios` stdin/stdout         | **`VmmHostIo`** (or split TX/RX; see §4.3)     |
| 41 | `serial_write_byte(serial, byte) -> i32`                        | Write 1 byte to host stdout                        | **`VmmHostIo`** (or `VmmHostCore` console out) |
| 42 | `serial_read_input(serial, dst_ptr, max_len) -> i32`            | Read buffered bytes from host stdin                | **`VmmHostIo`**                                |
| 43 | `serial_shutdown(serial) -> i32`                                | Signal VM shutdown (`Ctrl-a q`)                    | **`VmmHostIo`**                                |
| 44 | `serial_close(serial)`                                          | Restore terminal mode & drop serial handle         | **`VmmHostIo`**                                |
| 45 | `vm_create_tap(vm, has_name, name_ptr, name_len) -> i32`        | Open `/dev/net/tun` TAP interface                  | **`VmmHostIo`**                                |
| 46 | `tap_detected_offload(tap) -> u64`                              | Query supported TAP offloads                       | **`VmmHostIo`**                                |
| 47 | `tap_enable_offload(tap, feature) -> i32`                       | Configure `TUNSETOFFLOAD`                          | **`VmmHostIo`**                                |
| 48 | `tap_register(tap, token, interests) -> i32`                    | Register TAP fd with `mio::Poll`                   | **`VmmHostIo`**                                |
| 49 | `tap_deregister(tap)`                                           | Deregister TAP fd from `mio::Poll`                 | **`VmmHostIo`**                                |
| 50 | `tap_read(tap, dst_ptr, max_len) -> i32`                        | Non-blocking packet read from TAP                  | **`VmmHostIo`**                                |
| 51 | `tap_write(tap, src_ptr, len) -> i32`                           | Non-blocking packet write to TAP                   | **`VmmHostIo`**                                |
| 52 | `tap_close(tap)`                                                | Close TAP fd                                       | **`VmmHostIo`**                                |

*(Note: table rows 1–52 correspond to the 52 `extern "C"` declarations in
[`vmm-runner/src/wasm.rs`](file:///usr/local/google/home/posk/work/wasm-vmm/vmm-runner/src/wasm.rs#L33-L108),
42 of which are live in the stripped release binary.)*

### 2.2 Existing WASI & Runtime Imports (20 Functions + 1 Memory)

| Import                                                    | Current Usage in `vmm-runner`                           | Split Fate (`vmm-core` vs. `vmm-io`)                            |
| :-------------------------------------------------------- | :------------------------------------------------------ | :-------------------------------------------------------------- |
| `env::memory`                                             | Shared Wasm linear memory (`SharedMemory`)              | **Both** (each Wasm module has its own linear memory)           |
| `wasi::thread-spawn`                                      | Spawns `vcpu_0..N` threads and `vmm_io` thread          | **`VmmHostCore`** (for `vcpu_0..N`). Optional in `vmm-io`.      |
| `wasi_snapshot_preview1::path_open`, `fd_read`,           | Used by `virtio-blk` (`Block`), `parse_config`          | **Removed from `vmm-core`!** Moved to **`vmm-io` /              |
| `fd_write`, `fd_seek`, `fd_filestat_get`, `fd_close`,     | (`vm.toml`), `loader` (`bzImage`/`initramfs`),          | `VmmHostIo`** (see §3.2 for explicit `VmmHostIo`                |
| `fd_fdstat_*`, `fd_prestat_*`                             | and `PerThreadLogWriter`                                | file/block APIs vs. WASI).                                      |
| `wasi_snapshot_preview1::args_get`, `args_sizes_get`,     | CLI `-c vm.toml` parsing                                | **`vmm-io`** (or passed via `VmmHostCore` / `VmmHostIo` init).  |
| `environ_get`, `environ_sizes_get`                        |                                                         |                                                                 |
| `wasi_snapshot_preview1::clock_time_get`                  | Used by CMOS/RTC (`hw_x86_64.rs`) and `simplelog`       | Replaced by `get_wall_time_ns()` / `log_write()` if `no_std`.   |
| `wasi_snapshot_preview1::random_get`, `sched_yield`,      | HashMap seed, thread yield, exit                        | Provided minimally or eliminated when moving to `no_std`.       |
| `proc_exit`                                               |                                                         |                                                                 |

---

## 3. Proposed Trait Definitions: `VmmHostCore` and `VmmHostIo`

```rust
/// Opaque host resource handle (hypervisor, VM, vCPU, memory, IRQ sender,
/// Virtio device, TAP, block device, serial console, etc.).
///
/// Note: On Linux, underlying handles/FDs are `u32` (or `RawFd`) to match the
/// existing KVM/POSIX API, but in `VmmHostCore` and `VmmHostIo` we use `u64`
/// to be more generic (e.g. for 64-bit kernel handles/capabilities in Ring 0).
pub type Handle = u64;
```

### 3.1 `VmmHostCore` (in `vmm-core-host`)

`VmmHostCore` contains **only** hypervisor/vCPU/memory/interrupt primitives plus
the **Core-side of the Core $\leftrightarrow$ I/O bridge**:

```rust
pub trait VmmHostCore: Send + Sync {
    // --- Hypervisor & VM Lifecycle ---
    fn hv_new(&self) -> Result<Handle, Error>;
    fn hv_get_supported_cpuids(&self, hv: Handle) -> Result<Vec<Cpuid>, Error>;
    fn hv_create_vm(&self, hv: Handle) -> Result<Handle, Error>;
    fn hv_close(&self, hv: Handle);
    fn vm_close(&self, vm: Handle);

    // --- vCPU Lifecycle & Execution ---
    fn vm_create_vcpu(&self, vm: Handle, id: u32) -> Result<Handle, Error>;
    fn vm_stop_vcpu(&self, vm: Handle, id: u32) -> Result<(), Error>;
    fn vcpu_run(&self, vcpu: Handle, entry: VmEntry) -> Result<VmExit, Error>;
    fn vcpu_get_reg(&self, vcpu: Handle, reg: Reg) -> Result<u64, Error>;
    fn vcpu_set_regs(&self, vcpu: Handle, vals: &[(Reg, u64)]) -> Result<(), Error>;
    fn vcpu_get_seg_reg(&self, vcpu: Handle, reg: SegReg) -> Result<SegRegVal, Error>;
    fn vcpu_get_dt_reg(&self, vcpu: Handle, reg: DtReg) -> Result<DtRegVal, Error>;
    fn vcpu_get_sreg(&self, vcpu: Handle, reg: SReg) -> Result<u64, Error>;
    fn vcpu_set_sregs(
        &self,
        vcpu: Handle,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error>;
    fn vcpu_set_cpuids(&self, vcpu: Handle, cpuids: &[Cpuid]) -> Result<(), Error>;
    fn vcpu_dump(&self, vcpu: Handle) -> Result<(), Error>;
    fn vcpu_close(&self, vcpu: Handle);

    // --- Guest Physical Memory & Pages ---
    fn vm_create_vm_memory(&self, vm: Handle) -> Result<Handle, Error>;
    fn vm_memory_mem_map(
        &self,
        mem: Handle,
        slot: u32,
        gpa: u64,
        size: u64,
        hva: u64,
        option: MemMapOption,
    ) -> Result<(), Error>;
    fn vm_memory_unmap(&self, mem: Handle, slot: u32, gpa: u64, size: u64) -> Result<(), Error>;
    fn vm_memory_max_mem_slots(&self, mem: Handle) -> Result<u32, Error>;
    fn vm_memory_register_encrypted_range(&self, mem: Handle, range: &[u8]) -> Result<(), Error>;
    fn vm_memory_deregister_encrypted_range(&self, mem: Handle, range: &[u8]) -> Result<(), Error>;
    fn vm_memory_alloc_anon_mem(
        &self,
        mem: Handle,
        size: usize,
    ) -> Result<(Handle, u64, usize), Error>;
    fn vm_memory_close(&self, mem: Handle);

    fn mem_pages_sync(&self, pages: Handle) -> Result<(), Error>;
    fn mem_pages_read(&self, pages: Handle, offset: usize, dst: &mut [u8]) -> Result<(), Error>;
    fn mem_pages_write(&self, pages: Handle, offset: usize, src: &[u8]) -> Result<(), Error>;
    fn mem_pages_close(&self, pages: Handle);

    // --- Interrupt Injection ---
    fn vm_create_intx_sender(&self, vm: Handle, pin: u8) -> Result<Handle, Error>;
    fn intx_sender_send(&self, sender: Handle) -> Result<(), Error>;
    fn intx_sender_close(&self, sender: Handle);

    fn vm_create_msi_sender(&self, vm: Handle) -> Result<Handle, Error>;
    fn msi_sender_send(&self, sender: Handle, addr: u64, data: u32) -> Result<(), Error>;
    fn msi_sender_close(&self, sender: Handle);

    // =========================================================================
    // Cross-Split Bridge Methods on VmmHostCore (Core <-> IO communication)
    // =========================================================================

    /// Retrieve the core VM configuration (`num_cpus`, `mem_size`, `cmd_line`,
    /// `exec_type`) and the list of Virtio PCI device descriptors registered
    /// by `vmm-io` (`dev_handle`, `virtio_device_id`, `device_features`,
    /// `num_queues`, initial device config space bytes).
    fn core_get_boot_info(&self) -> Result<CoreBootInfo, Error>;

    /// Read a chunk of the kernel or initramfs image (opened/managed by the IO
    /// side) so `vmm-core`'s loader (`bzImage` / ELF / PVH) can parse headers
    /// and load segments into guest RAM without direct filesystem access.
    fn core_read_payload(
        &self,
        kind: PayloadKind, // Kernel or Initramfs
        offset: u64,
        dst: &mut [u8],
    ) -> Result<usize, Error>;

    /// Called by `vmm-core` when the guest driver writes `DRIVER_OK` to a
    /// Virtio PCI device. Passes negotiated driver features, configured split
    /// queue parameters (`size`, `desc_gpa`, `avail_gpa`, `used_gpa`), and the
    /// MSI-X interrupt binding to `vmm-io`.
    fn core_virtio_start(
        &self,
        dev: Handle,
        driver_features: u64,
        queues: &[VirtioQueueConfig],
    ) -> Result<(), Error>;

    /// Called by `vmm-core` when a vCPU writes to the Virtio PCI `QueueNotify`
    /// MMIO register for `(dev, queue_index)`. Acts as an asynchronous doorbell:
    /// enqueues a `VirtioNotify` event for `vmm-io`, wakes `vmm-io`'s event
    /// loop, and returns immediately so the vCPU can re-enter `KVM_RUN`.
    fn core_virtio_notify(&self, dev: Handle, queue_index: u16) -> Result<(), Error>;

    /// Called by `vmm-core` when the guest driver resets a Virtio PCI device.
    fn core_virtio_reset(&self, dev: Handle) -> Result<(), Error>;

    /// Called by `vmm-core` when the guest updates MSI-X table/vector routing
    /// for a Virtio PCI device so `vmm-io` (or `vmm-core-host`) knows which
    /// `(msi_addr, msi_data)` to fire when a queue completes.
    fn core_virtio_update_irq(
        &self,
        dev: Handle,
        config_msi: Option<(u64, u32)>,
        queue_msis: &[Option<(u64, u32)>],
    ) -> Result<(), Error>;

    /// Serial console TX/RX bridge between `vmm-core`'s 16450 UART (PIO 0x3f8)
    /// and `vmm-io`'s host terminal.
    fn core_serial_tx(&self, byte: u8) -> Result<(), Error>;
    fn core_serial_rx(&self, dst: &mut [u8]) -> Result<usize, Error>;

    /// Notify `vmm-io` that the VM is shutting down (e.g., ACPI poweroff).
    fn core_notify_shutdown(&self) -> Result<(), Error>;
}
```

---

### 3.2 `VmmHostIo` (in `vmm-io-host`)

`VmmHostIo` contains all **TAP, disk/file, serial terminal, and event-polling**
operations plus the **I/O-side of the Core $\leftrightarrow$ I/O bridge**:

```rust
pub trait VmmHostIo: Send + Sync {
    // --- TAP Networking ---
    fn tap_create(&self, if_name: Option<&str>) -> std::io::Result<Handle>;
    fn tap_detected_offload(&self, tap: Handle) -> u64;
    fn tap_enable_offload(&self, tap: Handle, feature: NetFeature) -> std::io::Result<()>;
    fn tap_register(&self, tap: Handle, token: Token, interests: Interest) -> std::io::Result<()>;
    fn tap_deregister(&self, tap: Handle);
    fn tap_read(&self, tap: Handle, buf: &mut [u8]) -> std::io::Result<usize>;
    fn tap_write(&self, tap: Handle, buf: &[u8]) -> std::io::Result<usize>;
    fn tap_close(&self, tap: Handle);

    // --- Block / File Backing Storage ---
    // (Can either use these explicit host imports or WASI Preview 1 in userspace)
    fn blk_open(&self, path: &str, read_only: bool) -> std::io::Result<(Handle, u64)>; // (handle, size_bytes)
    fn blk_read_at(&self, blk: Handle, offset: u64, dst: &mut [u8]) -> std::io::Result<usize>;
    fn blk_write_at(&self, blk: Handle, offset: u64, src: &[u8]) -> std::io::Result<usize>;
    fn blk_flush(&self, blk: Handle) -> std::io::Result<()>;
    fn blk_close(&self, blk: Handle);

    // --- Serial Terminal ---
    fn serial_create(&self) -> std::io::Result<Handle>;
    fn serial_write(&self, serial: Handle, buf: &[u8]) -> std::io::Result<usize>;
    fn serial_read(&self, serial: Handle, dst: &mut [u8]) -> std::io::Result<usize>;
    fn serial_close(&self, serial: Handle);

    // =========================================================================
    // Cross-Split Bridge Methods on VmmHostIo (IO <-> Core communication)
    // =========================================================================

    /// Called by `vmm-io` at startup after parsing `vm.toml` and opening
    /// `virtio-blk` / `virtio-net` backends. Publishes the boot configuration
    /// and Virtio device specifications (`dev: Handle`, `device_id`, `features`,
    /// `num_queues`, `config_bytes`) so `vmm-core` can construct the board and
    /// PCI bus.
    fn io_register_vm_config(
        &self,
        boot_info: CoreBootInfo,
        devices: &[VirtioDeviceSpec],
    ) -> Result<(), Error>;

    /// Wait for the next event on the I/O side:
    /// - `IoSideEvent::VirtioStart { dev: Handle, driver_features, queues }`
    /// - `IoSideEvent::VirtioNotify { dev: Handle, queue_index }`
    /// - `IoSideEvent::VirtioReset { dev: Handle }`
    /// - `IoSideEvent::Poll(PollEvent)` (TAP fd readable/writable)
    /// - `IoSideEvent::SerialInput` (host stdin readable)
    /// - `IoSideEvent::SerialTx(u8)` (if serial TX is forwarded through `vmm-io`)
    /// - `IoSideEvent::Shutdown` (VM stopped by `vmm-core`)
    fn io_next_event(&self) -> Result<IoSideEvent, Error>;

    /// Wake `io_next_event` and request shutdown of both `vmm-io` and
    /// `vmm-core` (e.g., when `Ctrl-a q` is pressed on serial input).
    fn io_request_shutdown(&self) -> Result<(), Error>;

    /// Read guest physical memory (`gpa .. gpa + dst.len()`) so `vmm-io` can
    /// walk `SplitQueue` descriptor chains (`AvailRing`, `Desc`, readable
    /// buffers) in guest RAM.
    fn io_guest_mem_read(&self, gpa: u64, dst: &mut [u8]) -> Result<(), Error>;

    /// Write guest physical memory (`gpa .. gpa + src.len()`) so `vmm-io` can
    /// write writable descriptor buffers and update `UsedRing` in guest RAM.
    fn io_guest_mem_write(&self, gpa: u64, src: &[u8]) -> Result<(), Error>;

    /// Trigger a Virtio queue or config interrupt in `vmm-core` after `vmm-io`
    /// commits new entries to the `UsedRing`.
    fn io_virtio_irq(&self, dev: Handle, kind: VirtioIrqKind) -> Result<(), Error>;

    /// Push incoming serial console bytes (`stdin`) to `vmm-core`'s 16450 RX
    /// FIFO and assert COM1's legacy INTx (IRQ 4).
    fn io_serial_push_rx(&self, bytes: &[u8]) -> Result<(), Error>;
}
```

---

## 4. Key Architectural & Design Decisions

### 4.1 `SplitQueue` (Virtqueue Ring Walking) Lives in `vmm-io`

- **`vmm-core`** emulates only the PCI bus, MSI-X table, and Virtio PCI
  capabilities (`VirtioCommonCfg`, `ISR`, `DeviceConfig`, `QueueNotify`).
- When the guest driver writes `DRIVER_OK`, `vmm-core` calls
  `core_virtio_start(dev, driver_features, &[VirtioQueueConfig { size, desc_gpa, avail_gpa, used_gpa }])`
  to hand the configured queue GPAs to `vmm-io`.
- When a vCPU writes to `QueueNotify`, `vmm-core` calls
  `core_virtio_notify(dev, q_index)`.
- **`vmm-io`** owns `SplitQueue`, reads/writes guest RAM via
  `io_guest_mem_read` / `io_guest_mem_write`, executes the disk/TAP I/O, and
  calls `io_virtio_irq(dev, VirtioIrqKind::Queue(q_index))`.
- **Rationale**:
  1. Keeps `vmm-core` small and completely decoupled from Virtio ring buffer
     traversal and bounce buffers.
  2. Supports asynchronous RX queues (`virtio-net` RX), where incoming TAP
     packets arrive asynchronously on the `vmm-io` thread when no vCPU is inside
     `vmm-core`, requiring `vmm-io` to pop RX buffers from the RX `SplitQueue`
     independently.

---

### 4.2 Asynchronous `core_virtio_notify` Doorbell

When a vCPU in `vmm-core` writes to the Virtio PCI `QueueNotify` register:
- `core_virtio_notify(dev, q_index)` acts as an **asynchronous doorbell**: it
  enqueues a `VirtioNotify` event for `vmm-io` and wakes `vmm-io`'s `mio::Poll`
  / event loop, returning immediately so the vCPU can re-enter `KVM_RUN` without
  waiting for host disk or TAP I/O.
- When `vmm-io` finishes processing the queue, it calls
  `io_virtio_irq(dev, VirtioIrqKind::Queue(q_index))`.

---

### 4.3 Direct MSI-X Interrupt Routing (`io_virtio_irq` $\rightarrow$ `vmm-core-host`)

When `vmm-io` finishes a queue request and calls `io_virtio_irq(dev, VirtioIrqKind::Queue(q_idx))`:
- In `vmm-core`, the guest configures MSI-X table entries (`MsixTableEntry`:
  `addr_lo`, `addr_hi`, `data`, `masked`) and maps `queue_msix_vector` in
  `VirtioCommonCfg`.
- Whenever `vmm-core` updates a device's MSI-X table entry or `queue_msix_vector`,
  `vmm-core` pushes the resolved `(msi_addr, msi_data)` table to `vmm-core-host`
  via `core_virtio_update_irq`.
- When `vmm-io` calls `io_virtio_irq(dev, VirtioIrqKind::Queue(q_idx))`, the host
  invokes `ioctl(KVM_SIGNAL_MSI)` **directly in `vmm-core-host`** without needing
  to interrupt or enter a `vmm-core` Wasm thread.

---

### 4.4 Core $\leftrightarrow$ I/O Bridge Transport: Shared Memory + Lock-Free Rings + `eventfd`

The bridge between `vmm-core-host` and `vmm-io-host` separates **bulk memory
access** from **control/doorbell messages**:

#### A. Bulk Data (Guest RAM & Boot Payloads): Direct Shared Memory
Instead of copying disk/network payloads or `SplitQueue` descriptors across an
IPC pipe/socket:
- **Guest RAM (`MemPages`)** is allocated as shared memory (`memfd_create` +
  `MAP_SHARED` on Linux, or shared physical pages mapped into both Ring 0 and
  Ring 3 on Motor OS).
- `vmm-core-host` shares the Guest RAM mapping and a `gpa -> shm_offset` slot
  table with `vmm-io-host`.
- When `vmm-io` calls `io_guest_mem_read` or `io_guest_mem_write` (to walk
  `SplitQueue` rings or transfer `virtio-blk` / `virtio-net` DMA buffers),
  `vmm-io-host` copies directly between `vmm-io`'s Wasm linear memory and the
  shared Guest RAM mapping—**zero IPC traffic on data payloads**.
- Similarly, for `core_read_payload` (kernel & initramfs), `vmm-io-host` exposes
  the opened payload mappings in shared memory at boot.

#### B. Control & Doorbell Data: Shared-Memory Ring Buffers + `eventfd`
Control messages and doorbells are placed in a single shared-memory **Bridge
Region** (`#[repr(C)]`, e.g., 64 KiB) paired with two `eventfd`s (or OS
wait/wake handles: `core_to_io_evt` and `io_to_core_evt`):

```text
+-------------------------------------------------------------------+
| Shared Bridge Region (#[repr(C)], e.g. 64 KiB)                    |
+-------------------------------------------------------------------+
| 1. Static / Config Header                                         |
|    - CoreBootInfo (num_cpus, mem_size, cmd_line, ...)             |
|    - VirtioDeviceSpec[MAX_DEVS] (dev, device_id, features, cfg)   |
|    - GuestRamSlot[MAX_SLOTS] (gpa, size, shm_offset)              |
|    - VirtioQueueConfig[MAX_DEVS][MAX_QUEUES] (set on DRIVER_OK)   |
|    - MsixRoutingTable[MAX_DEVS][MAX_QUEUES] (addr, data)          |
+-------------------------------------------------------------------+
| 2. Core -> IO Ring Buffer (MPSC: vCPU threads -> IO thread)       |
|    Fixed-size #[repr(C)] entries (e.g. 32 bytes each):            |
|    - VirtioNotify { dev: Handle, queue_index: u16 }   [Hot Path]  |
|    - VirtioStart  { dev: Handle, driver_features: u64 }           |
|    - VirtioReset  { dev: Handle }                                 |
|    - SerialTx     { len: u8, bytes: [u8; 23] }                    |
|    - Shutdown                                                     |
+-------------------------------------------------------------------+
| 3. IO -> Core Ring Buffer (SPSC: IO thread -> Core host)          |
|    Fixed-size #[repr(C)] entries:                                 |
|    - VirtioIrq    { dev: Handle, kind: VirtioIrqKind } [Hot Path] |
|    - SerialRx     { len: u8, bytes: [u8; 23] }                    |
|    - RequestShutdown                                              |
+-------------------------------------------------------------------+
```

#### C. Rationale
1. **Identical across all deployment models**:
   - **Single-process (2 Wasm instances in 1 host binary)**: Both sides share
     an `Arc<BridgeShm>` + `eventfd`s.
   - **Multi-process on Linux**: Shared via `memfd` + `eventfd` (`SCM_RIGHTS`).
   - **Ring 0 (`vmm-core`) $\leftrightarrow$ Ring 3 (`vmm-io`) on Motor OS**:
     Shared pages + wait/wake handles are the native zero-copy kernel/userspace
     IPC primitive (like `io_uring`), avoiding POSIX socket/pipe syscalls across
     the Ring 0 / Ring 3 boundary.
2. **Event coalescing on the hot path**:
   - Multiple `QueueNotify` writes from vCPUs coalesce in the ring buffer;
     `core_to_io_evt` only needs to be signaled when transitioning from empty
     to non-empty (or when an atomic `io_is_sleeping` flag is set).
3. **Zero serialization / zero `xmm`**:
   - Every ring entry is a fixed-size `#[repr(C)]` `zerocopy` struct—no `serde`,
     no dynamic allocation, and `vmm-io-host`'s `mio::Poll` registers
     `core_to_io_evt` directly alongside TAP and serial FDs.

---

### 4.5 Startup & Boot Sequence Across the Split

```text
1. Host Startup
   ├── vmm-io-host instantiates vmm-io.wasm / vmm-io.cwasm
   │     ├── vmm-io parses vm.toml
   │     ├── vmm-io opens disk images (virtio-blk) and TAP devices (virtio-net)
   │     └── vmm-io calls io_register_vm_config(boot_info, virtio_device_specs)
   │
2. Core Initialization
   ├── vmm-core-host instantiates vmm-core.wasm / vmm-core.cwasm
   │     ├── vmm-core calls core_get_boot_info()
   │     ├── vmm-core allocates Guest RAM (RamBus) & registers KVM mem slots
   │     ├── vmm-core creates PCIe bus + PciVirtio stub devices from virtio_device_specs
   │     ├── vmm-core loads kernel/initramfs via core_read_payload() into Guest RAM
   │     └── vmm-core spawns vcpu_0..N Wasm threads
   │
3. Runtime Execution (Parallel)
   ├── vmm-core (vcpu_0..N threads):
   │     └── loop: vcpu_run() -> handle PIO/MMIO/PCI -> core_virtio_notify()
   └── vmm-io (I/O thread):
         └── loop: io_next_event() -> SplitQueue (io_guest_mem_read/write)
                   -> blk/tap I/O -> io_virtio_irq()
```
