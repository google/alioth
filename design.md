# WASM VMM Design Document

## 1. Overview & Motivation

**WASM VMM** splits a Linux/KVM Virtual Machine Monitor (originally based on
[Alioth](https://github.com/google/alioth) v0.2.0) into two isolated layers:

1. **`vmm-runner` (Multithreaded WebAssembly Guest Module)**:
   Contains all complex VMM logic—guest physical memory layout, x86_64
   architecture setup, ACPI table generation, Linux `bzImage`/ELF/PVH kernel
   loading, PCI bus emulation, 16450 UART serial emulation, Virtio
   (`virtio-blk`, `virtio-net`) device and split-virtqueue emulation, and
   per-vCPU / I/O thread orchestration. It compiles to the
   `wasm32-wasip1-threads` target as:
   - **`vmm-runner.wasm` (~649 KB)**: Portable multithreaded WASI module with
     shared linear memory (`env::memory`).
   - **`vmm-runner.cwasm` (~1.9 MB)**: Ahead-of-Time (AOT) precompiled Wasmtime
     module artifact.
2. **`vmm-host` (Native Linux Host Binaries)**: A thin native wrapper embedding
   Wasmtime that exposes Linux `/dev/kvm` ioctls, `"wasi"::"thread-spawn"`, host
   `mmap` memory allocation, `/dev/net/tun` TAP networking, and host terminal
   I/O to `vmm-runner` via a zero-overhead C-ABI host interface (`"vmm"` module).
   It builds in two variants:
   - **`vmm-host-cwasm` ("small/fast" host, ~2.2 MB static `musl`)**: Built without
     Cranelift; loads precompiled `vmm-runner.cwasm` (`--cwasm`).
   - **`vmm-host-wasm` ("safe" host, ~11.0 MB static `musl`)**: Built with
     Cranelift; validates and compiles `vmm-runner.wasm` in-process at startup
     (`--wasm`).

```text
+------------------------------------------------------------------------------+
|                  vmm-host-cwasm / vmm-host-wasm (x86_64 Linux)               |
|                                                                              |
|  +------------------------------------------------------------------------+  |
|  |         Wasmtime Engine + SharedMemory + WASI Preview 1 Threads        |  |
|  |                                                                        |  |
|  |  +------------------------------------------------------------------+  |  |
|  |  |  vmm-runner.cwasm / vmm-runner.wasm (wasm32-wasip1-threads)      |  |  |
|  |  |                                                                  |  |  |
|  |  |  [Wasm Thread: vcpu_0]  [Wasm Thread: vcpu_N]  [Wasm Thread: io] |  |  |
|  |  |         |                      |                      |          |  |  |
|  |  |         +----------+-----------+                      |          |  |  |
|  |  |                    v                                  v          |  |  |
|  |  |  +----------------+  +------------------+  +------------------+  |  |  |
|  |  |  | Kernel Loader  |  |   x86_64 Board   |  |   RAM / MMIO /   |  |  |  |
|  |  |  | (bzImage/PVH)  |  | & Per-vCPU Loops |  |   PIO Bus        |  |  |  |
|  |  |  +----------------+  +------------------+  +------------------+  |  |  |
|  |  |  +----------------+  +------------------+  +------------------+  |  |  |
|  |  |  |  ACPI / E820   |  | 16450 Serial     |  | PCI + Virtio     |  |  |  |
|  |  |  |  Tables        |  | Console (COM1)   |  | (blk, net, split)|  |  |  |
|  |  |  +----------------+  +------------------+  +------------------+  |  |  |
|  |  +------------------------------------------------------------------+  |  |
|  |                 |                                    |                 |  |
|  |     C-ABI Imports ("vmm"::*)            WASI Preview 1 + thread-spawn  |  |
|  +-----------------|------------------------------------|-----------------+  |
|                    v                                    v                    |
|  +-----------------------------------+  +---------------------------------+  |
|  | KVM & Host I/O Subsystems         |  | Host Filesystem & Threads       |  |
|  | - /dev/kvm (VM, vCPU, Irqfd, MSI) |  | - std::thread::spawn per Wasm   |  |
|  | - Direct ioctl(KVM_RUN) on caller |  |   thread (wasi_thread_start)    |  |
|  | - Anonymous mmap (MemPages)       |  | - vm.toml, bzImage, initramfs   |  |
|  | - /dev/net/tun (HostTap)          |  | - Disk images (alpine.raw)      |  |
|  | - Raw termios stdin/stdout        |  | - VMM log (/tmp/wasm-vmm.log)   |  |
|  | - Direct mio::Poll on io caller   |  +---------------------------------+  |
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
layout knowledge, no kernel parsing, and spawns no background worker threads of
its own. Its sole job is to bridge Wasmtime host calls directly to Linux kernel
primitives on the calling Wasm thread:

- **Wasmtime & `wasm32-wasip1-threads` Hosting (`vmm-host/src/wasm_host.rs`)**:
  - Configures `wasmtime::Config` with `wasm_threads(true)` and
    `shared_memory(true)` and instantiates the module's imported
    `wasmtime::SharedMemory` (`"env"::"memory"`).
  - In `vmm-host-cwasm` ("small/fast" pair), deserializes the AOT-precompiled
    `vmm-runner.cwasm` via `Module::deserialize_file(&engine, path)`.
  - In `vmm-host-wasm` ("safe" pair), validates and JIT-compiles
    `vmm-runner.wasm` via `Module::from_file(&engine, path)`.
  - Implements `"wasi"::"thread-spawn"`, which spawns a native OS thread with
    its own `Store<ThreadState>`, shares the same `SharedMemory` and global
    `Arc<HostEnv>` handle table, and invokes the guest's `wasi_thread_start(tid, start_arg)`.
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
  - Copies buffers directly between Wasm `SharedMemory` (`SharedMemory::data()`)
    and `HostMemPages` during `mem_pages_read` and `mem_pages_write`.
- **Direct Synchronous vCPU Execution (`vmm-host/src/kvm/vcpu.rs`)**:
  - Creates a KVM vCPU file descriptor (`KVM_CREATE_VCPU`), `mmap`s its
    `kvm_run` structure, and records the calling OS thread's `pthread_t` handle
    (`libc::pthread_self()`) for immediate `SIGRTMIN` interruption (`KvmVm::stop_vcpus`).
  - Executes `ioctl(KVM_RUN)` directly and synchronously on the calling Wasm
    vCPU thread (`KvmVcpu::run(entry) -> Result<VmExit, Error>`), returning the
    decoded exit reason (`IoIn`, `IoOut`, `MmioRead`, `MmioWrite`, `Shutdown`,
    `Reboot`, `Interrupted`) straight back to the Wasm caller.
- **Interrupt Injection (`KvmIntxSender`, `KvmMsiSender`)**:
  - Injects legacy INTx interrupts via `KVM_IRQFD` (`eventfd`) and MSI
    interrupts via `KVM_SIGNAL_MSI`.
- **Direct I/O Polling, Serial Terminal, and TAP (`vmm-host/src/serial.rs`, `vmm-host/src/tap.rs`)**:
  - Puts host `stdin` into non-blocking raw `termios` mode (`HostSerialConsole`)
    and opens/configures `/dev/net/tun` (`TUNSETIFF`, `TUNSETOFFLOAD`) for
    `HostTap`.
  - Exposes `KvmVm::next_io_event()`, which runs `mio::Poll::poll` directly on
    the calling Wasm `vmm_io` thread and wakes immediately via `mio::Waker` when
    `KvmVm::stop_io_poll()` is called during VM shutdown.

---

### 2.2 What `vmm-runner` is Responsible For

`vmm-runner` (`vmm-runner/src/`) is a pure-Rust crate compiled to
`wasm32-wasip1-threads`. It interacts with the host exclusively through the
traits in `vmm-runner/src/host.rs` (backed by `"vmm"` C-ABI imports in
`vmm-runner/src/wasm.rs` and standard library / WASI calls):

- **Multithreaded Orchestration & Synchronization (`vmm-runner/src/vm.rs`, `vmm-runner/src/hw/board.rs`, `vmm-runner/src/sync.rs`)**:
  - Spawns `num_cpus` Wasm threads (`vcpu_0`, `vcpu_1`, ...) via
    `std::thread::spawn`, each running `Board::run_vcpu` / `Board::vcpu_loop`,
    plus one Wasm thread (`vmm_io`) running `Board::run_io_loop`.
  - Uses native Wasm `memory.atomic.wait32` / `memory.atomic.notify` via
    `std::sync::{Mutex, RwLock, Condvar}` (`vmm-runner/src/sync.rs`) to
    synchronize BSP/AP boot barriers and shared MMIO/PIO/PCI device state across
    concurrent vCPU and I/O Wasm threads.
- **Configuration & Per-Thread WASI File Access (`vmm-runner/src/config.rs`, `vmm-runner/src/lib.rs`, `vmm-runner/src/virtio/dev/blk.rs`)**:
  - Because each spawned Wasm thread has its own `WasiP1Ctx` file-descriptor
    table, `PerThreadLogWriter` and `Blk` lazily open and cache a per-`ThreadId`
    file handle so any vCPU thread can log or service `virtio-blk` requests.
- **x86_64 PC/Q35-like Board & Memory Map (`vmm-runner/src/hw/`)**:
  - Sets up the guest physical address space (`RamBus`, `Addressable<Box<dyn Mmio>>`,
    `Addressable<Box<dyn Pio>>`), including low RAM below the 2 GiB MMIO gap and
    high RAM above 4 GiB when needed.
  - Generates ACPI tables (`RSDP`, `XSDT`, `FADT`, `DSDT`, `MADT`, `MCFG`) in
    guest RAM so Linux discovers all vCPUs, the IOAPIC, and the PCIe ECAM region.
  - Emulates the 8254 PIT (port `0x61`), CMOS/RTC (ports `0x70`–`0x71`), ACPI
    PM/sleep control registers (`0x600`, `0x604`), and fw_cfg ports.
- **Kernel & Initramfs Loader (`vmm-runner/src/loader/`)**:
  - Parses Linux `bzImage` setup headers (`BootParams`, E820 table, command line,
    initial 64-bit identity page tables `PML4`/`PDPT`/`PD`, and `BOOT_GDT`) or
    Xen PVH ELF notes, loads the kernel and optional `initramfs` into guest RAM,
    and computes the initial vCPU register state (`InitState`).
- **16450 UART Serial Console (`vmm-runner/src/hw/serial.rs`)**:
  - Emulates COM1 at I/O port `0x3f8`–`0x3ff`, FIFO buffering, escape sequence
    detection (`Ctrl-a q` to shut down), and IRQ 4 assertion via `IntxSender`.
- **PCI Bus & Virtio Devices (`vmm-runner/src/virtio/`)**:
  - Emulates PCIe ECAM configuration space (`0xe000_0000`), PCI host bridge
    (`00:00.0`), Virtio PCI capabilities (Common, Notify, ISR, Device, MSI-X),
    and 64-bit BAR allocation/relocation.
  - **`virtio-blk` (`vmm-runner/src/virtio/dev/blk.rs`)**: Handles
    `VIRTIO_BLK_T_IN`, `VIRTIO_BLK_T_OUT`, `VIRTIO_BLK_T_FLUSH`, and
    `VIRTIO_BLK_T_GET_ID` on whichever vCPU thread notified the queue.
  - **`virtio-net` (`vmm-runner/src/virtio/dev/net.rs`)**: Negotiates Virtio net
    offload features (`CSUM`, `TSO4`, `TSO6`, `USO`, etc.) with `Tap`, processes
    TX queues directly on the notifying vCPU thread, and processes incoming RX
    packets on the `vmm_io` thread when the TAP fd becomes readable.

---

## 3. Crossing the 32-bit Wasm / 64-bit Host Boundary

### 3.1 Core Wasm C-ABI Host Interface (`"vmm"` Module)

Because `wasm32-wasip1-threads` uses shared linear memory (`SharedMemory`), the
interface between `vmm-runner` and `vmm-host` is a set of flat C-ABI host
functions in the `"vmm"` import module (`vmm-runner/src/wasm.rs`,
`vmm-host/src/wasm_host.rs`) operating on integer resource handles and
`#[repr(C)]` `zerocopy` structs (`vmm-runner/src/host.rs::abi`):

```text
"vmm" host imports
  ├── last_error_len() / last_error_read(ptr, cap)
  ├── get_hypervisor() -> hv_handle
  ├── hv_get_supported_cpuid(hv, out_ptr, cap, out_len_ptr)
  ├── hv_create_vm(hv) -> vm_handle
  ├── vm_create_vcpu(vm, id) -> vcpu_handle
  │     ├── vcpu_set_regs / vcpu_set_sregs / vcpu_set_cpuid
  │     └── vcpu_run(vcpu, entry_kind, entry_data, out_exit_ptr)
  ├── vm_stop_vcpus(vm)
  ├── vm_next_io_event(vm, out_event_ptr) / vm_stop_io_poll(vm)
  ├── vm_create_vm_memory(vm) -> mem_handle
  │     ├── vm_memory_alloc_anon_mem(size, out_addr_ptr) -> pages_handle
  │     ├── mem_pages_read(pages, offset, dst_ptr, len)
  │     └── mem_pages_write(pages, offset, src_ptr, len)
  ├── vm_create_intx_sender(vm, pin) -> intx_handle
  ├── vm_create_msi_sender(vm) -> msi_handle
  ├── vm_create_serial_console(vm) -> serial_handle
  └── vm_create_tap(vm, name_ptr, name_len) -> tap_handle
```

### 3.2 Guest RAM & Virtqueue Access Across Address Spaces

When `vmm-runner` runs inside `wasm32-wasip1-threads`:
1. **32-bit Wasm vs. 64-bit Host Virtual Addresses**: Wasm uses a 32-bit shared
   linear memory (`usize` is 32 bits), whereas host `mmap` addresses (`hva`) for
   `KVM_SET_USER_MEMORY_REGION` are 64-bit host addresses. `MemPages::addr()`
   and `VmMemory::mem_map()` pass HVAs as opaque `u64` values rather than
   `usize`.
2. **Direct SharedMemory Copy (`mem_pages_read` / `mem_pages_write`)**:
   `WasmMemPages` caches `addr: u64` and `size: usize` locally inside Wasm so
   address-range lookups in `RamBus` require zero host calls. When reading or
   writing guest RAM, `vmm-runner` passes a 32-bit pointer into its Wasm
   `SharedMemory`, and `vmm-host` copies directly between the `SharedMemory`
   slice (`unsafe { memory.data()[ptr..ptr+len] }`) and the `HostMemPages`
   `mmap` region with zero intermediate heap allocations.

---

## 4. Multithreaded Per-vCPU Execution Model

By targeting `wasm32-wasip1-threads`, `vmm-runner` spawns real threads inside
WebAssembly using standard Rust `std::thread::spawn`:

1. **`Machine::boot` (`vmm-runner/src/vm.rs`)** spawns:
   - **`num_cpus` Wasm vCPU threads (`vcpu_0` .. `vcpu_{N-1}`)**: Each Wasm
     thread calls `vm.create_vcpu(id)` on its own OS thread, synchronizes
     BSP/AP initialization via a Wasm `Condvar` barrier (`ArchMP`), and loops on
     `vcpu.run(entry)` (`ioctl(KVM_RUN)`). When a VM exit occurs (`IoIn`,
     `IoOut`, `MmioRead`, `MmioWrite`, `Shutdown`, `Reboot`), the **same Wasm
     vCPU thread** immediately handles the exit (PIO/MMIO bus lookup, serial TX,
     PCI config space, or `virtio-blk` / `virtio-net` queue processing) and
     re-enters `vcpu.run(entry)` with zero cross-thread channel hops.
   - **1 Wasm I/O poller thread (`vmm_io`)**: Calls `vm.next_io_event()`
     (`mio::Poll::poll`) in a loop to handle asynchronous host `stdin` bytes
     (`serial.handle_input()`) and incoming `HostTap` packets
     (`pci_bus.handle_poll_event()`).
2. **Coordinated Shutdown**: When any vCPU triggers `Shutdown`/`Reboot` (or the
   `vmm_io` thread sees `Ctrl-a q` on serial input), `Board` sets its atomic
   `stop_requested` flag, calls `vm.stop_vcpus()` (sending `SIGRTMIN` to kick
   all other vCPU threads out of `ioctl(KVM_RUN)`) and `vm.stop_io_poll()`
   (waking the `mio::Waker`), and `Machine::wait` joins all Wasm threads cleanly.

```text
vmm-runner (Wasm Threads in SharedMemory)          vmm-host (Same OS Thread via C-ABI)
=========================================          ===================================

[Wasm Thread: vcpu_0]
  loop {
    exit = vcpu.run(entry) ----------------------> ioctl(vcpu_0_fd, KVM_RUN)
    entry = handle_exit(exit) <------------------- returns RawVmExit in SharedMemory
      (PIO / MMIO / Virtio on vcpu_0)
  }

[Wasm Thread: vcpu_N]
  loop {
    exit = vcpu.run(entry) ----------------------> ioctl(vcpu_N_fd, KVM_RUN)
    entry = handle_exit(exit) <------------------- returns RawVmExit in SharedMemory
      (PIO / MMIO / Virtio on vcpu_N)
  }

[Wasm Thread: vmm_io]
  loop {
    ev = vm.next_io_event() ---------------------> mio::Poll::poll(stdin, tap)
    handle_io(ev) <------------------------------- returns RawIoEvent in SharedMemory
      (Serial RX / TAP RX -> IRQ/MSI-X)
  }
```

---

## 5. Binary Size Analysis: `vmm-host-wasm` (~11.0 MB) vs. `vmm-host-cwasm` (~2.2 MB)

Switching from WASI Preview 2 (`wasmtime/component-model` + `wasmtime-wasi/p2`)
to `wasm32-wasip1-threads` (`wasmtime/threads` + `wasmtime-wasi/p1`) reduced the
size of both host binaries even further while adding full Wasm multithreading:

- **The "Safe" Pair (`./run-vm.sh --wasm`)**:
  - `vmm-host-wasm` (**~11.0 MB**) + `vmm-runner.wasm` (**~649 KB**)
  - Embeds Wasmtime's Cranelift compiler; validates and compiles the portable
    `.wasm` module in-process at startup (`Module::from_file`).
- **The "Small/Fast" Pair (`./run-vm.sh --cwasm`)**:
  - `vmm-host-cwasm` (**~2.2 MB**) + `vmm-runner.cwasm` (**~1.9 MB**)
  - Excludes Cranelift from the host binary; loads the precompiled `.cwasm`
    artifact (`Module::deserialize_file`), reducing the host binary size by
    **87.6%** compared to the initial 18.28 MB host and making startup
    instantaneous.

### 5.1 ELF Section Breakdown Across Host Variants

Inspecting `size -A` on the static `x86_64-unknown-linux-musl` release binaries:

| ELF Section | Initial Default JIT | `vmm-host-wasm` ("Safe" JIT) | `vmm-host-cwasm` ("Small/Fast" AOT) | Contents |
| :--- | ---: | ---: | ---: | :--- |
| `.text` | 14.38 MB | **8.96 MB** | **1.81 MB** | Machine code (Wasmtime runtime, WASI p1 + threads host, KVM wrapper, plus Cranelift in `-wasm`) |
| `.rodata` | 1.83 MB | **0.82 MB** | **0.13 MB** | Read-only data and ISA/lookup tables |
| `.eh_frame` + `.eh_frame_hdr` | 1.30 MB | **0.82 MB** | **0.17 MB** | Unwind tables for Wasm trap handling and stack unwinding |
| `.rela.dyn` + `.data.rel.ro` | 0.75 MB | **0.36 MB** | **0.14 MB** | Static-PIE relocation tables and vtables |
| `.data` + `.bss` + other | 0.02 MB | **0.01 MB** | **0.02 MB** | Mutable globals and metadata |
| **Total** | **18.28 MB** | **10.97 MB** | **2.27 MB (2.16 MiB)** | |

### 5.2 What Contributes to the Size—and How Each Optimization Helps

1. **Core Wasm Module + WASI Preview 1 Threads (`wasmtime/threads` + `wasmtime-wasi/p1`)**:
   - Replacing the Component Model (`wasmtime/component-model` + `wasmtime-wasi/p2`)
     with a core Wasm module using `wasmtime` features `["runtime", "threads", "std"]`
     and `wasmtime-wasi` feature `["p1"]` eliminates component canonical ABI
     adapters and `wasi:sockets` / ICU dependencies, shrinking `vmm-host-cwasm`
     from 2.97 MB to **2.27 MB** and `vmm-host-wasm` from 12.41 MB to **10.97 MB**.
2. **External Module Artifacts**:
   - Neither host embeds the Wasm binary in `.rodata`; `vmm-host-wasm` loads
     `vmm-runner.wasm` and `vmm-host-cwasm` loads `vmm-runner.cwasm` from disk.
3. **Ahead-of-Time Precompilation (`vmm-host-cwasm`, ~8.7 MB saved)**:
   - [`vmm-host/build.rs`](vmm-host/build.rs) uses `Engine::precompile_module`
     (with `wasm_threads(true)` and `shared_memory(true)`) to AOT-precompile
     `vmm-runner.wasm` into `vmm-runner.cwasm` (~1.9 MB) during `cargo build`.
   - `vmm-host-cwasm` is compiled without the `compiler` (`wasmtime/cranelift`)
     feature and loads `vmm-runner.cwasm` directly via
     `unsafe { Module::deserialize_file(&engine, module_path) }`.
