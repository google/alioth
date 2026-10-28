# Ring-0-Ready, Hypervisor-Generic `VmmHostCore` Architecture

## 1. Executive Summary

In [`split-vmm.md`](split-vmm.md), we split the monolithic VMM into two sandboxed Wasm components:
- **`vmm-core` (Wasm) + `vmm-core-host` (`VmmHostCore` trait)**: owns the hot VM-exit path, guest
  physical memory layout (`RamBus`), ACPI/boot loading, PCIe ECAM, Virtio PCI transport, MSI-X
  tables, and 16450 UART registers.
- **`vmm-io` (Wasm) + `vmm-io-host` (`VmmHostIo` trait)**: owns `vm.toml`, Virtio `SplitQueue` DMA
  processing, `virtio-blk`, `virtio-net` (`TAP`), and host terminal I/O.

While decoupling `wasm_host.rs` to depend exclusively on `VmmHostCore` made the host pluggable in
principle, **current `VmmHostCore` is still a thin 1:1 projection of Linux's Ring-3 `/dev/kvm`
`ioctl` API and POSIX process model**:
1. It exposes seven POSIX file-descriptor handle types (`hv` -> `vm` -> `vm_memory` / `vcpu` /
   `intx_sender` / `msi_sender`) even though one `vmm-core` instance always manages **one** VM.
2. It leaks userspace `mmap` virtual addresses (`hva: u64`), `msync`, and KVM's internal
   `slot: u32` array indices (`KVM_SET_USER_MEMORY_REGION`) into Wasm.
3. It silently relies on **thousands of lines of hidden Linux KVM kernel emulation**
   (`KVM_CREATE_IRQCHIP`'s in-kernel IOAPIC, 8259 PIC, Local APIC, AP `INIT`/`SIPI` wakeup state
   machine, and `arch/x86/kvm/emulate.c`'s x86 MMIO instruction decoder) that do **not** exist in
   Microsoft MSHV, macOS `Hypervisor.framework`, or a clean-slate Ring 0 kernel like **Motor OS**.
4. It relies on Ring-3 execution primitives (`wasm32-wasip1-threads`, `wasi::thread-spawn`, WASI
   Preview 1 syscalls, blocking `Condvar`s, `pthread_kill(SIGRTMIN)`, `Vec`/`String` heap
   allocations, and `std::io::Error`) that conflict with **Linux Ring 0** (16 KiB kernel stacks,
   no `std`, no signals) and **Motor OS Ring 0** (strictly non-blocking `#![no_std]` microkernel).
5. It conflates **hardware virtualization** with **Virtio/UART-specific IPC** (`core_virtio_*`,
   `core_serial_*`) instead of exposing device-agnostic fast-path doorbells (`ioeventfd` / `ioreq`).

### Target Architecture Summary

To run cleanly across **Motor OS Ring 0**, **Linux Ring 0**, **Linux Ring 3 (`KvmCoreHost`)**,
**Microsoft MSHV**, **FreeBSD `bhyve`**, **macOS `Hypervisor.framework`**, and **Xen `ioreq`**,
this document specifies a refactored architecture built on five pillars:
1. **Two Focused `#![no_std]` Host Traits**: `VmmHostCore` (pure single-VM hardware virtualization)
   and `VmmCoreBridge` (Core <-> I/O split channel, completely decoupled from hypervisor ops).
2. **Inverted, Non-Blocking Control Flow (`wasm32-unknown-unknown`, `#![no_std]`)**: The host owns
   vCPU threads/scheduling and calls exported run-to-completion trap handlers
   (`vmm_on_vcpu_exit(vcpu_id)`) backed by pinned per-vCPU `VcpuCommPage` shared-memory frames --
   eliminating WASI, `thread-spawn`, blocking futexes, and deep kernel stacks.
3. **Split-IRQChip Hardware Boundary**: Keep latency-critical Local APIC (APICv/AVIC, timer, IPI,
   `INIT`/`SIPI`) in the host, move **IOAPIC (`0xfec0_0000`) into `vmm-core` Wasm**, and unify
   interrupt injection on `inject_msi(addr, data)`.
4. **Hybrid MMIO Exits + In-Wasm Instruction Decoder**: Accept both pre-decoded `VmExit::Mmio` (KVM,
   Xen, ARM64 `ISV=1`) and raw `VmExit::MmioFault` (Motor OS Ring 0, MSHV, macOS HVF), keeping
   complex x86 instruction decoding inside the Wasm sandbox rather than native Ring 0 code.
5. **Slotless `MemObj` GPA Mapping + Fast Ring-0 Doorbells**: Map guest physical memory via
   `(gpa, size, MemObjId, offset, MemProt)` with no `hva` or `slot` IDs, and route Virtio
   `QueueNotify` writes via `register_doorbell` in Ring 0 with **zero Wasm transitions**.

Section 2 audits current `/dev/kvm` assumptions, Section 3 surveys hypervisor APIs and KVM Ring-0
internals, Section 4 specifies the target architecture in detail, Section 5 lays out an incremental
4-phase migration plan, and Appendix A summarizes rejected/partial alternatives.

---

## 2. Audit: Why Current `VmmHostCore` Is Still `/dev/kvm` in Disguise

Inspecting [`vmm-core-host/src/wasm_host.rs`](vmm-core-host/src/wasm_host.rs) and
[`vmm-core/src/host.rs`](vmm-core/src/host.rs) exposes seven categories of KVM-specific or
Ring-3-specific assumptions:

### 2.1 POSIX File-Descriptor Hierarchy for a Single-VM Instance

Today, `VmmHostCore` exposes **seven distinct handle types** and 14 create/close lifecycle methods:
- `hv_new` / `hv_close` (`open("/dev/kvm")`)
- `hv_create_vm` / `vm_close` (`ioctl(kvm_fd, KVM_CREATE_VM)`)
- `vm_create_vm_memory` / `vm_memory_close` (a synthetic singleton wrapper around `vm_fd` that
  returns `Error::CreatingMultipleMemory` if called twice)
- `vm_memory_alloc_anon_mem` / `mem_pages_close` (`mmap` region handle)
- `vm_create_vcpu` / `vcpu_close` (`ioctl(vm_fd, KVM_CREATE_VCPU)`)
- `vm_create_intx_sender` / `intx_sender_close` (`eventfd` + `KVM_IRQFD`)
- `vm_create_msi_sender` / `msi_sender_close` (another synthetic wrapper around `vm_fd`)

In both Ring 3 and Ring 0, **one `vmm-core` Wasm instance corresponds to one VM partition**, and
vCPUs are densely numbered `0..num_cpus`. Maintaining seven `RwLock<HashMap<Handle, Arc<...>>>`
resource tables in [`vmm-core-host/src/linux_host.rs`](vmm-core-host/src/linux_host.rs) adds lock
contention on every VM exit (`self.vcpus.get(vcpu)?.lock().run(...)`) purely to emulate `/dev/kvm`'s
multi-FD hierarchy.

### 2.2 Guest Memory Model: `hva: u64`, `slot: u32`, `alloc_anon_mem`, and `msync`

```rust
fn vm_memory_alloc_anon_mem(&self, mem: Handle, size: u64) -> HvResult<(Handle, u64, u64)>;
fn vm_memory_mem_map(
    &self,
    mem: Handle,
    slot: u32,
    gpa: u64,
    size: u64,
    hva: u64,
    option: MemMapOption,
) -> HvResult<()>;
fn vm_memory_unmap(&self, mem: Handle, slot: u32, gpa: u64, size: u64) -> HvResult<()>;
fn vm_memory_max_mem_slots(&self, mem: Handle) -> HvResult<u32>;
fn mem_pages_sync(&self, pages: Handle) -> HvResult<()>;
```

- **Leaked Host Virtual Address (`hva: u64`)**: `vmm-core` cannot dereference `hva`; it caches
  `hva` inside Wasm solely to hand it back to `vm_memory_mem_map`
  (`KVM_SET_USER_MEMORY_REGION.userspace_addr`) and `register_encrypted_range`. In **Ring 0 (Motor
  OS or Linux kernel)**, guest RAM is backed by **physical page frames / folios (HPAs/PFNs)**
  mapped directly into hardware EPT/NPT -- not necessarily mapped contiguously into a userspace
  `mm_struct` virtual address range.
- **KVM `slot: u32` & `max_mem_slots`**: Numbered memory slots are strictly an artifact of Linux
  KVM's internal `struct kvm_memslots` array (`virt/kvm/kvm_main.c`). **MSHV, Hyper-V, macOS
  `Hypervisor.framework`, FreeBSD `bhyve`, and Xen do not have `slot` IDs** -- they map and unmap
  Stage-2 translations directly by `(gpa, size)`.
- **`mem_pages_sync` (`libc::msync`)**: Only meaningful for POSIX file-backed `mmap` (`pmem`),
  meaningless for physical frames in Ring 0.

### 2.3 The Hidden Iceberg of `KVM_CREATE_IRQCHIP`

In [`vmm-core-host/src/kvm/kvm.rs`](vmm-core-host/src/kvm/kvm.rs), `Kvm::create_vm()` silently
invokes:

```rust
unsafe { kvm_create_irqchip(&kvm_vm.fd) }?;
unsafe { kvm_set_tss_addr(&kvm_vm.fd, 0xf000_0000) }?;
unsafe { kvm_set_identity_map_addr(&kvm_vm.fd, &0xf000_3000) }?;
```

Because of that single `kvm_create_irqchip` call, `vmm-core` implicitly assumes the host implements
**three complex x86 hardware subsystems**:
1. **I/O APIC at `0xfec0_0000`**:
   [`vmm-core/src/hw/firmware/acpi/acpi.rs`](vmm-core/src/hw/firmware/acpi/acpi.rs) places an
   IOAPIC at `0xfec0_0000` in the ACPI MADT and wires `COM1` to GSI 4 in `dsdt.dsl`, yet `vmm-core`
   has **zero IOAPIC code**. Neither MSHV, macOS `Hypervisor.framework`, nor a clean Ring 0 Motor
   OS VMX driver has an in-kernel IOAPIC!
2. **Legacy 8259A PICs**: Created by `KVM_CREATE_IRQCHIP` (ports `0x20`/`0xa0`), plus
   edge/pulse-only `IntxSender::send()` (via `KVM_IRQFD`) instead of architectural level-triggered
   `set_irq_line(gsi, level: bool)` semantics.
3. **Local APIC & SMP `INIT`/`SIPI` State Machine**: In
   [`vmm-core/src/hw/board.rs`](vmm-core/src/hw/board.rs), only `vcpu 0` (BSP) calls
   `init_boot_vcpu`! Application Processors (`vcpu 1..N`) enter `vcpu.run(VmEntry::None)`
   uninitialized. On KVM, this works *only* because `kvm_arch_vcpu_create` puts `vcpu > 0` into
   `KVM_MP_STATE_UNINITIALIZED` (Wait-for-SIPI), blocks the thread inside `KVM_RUN`, intercepts BSP
   writes to the `ICR` register in KVM's in-kernel `lapic.c`, transitions the AP to
   `SIPI_RECEIVED`, loads `CS = vector << 8, RIP = 0`, and wakes the AP! On raw Ring 0 VMX/SVM or
   macOS HVF, APs would immediately triple-fault at `0xffff_fff0` unless `MpState` / `INIT`-`SIPI`
   is explicitly modeled.

### 2.4 Pre-Decoded `VmExit::Mmio` vs. Hardware Reality

`VmmHostCore::vcpu_run` currently returns:

```rust
VmExit::Mmio { addr: u64, write: Option<u64>, size: u8 }
```

On x86_64 hardware, **neither Intel VT-x (`EXIT_REASON_EPT_VIOLATION`) nor AMD-V (`VMEXIT_NPF`)
decodes MMIO instructions in silicon!** Unlike `IN`/`OUT` port I/O (where VMX/SVM exit
qualification encodes port, size, direction, and uses `RAX`), an x86 EPT fault only provides the
faulting `GPA`, `GLA`, access bits, and (with hardware decode assists) up to 15 raw instruction
bytes.
- KVM bridges this gap inside the Linux kernel via `arch/x86/kvm/emulate.c` (~10,000 lines of C
  that walk guest page tables and interpret x86 instructions, historically a major source of kernel
  CVEs).
- **MSHV / Hyper-V** and **macOS `Hypervisor.framework`** refuse to put a full x86 instruction
  interpreter in Ring -1 / Ring 0; they return raw fault metadata + instruction bytes, requiring
  the VMM to decode MMIO instructions.
- If `VmmHostCore` only supports pre-decoded `VmExit::Mmio`, **Motor OS would be forced to put a
  complex x86 instruction decoder and guest page-table walker into trusted native Ring 0 code**,
  defeating the primary security goal of sandboxing `vmm-core` in Wasm!

### 2.5 Chatty Register API & Missing Architectural State

- `VmmHostCore` has **six** separate register methods (`vcpu_get_reg`, `vcpu_set_regs`,
  `vcpu_get_seg_reg`, `vcpu_get_dt_reg`, `vcpu_get_sreg`, `vcpu_set_sregs`), where reading `k`
  single registers in `KvmVcpu` executes `k` separate `KVM_GET_REGS` / `KVM_GET_SREGS` calls.
- It lacks **MSR access (`get_msrs` / `set_msrs`)** and **`VmExit::Msr` / `VmExit::Cpuid` /
  `VmExit::Hlt`**, which raw Ring 0 hypervisors, MSHV, and macOS HVF surface to the VMM.
- It lacks **Ring 0 vCPU thread migration hooks** (e.g., `VMCLEAR` / `VMPTRLD` when a kernel
  scheduler moves a vCPU task across physical cores).

### 2.6 Ring-3 Threading, Signals, WASI, & Heap Allocations

- **WASI & Threads**: `vmm-core` compiles to `wasm32-wasip1-threads`, importing
  `"wasi"::"thread-spawn"` and ~20 `wasi_snapshot_preview1` functions, pulling `wasmtime-wasi` into
  `vmm-core-host`.
- **Blocking inside Wasm**: `vmm-core` blocks threads on `memory.atomic.wait32` (`mp_sync`
  `Condvar`, `mpsc::channel`) and blocks the main Wasm thread inside `core_serial_rx()` waiting on
  a host `Condvar`.
- **POSIX Signals**: `KvmVm::stop_vcpu` uses `pthread_self()` + `pthread_kill(SIGRTMIN)` --
  non-existent in Ring 0.
- **Heap Allocations & `std::io::Error`**: `VmmHostCore` uses `std::io::Error`, `String`, and
  `Vec<T>` in trait signatures and allocates temporary `Vec`s in `wasm_host.rs` on every
  `vcpu_set_regs`, `core_virtio_update_irq`, and `core_serial_rx` call -- unsuitable for
  `#![no_std]` Ring 0 hot paths.

### 2.7 Conflating Hardware Virtualization with Virtio/UART IPC

`VmmHostCore` mixes hypervisor primitives with 9 Virtio/Serial-specific bridge methods
(`core_virtio_start`, `core_virtio_notify`, `core_virtio_update_irq`, `core_serial_tx`,
`core_serial_rx`, etc.). Inside Linux KVM, the kernel knows nothing about Virtio PCI layouts -- it
exposes generic **`ioeventfd` (fast MMIO/PIO doorbell matching)** and **`irqfd` (interrupt
injection tokens)** so steady-state `QueueNotify` writes never even exit to the VMM!

---

## 3. Survey of Hypervisor APIs & Linux KVM Internals

### 3.1 How KVM Works *Inside* the Linux Kernel (`virt/kvm/` & `arch/x86/kvm/`)

Inside Ring 0, KVM's internal architecture looks completely different from `/dev/kvm` `ioctl`s:

```text
Linux Kernel Ring 0 (virt/kvm/ + arch/x86/kvm/)
+-------------------------------------------------------------------------+
| kvm_arch_vcpu_ioctl_run() Loop                                          |
|   1. Check pending requests (KVM_REQ_TLB_FLUSH, KVM_REQ_EVENT, etc.)    |
|   2. Inject pending LAPIC / exception events via kvm_x86_ops            |
|   3. Disable IRQs -> kvm_x86_ops.vcpu_run() [VMLAUNCH/VMRESUME/VMRUN]   |
|   4. On VM-Exit, handle fast paths IN-KERNEL before ever exiting:       |
|      - External IRQ / Host Timer -> handle host IRQ & re-enter          |
|      - EPT Violation on RAM      -> tdp_page_fault() (GFN -> PFN)       |
|      - HLT                       -> kvm_vcpu_halt() (rcuwait block)     |
|      - APIC / x2APIC / Timer MSR -> lapic.c + hrtimer / APICv           |
|      - PIO / MMIO on kvm_io_bus  -> ioeventfd wakeup (0 VMM exits!)     |
|   5. Slow path ONLY: return exit to VMM device model                    |
+-------------------------------------------------------------------------+
```

Key internal mechanisms that directly inform our target design:
- **`struct kvm_x86_ops`**: The internal trait between generic KVM (`kvm.ko`) and hardware
  (`kvm-intel.ko` / `kvm-amd.ko`) is ultra-narrow: VMCS/VMCB lifecycle, `vcpu_load`/`vcpu_put`
  (per-pCPU `VMPTRLD`/`VMCLEAR` via preemption notifiers), lazy register dirty/avail bitmaps
  (`vcpu->arch.regs_avail` / `regs_dirty`), `vcpu_run`, interrupt injection, and `tlb_remote_flush`.
- **Two-Dimensional Paging (`tdp_mmu.c`)**: Maps `GFN` -> `PFN` lazily in EPT/NPT page tables,
  using sequence locks + RCU and remote IPI TLB shootdowns (`INVEPT`) on unmap/dirty-log changes.
- **Fast In-Kernel `kvm_io_bus` (`ioeventfd`)**: Sorted RCU array of `(addr, len, datamatch)`
  ranges. When a guest vCPU writes to Virtio `QueueNotify`, `kvm_io_bus` signals the `eventfd`
  directly in Ring 0 and immediately resumes `VMRESUME` -- avoiding >90% of steady-state VMM exits.
- **`kvm_vcpu_kick()` (No Signals!)**: Sets a request bit / `immediate_exit` and either wakes
  `vcpu->wait` (`rcuwait`) if halted or sends a **physical host reschedule IPI**
  (`smp_send_reschedule(pcpu)`) to force an immediate `EXTERNAL_INTERRUPT` VM-exit on the remote
  physical CPU.
- **Split IRQChip (`KVM_CAP_SPLIT_IRQCHIP`)**: Security-focused VMMs (Cloud Hypervisor, crosvm,
  QEMU `-machine kernel-irqchip=split`) keep **only the latency-critical Local APIC** in Ring 0
  (for APICv/AVIC, TSC-deadline timer, and IPIs) and move **IOAPIC + 8259 PIC out of the kernel**
  into the VMM!

### 3.2 Microsoft Hypervisor -- MSHV (`/dev/mshv`, WHP, & Hyper-V TLFS)

MSHV exposes Microsoft's Type-1 Hyper-V hypervisor to root-partition VMMs (Cloud Hypervisor,
OpenVMM):
- **Partition + Integer `vp_index: u32`**: No opaque `vcpu` FD at the hypercall layer
  (`HvCallRunVp(partition_id, vp_index)`).
- **Slotless GPA Mapping**: `HvCallMapGpaPages` / `MSHV_MAP_GUEST_MEMORY` takes
  `(guest_pfn, size, backing_pages, flags)` -- **no `slot_id`**.
- **Uniform Batched Register Array**: All registers (GPRs, CRs, segments, descriptor tables, MSRs,
  APIC state, `VpActivityState`) are read/written in batches via
  `HvCallGetVpRegisters` / `HvCallSetVpRegisters(&[(HvRegisterName, HvRegisterValue)])`.
- **No In-Hypervisor IOAPIC or 8259 PIC**: Only per-VP Local APIC / SynIC exists in the hypervisor
  (`MSHV_ASSERT_INTERRUPT` / MSI). VMMs *must* emulate IOAPIC in VMM software.
- **Raw Intercept Messages (No In-Hypervisor x86 Instruction Interpreter)**:
  `HV_X64_MEMORY_INTERCEPT_MESSAGE` returns `gpa`, `gva`, access type, `rip`, `cs` attributes, and
  `instruction_bytes[16]`. The VMM runs a compact safe-Rust instruction emulator.

### 3.3 FreeBSD `bhyve` (`sys/amd64/vmm/vmm.ko` <-> `usr.sbin/bhyve`)

- **Integer `vcpuid` & Memory Objects (`vm_mmap_memseg`)**: Guest RAM is allocated as kernel memory
  objects (`segid` = `VM_SYSMEM`) and mapped into EPT/RVI via `(gpa, segid, segoff, len, prot)` --
  decoupling GPA mappings from userspace virtual addresses (`hva`) and avoiding KVM `slot` IDs.
- **Lesson for Ring 0 Wasm**: `bhyve` put `vioapic`, `vatpic`, and instruction emulation (`vie`)
  into native Ring 0 C (`vmm.ko`) to avoid Ring 0 <-> Ring 3 transitions. Hosting `vmm-core.cwasm`
  in Ring 0 achieves the **same zero-context-switch latency** while keeping `IoApic`, PCIe, UART,
  and instruction emulation **inside the Wasm sandbox**!

### 3.4 macOS `Hypervisor.framework` (`hv_vm_*` on x86_64 & Apple Silicon)

- **Implicit Single-VM Partition**: `hv_vm_create()` binds one VM partition to the caller;
  `hv_vm_map(addr, gpa, size, flags)` and `hv_vm_unmap(gpa, size)` have no VM handle or `slot_id`.
- **Raw Hardware Exits**: Exposes raw VMX / ARM64 `ESR_EL2` (`ISV=1` hardware syndrome for simple
  loads/stores, `ISV=0` fallback to software decode) and `hv_vcpus_exit` host IPI kicks -- **zero
  in-kernel IOAPIC, PIC, or x86 instruction decoder**.

### 3.5 Xen (`HVM` / `PVH` & the `ioreq` Server Model)

- **Hypervisor-Owned Scheduling (Inverted Control!)**: Xen's scheduler runs guest vCPUs directly;
  a device model **never calls `vcpu_run()`**.
- **`ioreq` Shared Page + Non-Blocking Trap Completion**: When a vCPU traps on an emulated I/O
  range, Xen pauses the vCPU, populates `ioreq_t { addr, data, size, dir, vp_id }` in a shared
  page, and notifies the device model via an event channel. The device model processes the `ioreq_t`
  **non-blockingly** and signals completion -- identical to our host-driven `VcpuCommPage` design!

### 3.6 Target Ring 0 Environments: Motor OS vs. Linux Kernel

| Constraint / Feature | Motor OS Kernel (Ring 0)           | Linux Kernel Module (Ring 0)        |
| :------------------- | :--------------------------------- | :---------------------------------- |
| Language & Runtime   | `#![no_std]` + `alloc` microkernel | Rust-for-Linux (`no_std`) / C glue  |
| Concurrency Model    | Strictly non-blocking; async IPC   | `kthread` or `kvm_vcpu_run` hook    |
| Kernel Stack Budget  | Shallow event/task stack           | Strict 16 KiB kernel stack limit!   |
| FPU / SIMD (`xmm`)   | Forbidden without FPU state save   | Forbidden w/o `kernel_fpu_begin()`  |
| Wasm Trap Mechanism  | Explicit checks (no `SIGSEGV`)     | Explicit checks (no `SIGSEGV`)      |
| Guest RAM Backing    | Phys frame cap in EPT + `vmm-io`   | `folio`/`page` array in `tdp_mmu`   |
| vCPU Kick Mechanism  | Atomic exit flag + phys APIC IPI   | `kvm_vcpu_kick` (`rcuwait` + IPI)   |

*(Zero-FP codegen is already enforced via `verify_no_fp.rs`, and Wasmtime supports Ring 0 trap
handling without signals via `Config::signals_based_traps(false)`.)*

### 3.7 Cross-Hypervisor Comparison Matrix

**Table 3.7a: Current `VmmHostCore`, Linux KVM (`SPLIT_IRQCHIP`), and Microsoft MSHV**

| Dimension            | Current VmmHostCore   | Linux KVM (Split)      | Microsoft MSHV          |
| :------------------- | :-------------------- | :--------------------- | :---------------------- |
| VM / vCPU Addressing | 7 opaque Handle maps  | `kvm`, `vcpu_idx: u32` | Partition, `vp_idx:u32` |
| Memory Mapping Key   | `(slot,gpa,size,hva)` | `slot` -> `GFN->PFN`   | `(gpa, size, pages)`    |
| Exposes `slot_id`?   | Yes (`u32`)           | Internal `memslots`    | No                      |
| LAPIC Location       | Host (`IRQCHIP`)      | Host (`lapic` + APICv) | Hypervisor (LAPIC)      |
| IOAPIC & PIC Loc.    | Host (`IRQCHIP`)      | VMM (`SPLIT_IRQCHIP`)  | VMM (none in HV!)       |
| MMIO Insn Decode     | Host (`emulate.c`)    | Host (`emulate.c`)     | VMM (`insn_bytes[16]`)  |
| Register API         | 6 split methods       | `regs`/`sregs` + sync  | Batched `(Name, Val)`   |
| Control Flow         | Guest `vcpu_run()`    | Kernel loop -> exit    | VMM `MSHV_RUN_VP`       |
| Fast Queue Doorbell  | Wasm `virtio_notify`  | `ioeventfd` (0 exits!) | `ioeventfd` (0 exits!)  |

**Table 3.7b: FreeBSD `bhyve`, macOS `Hypervisor.framework`, Xen (`ioreq`), and Target Design**

| Dimension         | FreeBSD bhyve    | macOS HVF         | Xen (ioreq)      | Target Design      |
| :---------------- | :--------------- | :---------------- | :--------------- | :----------------- |
| VM / vCPU Address | `vmctx, vcpuid`  | Implicit, `u64`   | `domid, vcpuid`  | Implicit, `u32`    |
| Memory Map Key    | `(gpa,seg,off)`  | `(gpa,size,uva)`  | Foreign PFN map  | `(gpa,size,obj)`   |
| Exposes `slot`?   | No               | No                | No               | No                 |
| LAPIC Location    | Host (`vlapic`)  | VMM / VMX APICv   | HV (`vlapic`)    | Host thin LAPIC    |
| IOAPIC & PIC Loc. | Host (`vioapic`) | VMM               | HV (HVM) / None  | `vmm-core` (Wasm!) |
| MMIO Insn Decode  | Hybrid (`vie`)   | VMM (raw fault)   | HV (`ioreq`)     | Hybrid (Host/Wasm) |
| Register API      | Indexed / Set    | Indexed `get_reg` | HVM context blob | Batched + CommPage |
| Control Flow      | VMM `vm_run`     | VMM `hv_vcpu_run` | HV -> `ioreq`!   | Host -> Wasm!      |
| Fast Doorbell     | Kernel / user    | VMM exit          | `ioreq` routing  | Ring 0 table (0!)  |

---

## 4. Target Architecture Specification

### 4.1 System Overview & Hardware / Wasm Responsibility Split

```text
+-----------------------------------------------------------------------------------+
| vmm-core (Sandboxed Wasm: wasm32-unknown-unknown, #![no_std] + alloc, 0 WASI)     |
|  - Board init, Guest RAM layout, Kernel/Initrd loader, ACPI (MADT/DSDT/MCFG)      |
|  - PCIe ECAM bus, Virtio PCI modern transport, MSI-X table/PBA, 16450 UART        |
|  - Emulated IOAPIC (0xfec0_0000, ~250 LoC) -> translates GSIs to MSI (addr, data) |
|  - Compact x86_64/ARM64 MMIO Instruction Decoder (for raw VmExit::MmioFault)      |
|  - Pinned `[VcpuCommPage; num_cpus]` in SharedMemory for zero-copy trap exchange  |
+---------------------------+-------------------------------+-----------------------+
                            |                               |
          VmmHostCore trait |                               | VmmCoreBridge trait
      (Pure Virtualization) |                               | (Core <-> IO Split)
                            v                               v
+-----------------------------------------------+ +---------------------------------+
| Ring 0 / Hypervisor Host                      | | Bridge Transport to vmm-io      |
| (Motor OS | Linux Ring 0/3 | MSHV | HVF | Xen)| |  - Boot info & kernel payload   |
|  1. Host-owned vCPU loop / scheduler          | |  - Lock-free C2I / I2C rings    |
|  2. Stage-2 MMU (EPT/NPT: GPA -> HPA/PFN)     | |  - IRQ route table (MSI tokens) |
|  3. VMCS/VMCB + Local APIC (APICv, Timer,     | +----------------+----------------+
|     IPI, INIT/SIPI MpState)                   |                  ^
|  4. Fast Doorbell Table (GPA/PIO match --------+------------------+
|     signals vmm-io directly w/ 0 Wasm calls!) |   (Direct Ring-0 QueueNotify!)
+-----------------------------------------------+
```

This boundary places **every latency-critical or privilege-requiring primitive** in the native host
(Stage-2 page tables, VMX/SVM world switch, APICv/timer/IPI, and 10-line doorbell address matching)
while keeping **every complex, stateful, attack-prone parser and device state machine** inside the
`#![no_std]` Wasm sandbox (ACPI/ELF/bzImage loading, PCIe, Virtio config, UART, IOAPIC, and x86
MMIO instruction decoding).

---

### 4.2 Inverted, Non-Blocking Control Flow & `VcpuCommPage`

Instead of `vmm-core` spawning OS threads and calling a blocking `vcpu_run()` import, **the host
owns the vCPU execution loop** and invokes `vmm-core` exports strictly as non-blocking trap
handlers:

```text
Host / Kernel Scheduler (Motor OS, Linux Kernel, KVM Pthreads, MSHV, or Xen ioreq)
==================================================================================
  1. VM Init:
       - Host instantiates Instance[0], calls `vmm_init()` -> configures RAM, ACPI,
         BSP/AP initial states, and returns pointer to `[VcpuCommPage; num_cpus]`.
       - For SMP parallel mode, host instantiates Instance[1..num_cpus] sharing the
         same `SharedMemory` and calls `vmm_bind_vcpu(vcpu_id, stack_top)` once each.

  2. Per-vCPU Execution Loop (100% Host-Owned):
       loop {
           let exit = host_enter_guest(vcpu_id, &mut comm_page[vcpu_id]);

           // Fast paths handled purely in Host / Ring 0 (NEVER enter Wasm!):
           //  - Host IRQ / preemption  -> handle & re-enter
           //  - Stage-2 RAM page fault -> populate EPT/NPT
           //  - HLT / Wait-for-SIPI    -> sleep until LAPIC timer / MSI / kick IPI
           //  - Fast Doorbell match    -> push VirtioNotify to bridge & re-enter!

           // Slow path ONLY (PIO, PCI ECAM, Virtio cfg, IOAPIC, UART, MMIO fault):
           let action = wasm_call_vmm_on_vcpu_exit(vcpu_id); // <1 us, <4 KiB stack!
           if action != VmAction::Continue { break; }
       }

  3. Asynchronous I/O Events from `vmm-io` (e.g. SerialRx bytes, RequestShutdown):
       - Host wakes on I2C notification and calls `vmm_on_bridge_rx()` non-blockingly.
```

#### Zero-Copy `VcpuCommPage` (Eliminating Per-Exit Register Calls)

Modeled on Linux's `mmap`ped `struct kvm_run` (`KVM_SYNC_REGS`) and MSHV's intercept message page,
each vCPU has a cache-line-aligned `VcpuCommPage` in Wasm linear memory:

```rust
#[repr(C, align(64))]
pub struct VcpuCommPage {
    // Populated by Host before `vmm_on_vcpu_exit(vcpu_id)`:
    pub exit: RawVmExit,          // Exit reason + union payload (PIO, Mmio, MmioFault, ...)
    pub synced_regs: u32,         // Bitmask: GPRs, SREGs, CRs valid in snapshot below
    pub dirty_regs: u32,          // Set by Wasm when modifying snapshot regs (e.g. RAX/RIP)

    // Hot architectural state synced in-place without host calls:
    pub gprs: [u64; 16],          // RAX..R15 (used by PIO, Cpuid, Msr, and MMIO decode)
    pub rip: u64,
    pub rflags: u64,
    pub cr0: u64,
    pub cr3: u64,                 // Used if MMIO decoder walks guest page tables (GVA->GPA)
    pub cr4: u64,
    pub efer: u64,
    pub cs: RawSegReg,            // D/B & L bits determine 16/32/64-bit instruction mode

    // Populated by Wasm before returning from `vmm_on_vcpu_exit(vcpu_id)`:
    pub entry: RawVmEntry,        // Continue, IoComplete(u32), MmioComplete(u64), InjectFault
}
```

With `VcpuCommPage`, an entire PIO read/write or raw `MmioFault` instruction decode + register
writeback + `rip` advance executes inside `vmm_on_vcpu_exit(vcpu_id)` with **zero host register
imports**!

---

### 4.3 `#![no_std]` Rust Interface Specification

#### Wasm Exports (`vmm-core` -> Host)

```rust
// Exported by vmm-core.wasm (target: wasm32-unknown-unknown, #![no_std] + alloc)
extern "C" {
    /// Initialize board, allocate & map Guest RAM, load kernel/ACPI, configure BSP/AP
    /// initial states, and return Wasm offset of `[VcpuCommPage; num_cpus]` (or <0 on err).
    pub fn vmm_init() -> i32;

    /// One-time setup on each worker Instance[vcpu_id]: bind its private `__stack_pointer`
    /// (and TLS base, if used) to a disjoint per-vCPU stack region in SharedMemory.
    pub fn vmm_bind_vcpu(vcpu_id: u32, stack_top: u32);

    /// Handle one synchronous slow-path exit for `vcpu_id` via `comm_page[vcpu_id]`.
    /// Strictly non-blocking; returns VmAction (0 = Continue, 1 = Shutdown, 2 = Reboot).
    pub fn vmm_on_vcpu_exit(vcpu_id: u32) -> i32;

    /// Drain pending control messages from `vmm-io` (e.g. SerialRx -> COM1 FIFO + MSI).
    pub fn vmm_on_bridge_rx() -> i32;
}
```

#### Core Supporting Types & Host Traits (`VmmHostCore` + `VmmCoreBridge`)

```rust
#![no_std]

pub type VcpuId = u32;
pub type MemObjId = u32;

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum HvError {
    InvalidParam = -1,
    NoMemory = -2,
    WouldBlock = -3,
    Interrupted = -4,
    Unsupported = -5,
    HardwareFault = -6,
}

pub type HvResult<T> = core::result::Result<T, HvError>;

bitflags::bitflags! {
    #[derive(Copy, Clone, Debug)]
    pub struct HostCaps: u32 {
        /// Host decodes MMIO exits into `VmExit::Mmio` (e.g. KVM, Xen, ARM64 ISV=1).
        const DECODED_MMIO = 1 << 0;
        /// Host owns an in-hypervisor IOAPIC (`set_gsi_level` supported, e.g. Xen HVM).
        const HW_IOAPIC    = 1 << 1;
        /// Host supports Ring-0 `register_doorbell` fast path.
        const DOORBELLS    = 1 << 2;
    }

    #[derive(Copy, Clone, Debug)]
    pub struct MemProt: u32 {
        const READ  = 1 << 0;
        const WRITE = 1 << 1;
        const EXEC  = 1 << 2;
    }
}

#[derive(Copy, Clone, Debug)]
pub enum IoSpace {
    Pio,
    Mmio,
}

#[derive(Copy, Clone, Debug)]
pub struct DoorbellSpec {
    pub space: IoSpace,
    pub addr: u64,
    pub size: u8,
    pub datamatch: Option<u64>,
    pub dev_id: u32,
    pub queue_idx: u16,
}

pub enum VmExit {
    Io { port: u16, write: Option<u32>, size: u8 },
    /// Returned when host already decoded the access (KVM, Xen, ARM64 ISV=1).
    Mmio { gpa: u64, write: Option<u64>, size: u8 },
    /// Returned by minimal Ring-0 hosts (Motor OS, MSHV, macOS HVF, ARM64 ISV=0).
    /// Synced GPRs, RIP, CR3, EFER, and CS are already in `comm_page[vcpu_id]`.
    MmioFault {
        gpa: u64,
        gva: Option<u64>,
        is_write: bool,
        insn_len: u8,
        insn_bytes: [u8; 15],
    },
    Cpuid { func: u32, index: u32 },
    MsrRead { msr: u32 },
    MsrWrite { msr: u32, val: u64 },
    Shutdown,
    Reboot,
}

/// Pure single-VM hardware virtualization backend (100% non-blocking, zero Virtio/UART!).
pub trait VmmHostCore: Send + Sync + 'static {
    // --- Capabilities & CPUID ---
    fn caps(&self) -> HostCaps;
    fn supported_cpuids(&self, dst: &mut [RawCpuid]) -> HvResult<usize>;

    // --- Cold-Path vCPU Setup & Kick (Hot-path regs live in VcpuCommPage!) ---
    fn vcpu_configure(&self, vcpu: VcpuId, cpuids: &[RawCpuid]) -> HvResult<()>;
    fn vcpu_get_regs(&self, vcpu: VcpuId, ids: &[RegId], out: &mut [RegVal]) -> HvResult<()>;
    fn vcpu_set_regs(&self, vcpu: VcpuId, regs: &[(RegId, RegVal)]) -> HvResult<()>;
    fn vcpu_kick(&self, vcpu: VcpuId) -> HvResult<()>;

    // --- Slotless Physical Memory Objects & Stage-2 GPA Mapping ---
    fn mem_alloc(&self, size: u64) -> HvResult<MemObjId>;
    fn mem_free(&self, obj: MemObjId) -> HvResult<()>;
    fn mem_read(&self, obj: MemObjId, offset: u64, dst: &mut [u8]) -> HvResult<()>;
    fn mem_write(&self, obj: MemObjId, offset: u64, src: &[u8]) -> HvResult<()>;
    fn gpa_map(
        &self,
        gpa: u64,
        size: u64,
        obj: MemObjId,
        offset: u64,
        prot: MemProt,
    ) -> HvResult<()>;
    fn gpa_unmap(&self, gpa: u64, size: u64) -> HvResult<()>;

    // --- Interrupt Injection & Fast-Path Doorbells ---
    fn inject_msi(&self, addr: u64, data: u32) -> HvResult<()>;
    fn set_gsi_level(&self, gsi: u32, active: bool) -> HvResult<()>; // Used iff HW_IOAPIC
    fn register_doorbell(&self, spec: DoorbellSpec) -> HvResult<()>;
    fn unregister_doorbell(&self, space: IoSpace, addr: u64, size: u8) -> HvResult<()>;
}

/// Separate trait for the Core <-> IO Split Channel (decoupled from hypervisor ops).
pub trait VmmCoreBridge: Send + Sync + 'static {
    fn boot_info(
        &self,
        out_info: &mut ShmBootInfo,
        out_devs: &mut [ShmVirtioDeviceSpec],
    ) -> HvResult<usize>;
    fn read_payload(&self, kind: PayloadKind, offset: u64, dst: &mut [u8]) -> HvResult<usize>;
    fn send_io_cmd(&self, entry: &CoreToIoEntry) -> HvResult<()>;
    fn recv_io_cmd(&self, out: &mut IoToCoreEntry) -> HvResult<bool>;
    fn update_irq_route(&self, route_id: u32, msi: Option<(u64, u32)>) -> HvResult<()>;
}
```

---

### 4.4 Chipset, Interrupts, Doorbells, & Hybrid MMIO Decoding

1. **In-Wasm IOAPIC (`0xfec0_0000`) & Pure MSI Boundary**:
   - Moving a ~250-line `IoApic` register model (`IOREGSEL`/`IOWIN` + 24 Redirection Table Entries)
     into `vmm-core` eliminates the hidden dependency on `KVM_CREATE_IRQCHIP`'s kernel IOAPIC/PIC.
   - `COM1` (UART GSI 4) asserts pin 4 on `vmm-core`'s `IoApic`, which formats RTE 4 into
     `host.inject_msi(addr, data)` -- identical to Virtio MSI-X delivery!
   - On Linux, `KvmCoreHost` enables `KVM_CAP_SPLIT_IRQCHIP` (shrinking active kernel attack
     surface). On Motor OS, MSHV, and macOS HVF, `vmm-core` works out of the box without any native
     IOAPIC code. (If `HostCaps::HW_IOAPIC` is set, e.g. Xen HVM, `vmm-core` delegates to
     `set_gsi_level` instead.)
2. **Explicit SMP `MpState` (`INIT` / `SIPI`)**:
   - `RegId::MpState` (`Runnable`, `Uninitialized` / Wait-for-SIPI, `Halted`) is explicitly set
     during `vmm_init()` (`BSP = Runnable`, `APs = Uninitialized`), matching `KVM_SET_MP_STATE`,
     MSHV `VpActivityState`, and Motor OS Ring-0 LAPIC `ICR` wakeup handling.
3. **Ring-0 Fast Doorbells (`register_doorbell`)**:
   - When the guest enables `VirtioPciDevice` BAR0, `vmm-core` registers each queue's notify address
     via `register_doorbell`.
   - On Linux KVM (`KVM_IOEVENTFD`), MSHV (`MSHV_IOEVENTFD`), or Motor OS Ring 0 (a small sorted
     array checked on EPT/PIO exit before entering Wasm), guest `QueueNotify` writes push directly
     to the `vmm-io` bridge and immediately resume the guest with **0 Wasm calls**.
4. **Hybrid MMIO Decoding (`VmExit::Mmio` + `VmExit::MmioFault`)**:
   - Hosts that already decode MMIO (Linux KVM, Xen `ioreq`, ARM64 `ESR_EL2` with `ISV=1`) emit
     `VmExit::Mmio`.
   - Minimal Ring-0 hosts (Motor OS, MSHV, macOS HVF, ARM64 `ISV=0`) emit `VmExit::MmioFault` with
     up to 15 instruction bytes (fetched by hardware VMX/SVM assist or via `cs:rip` -> `cr3`).
     `vmm-core` decodes common MMIO instructions (`MOV`, `MOVZX`, `MOVSX`, `AND`/`OR`/`CMP`, `STOS`,
     `MOVS`) in safe, float-free Rust inside Wasm, updating `comm_page.gprs` and `comm_page.rip`.

---

### 4.5 Concurrent Execution & Shared-Memory ABI in `#![no_std]` Wasm

The host **can** invoke `vmm_on_vcpu_exit(vcpu_id)` concurrently across physical CPUs, and those
concurrent calls **can** safely read and mutate the same shared Rust data structures (`Board`,
`PciBus`, `IoApic`, `Serial`, `VirtioPciDevice`, `[VcpuCommPage]`) in linear memory.

Wasmtime does not allow concurrent calls on a *single* `(Store, Instance)` (`TypedFunc::call`
requires `&mut Store`, and each `Instance` owns a single `__stack_pointer` global). Instead, at VM
init the host pre-instantiates **`num_cpus` lightweight `(Store, Instance)` pairs bound to one
`wasmtime::SharedMemory`**. Because every `Instance` imports the same `("env", "memory")`, any
32-bit Wasm pointer (`&BOARD`, `Arc<...>`) resolves to the exact same bytes across all vCPUs.

Moving from `wasm32-wasip1-threads` (`wasi-libc` `wasi_thread_start`) to `#![no_std]`
(`wasm32-unknown-unknown`) requires **four low-level ABI invariants** for race-free concurrency:

1. **Disjoint Per-Instance Shadow Stacks (`__stack_pointer`)**:
   - *Pitfall*: Every newly instantiated `Instance[0..N]` initializes its private `global[0]`
     (`__stack_pointer`) to the same link-time `__stack_high` constant; concurrent calls would
     clobber each other's shadow stack frames in `SharedMemory`.
   - *Fix*: `vmm_init()` reserves `num_cpus` disjoint shadow stacks (e.g., `16 KiB` each) in
     `SharedMemory`, and the host calls `vmm_bind_vcpu(vcpu_id, stack_top)` once on each worker
     `Instance[vcpu_id]` before any `vmm_on_vcpu_exit(vcpu_id)` runs.
2. **Passive Data Segments (`--shared-memory` + `--import-memory`)**:
   - *Pitfall*: Active Wasm `data` segments would re-copy `.data` initializers into `SharedMemory`
     when `Instance[1..N]` are instantiated, overwriting state initialized by `vmm_init()`.
   - *Fix*: Link with `-Clink-arg=--import-memory`, `-Clink-arg=--shared-memory`, and
     `-Clink-arg=--max-memory=...` so `wasm-ld` emits passive segments guarded by an atomic
     once-flag in `__wasm_init_memory`.
3. **True Hardware Atomics in `core` & `alloc` (`+atomics` + `-Z build-std`)**:
   - *Pitfall*: Prebuilt `libcore` for `wasm32-unknown-unknown` lacks `+atomics`, causing LLVM to
     lower `core::sync::atomic` RMWs to **non-atomic** loads and stores!
   - *Fix*: Compile with `RUSTFLAGS="-C target-feature=+atomics,+mutable-globals"` **and**
     `-Z build-std=core,alloc` (or a custom target JSON) so Cranelift emits real `LOCK CMPXCHG` /
     `LOCK XADD` instructions.
4. **Non-Blocking Spinlocks & Thread-Safe `#![global_allocator]`**:
   - Replace `std::sync::Mutex` (`memory.atomic.wait32` futex) with short-hold `spin::Mutex` /
     `spin::RwLock` on shared devices (`PciBus`, `IoApic`, `Serial`, Virtio config). In Ring 0, run
     the sub-microsecond `vmm_on_vcpu_exit()` call with kernel preemption disabled (or spin-backoff
     `host_yield()` on overcommitted Ring 3 threads) so a vCPU never spins on a descheduled holder.
   - Wrap `#![global_allocator]` (e.g., `talc`) in `spin::Mutex`, and keep `vmm_on_vcpu_exit()`
     allocation-free after `vmm_init()`.

*(Optional ultra-tiny Ring 0 mode)*: Because Ring 0 handles `LAPIC`, `HLT`, EPT faults, and
`QueueNotify` doorbells without entering Wasm, memory-constrained hosts can alternatively serialize
slow-path exits through a **single** `(Store, Instance)`:

| Mode                  | Wasm Instances     | Shared State Access    | Best Fit               |
| :-------------------- | :----------------- | :--------------------- | :--------------------- |
| Per-vCPU `SharedMem`  | `N` `(Store,Inst)` | Parallel (`spin` lock) | SMP + heavy MMIO emul  |
| Single Locked `Store` | `1` `(Store,Inst)` | Host-serialized        | Tiny Ring 0 footprint  |

---

### 4.6 How `VmmHostCore` Maps Across Target Hosts

| Host Trait Primitive | Linux Ring 3 (KVM)      | Motor OS Ring 0        | MSHV / HVF / Xen       |
| :------------------- | :---------------------- | :--------------------- | :--------------------- |
| `gpa_map` / `unmap`  | Priv slot -> `USER_MEM` | Direct EPT/NPT map     | `MAP_GPA` / `hv_map`   |
| `VcpuCommPage` sync  | Copy <-> `kvm_run`      | VMCS/VMCB + GPR save   | Intercept / `ioreq_t`  |
| `vcpu_kick(vcpu)`    | `immediate_exit` + wake | Atomic flag + APIC IPI | `hv_vcpus_exit`/evtchn |
| `inject_msi(a, d)`   | `KVM_SIGNAL_MSI`        | LAPIC/APICv PIR + IPI  | `ASSERT_IRQ` / MSI     |
| `register_doorbell`  | `IOEVENTFD` -> `c2i_fd` | Ring-0 table -> `Shm`  | `IOEVENTFD` / `ioreq`  |
| MMIO Exit Variant    | `VmExit::Mmio`          | `VmExit::MmioFault`    | `MmioFault` / `Mmio`   |

---

## 5. Incremental 4-Phase Refactoring Roadmap

Each phase keeps `./local_test/run-vm-initrd.sh` and `./local_test/run-vm.sh` (`--cwasm` and
`--wasm`) booting and passing end-to-end:

1. **Phase 1 -- Clean Partition Surface & `VmmHostCore` / `VmmCoreBridge` Split**:
   - Split `VmmHostCore` into `VmmHostCore` (hypervisor) + `VmmCoreBridge` (Core <-> I/O IPC).
   - Collapse the 7 `Handle` resource tables into implicit single-VM partition semantics + dense
     `VcpuId(u32)` and `MemObjId(u32)` arrays (zero `RwLock<HashMap>` contention on exits).
   - Remove `slot: u32`, `max_mem_slots`, `hva: u64`, and `mem_pages_sync` from `VmmHostCore`
     (manage KVM `memslots` privately inside `KvmCoreHost`).
   - Replace the 6 split register methods with batched `vcpu_get_regs` / `vcpu_set_regs` (adding
     MSRs and `MpState`) and `#![no_std]` `HvError` (zero `Vec`/`String` allocations in host glue).
2. **Phase 2 -- Fast Doorbells (`ioeventfd`) & Split-IRQChip (`IoApic` in `vmm-core`)**:
   - Add `register_doorbell` / `unregister_doorbell` to `VmmHostCore` (wired to `KVM_IOEVENTFD` on
     Linux and a direct address-match table in Ring 0) so Virtio `QueueNotify` skips Wasm.
   - Implement `IoApic` (`0xfec0_0000`, ~250 LoC) inside `vmm-core`, switch `KvmCoreHost` from
     `KVM_CREATE_IRQCHIP` to `KVM_CAP_SPLIT_IRQCHIP`, and route all UART + Virtio interrupts via
     `inject_msi(addr, data)`.
3. **Phase 3 -- `VcpuCommPage`, Hybrid `VmExit::MmioFault`, & In-Wasm Instruction Decoder**:
   - Introduce `VcpuCommPage` for zero-call hot register sync on PIO/MMIO exits.
   - Add `VmExit::MmioFault` and a compact, float-free x86_64 MMIO instruction decoder in
     `vmm-core` (unit-tested against `MOV`, `MOVZX`, `MOVSX`, `AND`/`OR`/`CMP`, `STOS`, `MOVS`),
     unlocking Motor OS Ring 0, MSHV, and macOS HVF without a Ring-0 instruction interpreter.
4. **Phase 4 -- Invert Control Flow & Migrate `vmm-core` to `#![no_std]`
   (`wasm32-unknown-unknown`)**:
   - Refactor `vmm-core` from guest-driven `vcpu_run()` + `core_serial_rx()` threads to host-driven
     exports: `vmm_init()`, `vmm_bind_vcpu(vcpu_id, stack_top)`, `vmm_on_vcpu_exit(vcpu_id)`, and
     `vmm_on_bridge_rx()`.
   - Switch `vmm-core` from `wasm32-wasip1-threads` to `wasm32-unknown-unknown` (`#![no_std]` +
     `alloc` with `+atomics`, `-Z build-std=core,alloc`, `--shared-memory`, `spin::Mutex` device and
     allocator locks, and per-vCPU disjoint `__stack_pointer`s).
   - Remove `wasmtime-wasi` from `vmm-core-host` and enable Ring-0 Wasmtime settings
     (`signals_based_traps(false)`, static explicit bounds checks).

---

## Appendix A: Rejected / Partial Design Alternatives

During analysis, three alternative points in the design space were evaluated and set aside as the
final architecture (though Alternatives 1 and 2 correspond naturally to Phases 1-2 above):

### A.1 Alternative 1: Guest-Driven Cleaned-Up Partition Trait

Keep `vmm-core`'s guest-driven `vcpu_run()` threads and host-side IOAPIC/MMIO decoding, while only
cleaning up handles, `slot`/`hva`, batched registers, and `#![no_std]` error types.
- **Pros**: Smallest initial diff to `vmm-core`'s `Board::vcpu_loop`; removes KVM handle/slot/HVA
  artifacts.
- **Cons**: Still requires Wasm thread spawning (`wasi::thread-spawn`), persistent blocked Wasm
  call stacks across `vcpu_run` (unsafe for 16 KiB Linux kernel stacks and incompatible with Motor
  OS non-blocking scheduling or Xen `ioreq`), and still forces Motor OS / MSHV / HVF hosts to
  implement IOAPIC and x86 MMIO instruction decoding outside Wasm.

### A.2 Alternative 2: Guest-Driven Split-IRQChip + Doorbells (Without Control Inversion)

Move `IoApic` and fallback MMIO instruction decoding into `vmm-core` and add `register_doorbell`,
but keep `vmm-core` owning the `vcpu_run()` loop (`wasm32-wasip1-threads`).
- **Pros**: Achieves the small Ring-0 hardware TCB and 0-Wasm-call `QueueNotify` fast path; works
  on Ring-3 KVM, MSHV, `bhyve`, and macOS HVF.
- **Cons**: Retains ~21 WASI imports, `wasmtime-wasi`, blocking `memory.atomic.wait32` futexes, and
  deep pinned Wasm stacks across `vcpu_run()`, preventing clean non-blocking execution in Motor OS
  Ring 0, Linux 16 KiB kernel stacks, and Xen `ioreq`.

### A.3 Alternative 3: Ultra-Thin Raw Hardware Host + Wasm Multi-Memory ("macOS HVF Limit")

Move **even Local APIC register emulation, timers, and raw VMCS/VMCB state** into `vmm-core` Wasm,
and map Guest RAM directly as a second 64-bit Wasm linear memory (`multi-memory` + `memory64`).
- **Pros**: Smallest conceivable native Ring-0 glue (~500-800 LoC); zero-copy `RamBus` slice access
  in Wasm without `mem_read`/`mem_write` calls.
- **Cons**: Severe SMP/timer performance regression from trapping `ICR`/`TPR`/`EOI`/timer accesses
  into Wasm instead of using hardware **APICv/AVIC**; leaks Intel VMCS vs. AMD VMCB layouts into
  `vmm-core` (breaking KVM and MSHV portability); `memory64` + `shared_memory` in `#![no_std]`
  Wasmtime is still maturing (note: `memory64` can still be added later as an optional `RamBus`
  fast path on top of the target architecture).

### A.4 Summary Comparison

| Criterion          | Target Design     | Alt 1: Partition | Alt 2: Split+DB  | Alt 3: Raw HVF    |
| :----------------- | :---------------- | :--------------- | :--------------- | :---------------- |
| Control Flow       | Host -> Wasm      | Guest `vcpu_run` | Guest `vcpu_run` | Host or Guest     |
| Wasm Target        | `unknown-unknown` | `wasip1-threads` | `wasip1-threads` | `unknown`+`mem64` |
| `#![no_std]` Core? | Yes (0 WASI)      | No (~21 WASI)    | No (~21 WASI)    | Yes (0 WASI)      |
| Ring 0 Non-Block?  | Yes (100%)        | No               | No               | Yes               |
| 16 KiB KStack OK?  | Yes (< 4 KiB)     | No               | No               | Yes               |
| IOAPIC/MMIO Decode | In Wasm           | In Host          | In Wasm          | In Wasm (+LAPIC)  |
| Hardware APICv?    | Yes (Fast SMP)    | Yes              | Yes              | No (Slow IPI/TMR) |
| Motor OS Ring0 TCB | Smallest Viable   | Medium-Large     | Moderate (WASI)  | Tiny (no APICv!)  |
| KVM / MSHV / HVF   | All Native        | KVM (`bhyve`)    | All Native       | HVF / Raw VMX     |
| Xen `ioreq`        | Yes (Native!)     | No               | No               | No                |
| Virtio QueueNotify | 0 Wasm calls!     | Wasm round-trip  | 0 Wasm calls!    | 0 Wasm calls      |
