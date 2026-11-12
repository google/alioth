# Airlock on Motor OS: Ring-0 `vmm-core-host` & Ring-3 `vmm-io-host` Design

## 1. Overview & Motivation

Across [`design.md`](design.md), [`split-vmm.md`](split-vmm.md), and
[`vmm-core-kernel.md`](vmm-core-kernel.md), **WASM VMM** (`alioth-vmm`) has been
refactored into a two-plane architecture specifically designed to move the hot
VM-exit path into an OS kernel (Ring 0) while keeping complex emulation inside a
sandboxed WebAssembly airlock:

1. **`vmm-core` (`wasm32-unknown-unknown`, `#![no_std] + alloc`, 0 WASI, 0 FP/SIMD)**:
   Owns guest physical address layout (`RamBus`), `bzImage` / Xen PVH loading,
   ACPI tables (`RSDP`, `XSDT`, `FADT`, `DSDT`, `MADT`, `MCFG`), PCIe ECAM,
   Virtio PCI modern transport (`CommonCfg`, `NotifyCfg`, `IsrStatus`,
   `DeviceCfg`, MSI-X), 16450 UART (`0x3f8`), an in-Wasm `IoApic`
   (`0xfec0_0000`), and an in-Wasm x86_64 MMIO instruction decoder
   (`VmExit::MmioFault`). Driven by the host via non-blocking exports
   (`vmm_init`, `vmm_on_vcpu_exit`, `vmm_on_bridge_rx`) over cache-line-aligned
   `VcpuCommPage` frames against `VmmHostCore` and `VmmCoreBridge`.
2. **`vmm-io` (`wasm32-wasip1-threads`) + `vmm-io-host` (`VmmHostIo`)**:
   Runs in userspace (Ring 3). Owns `vm.toml` parsing, boot payload loading,
   Virtio `SplitQueue` descriptor-ring walking over shared Guest RAM,
   `virtio-blk`, `virtio-net`, and serial console I/O, communicating with the
   core side through lock-free shared-memory rings (`BridgeShm`) and doorbells.

### Why Port to Motor OS Ring 0 First?

Motor OS is an ideal proving ground before porting `vmm-core-host` into the
Linux kernel:
- **Pure `#![no_std] + alloc` Rust Microkernel**: `motor-os/src/sys/kernel` is
  already written in Rust with non-preemptible Ring-0 execution, explicit
  per-CPU cooperative job scheduling (`sched::Scheduler`), direct physical
  memory mapping (`PAGING_DIRECT_MAP_OFFSET`), and strict `W^X` enforcement.
- **Native Shared-Memory + Wait/Wake IPC**: Motor OS's four-syscall interface
  (`SYS_OBJ`, `SYS_MEM`, `SYS_CPU`, `SYS_RAY`) is built around shared physical
  pages (`SysMem` / `SysObj` `shared:...`) paired with non-blocking wait/wake
  handles (`SysCpu::wait` / `SysCpu::wake`)—matching `BridgeShm` with zero
  POSIX file-descriptor or signal impedance mismatch.
- **Existing Wasmtime Ecosystem**: Motor OS already maintains a Wasmtime port
  (`moturus/wasmtime`, v50.0.0) with explicit bounds/trap checks
  (`signals_based_traps(false)`), `W^X` dual-alias code publishing, and
  userspace WASI support.

This document lays out:
- **Section 2**: The end-to-end development roadmap (`(a1)`/`(a2)` through `(g)`)
  and the cross-host and repository-boundary invariants.
- **Section 3**: High-level architecture of `vmm-core-host` (Ring 0) and
  `vmm-io-host` (Ring 3) on Motor OS, maintained entirely inside `alioth-vmm`.
- **Sections 4–6**: Detailed designs for **Step (a)** (`(a1)` copying Motor OS
  `kernel` + `kloader` into `alioth-vmm/tests/`, and `(a2)` creating `test-init`
  + `initrd-test-guest` in `alioth-vmm/tests/`), **Step (b)** (booting
  `test-guest` in `wasm-vmm`), and **Step (c)** (porting `vmm-core-host` into
  the copied Motor OS kernel in `alioth-vmm/tests/kernel`).

---

## 2. End-to-End Development Roadmap (`a` – `g`)

```text
  (a1) Copy Motor OS `kernel` + `x64.kloader` under `alioth-vmm/tests/`
       (1st commit: pure verbatim source copy; 2nd: wire `../motor-dev` paths)
    |
    v
  (a2) Create `test-init` crate + `initrd-test-guest` packager in `alioth-vmm/tests/`
    |
    v
  (b)  Boot `test-guest` in Linux `wasm-vmm` (`tests/` + `vm_scripts/`; PVH, S5, SVM/VMX)
    |
    v
  (c)  Port `vmm-core-host` into `alioth-vmm/tests/kernel` (Ring 0: SVM/VMX + NPT/EPT + Wasm)
    |
    v
  (d)  Nested self-hosting smoke: Linux `wasm-vmm` [L0] -> `test-guest` [L1] -> `test-guest` [L2]
    |
    v
  (e)  Nested full Motor OS: Ring-3 `vmm-io-host` + `vmm-io.cwasm` staged via `imager`
    |
    v
  (f)  Nested Alpine Linux: `bzImage` boot, Linux MSR/CPUID/xAPIC/IOAPIC & MMIO decode coverage
    |
    v
  (g)  Port Ring-0 `vmm-core-host` to Linux Kernel (kthread / folios / tdp_mmu, <16 KiB stack)
```

| Step     | Milestone            | Key Deliverables               | Exit Criteria               |
| :------- | :------------------- | :----------------------------- | :-------------------------- |
| **(a1)** | **Copy `kernel` +**  | Copy Motor OS `kernel` &       | 1st commit is pure verbatim |
|          | **`kloader` into**   | `x64.kloader` under            | copy (`diff = 0`); 2nd      |
|          | **`tests/`**         | `alioth-vmm/tests/`; 1st       | wires `../motor-dev` paths  |
|          |                      | commit has 0 source changes.   | & builds `kloader` ELF.     |
| **(a2)** | **Create**           | `alioth-vmm/tests/test-init`   | Builds reproducibly in      |
|          | **`test-init` &**    | crate + `initrd-test-guest`    | `alioth-vmm`; 0 disks/NICs; |
|          | **`test-guest`**     | packager (0 edits to           | logs HV caps on `COM1` &    |
|          |                      | `motor-os`).                   | exits via ACPI S5.          |
| **(b)**  | **Boot**             | `tests/tests/boot_vms.rs` +    | `cargo test` &              |
|          | **`test-guest`**     | `vm_scripts/run-test-guest.sh` | `run-test-guest.sh`         |
|          | **in `wasm-vmm`**    | (`--wasm` & `--cwasm`); nested | (`--wasm`/`--cwasm`) log    |
|          |                      | `SVM`/`VMX` pass-through.      | `hv=svm`/`vmx` & exit `0`.  |
| **(c)**  | **Port Core Host**   | `tests/kernel/src/vmm/`:       | `tests/kernel` builds with  |
|          | **to Motor Ring 0**  | `SVM`/`VMX` + `NPT`/`EPT`,     | 0 FP/SIMD in                |
|          |                      | `x2APIC` + `pvclock`, `no_std` | `vmm-core.cwasm` & exposes  |
|          |                      | Wasmtime, & `BridgeShm`.       | `"vmm:..."` `SysObj`.       |
| **(d)**  | **Nested**           | Embed `vmm-core.cwasm`, inner  | `wasm-vmm` (L0) boots L1    |
|          | **`test-guest`**     | `test-guest` (`kloader` +      | `test-guest`, L1 boots L2   |
|          |                      | `initrd`), and tiny Ring-3     | `test-guest` via Ring 0, &  |
|          |                      | `BridgeShm` bootstrap in L1.   | L2 then L1 exit cleanly.    |
| **(e)**  | **Nested Full**      | Port `vmm-io-host` to Motor    | L1 (`tests/kloader` +       |
|          | **Motor OS**         | Ring 3 in `alioth-vmm`; stage  | staged disk) boots SMP      |
|          |                      | into copied `motor-os` image   | `motor-os` in L2 with       |
|          |                      | via `imager put`.              | `rush` shell & `russhd`.    |
| **(f)**  | **Nested**           | Linux guest surface in         | L1 Motor OS boots `bzImage` |
|          | **Alpine Linux**     | `tests/kernel`: `bzImage`,     | + `alpine.raw` in L2 to     |
|          |                      | `xAPIC` + `IoApic` IRQ 4,      | login prompt with working   |
|          |                      | Linux MSRs, & `MmioFault`s.    | `virtio-blk`, net, & SSH.   |
| **(g)**  | **Port Core Host**   | Linux kernel module in         | Linux Ring-0 `vmm-core` +   |
|          | **to Linux Ring 0**  | `alioth-vmm` hosting identical | Ring-3 `vmm-io-host` boots  |
|          |                      | `vmm-core.cwasm` + `BridgeShm` | Motor OS & Alpine in        |
|          |                      | over `folio`s & `tdp_mmu`.     | <16 KiB stack and 0 FPU.    |

### 2.1 Cross-Host Invariant: Byte-Identical Wasm Guests & Continuous Linux Ring-3 Compatibility

> **Non-Negotiable Invariant Across Steps `(a1)`–`(g)`**:
> Throughout every step of this roadmap, the existing **Linux Ring-3
> `vmm-core-host` and `vmm-io-host`** must remain working continuously as
> `vmm-core` and `vmm-io` evolve. Each step must finish with **one pair of
> byte-identical `vmm-core.wasm` and `vmm-io.wasm` guest binaries** (with AOT
> `.cwasm` artifacts compiled directly from those exact `.wasm` bytes, and
> **zero** host-specific `#[cfg]` forks or guest build variants) runnable
> unmodified by:
> 1. **Linux Ring-3 `vmm-core-host` + `vmm-io-host`** — booting both **Motor OS**
>    (`vm_scripts/run-motor-os.sh`, `vm_scripts/run-test-guest.sh`) and **Linux**
>    (`vm_scripts/run-linux.sh`, `vm_scripts/run-linux-initrd.sh`) in `--wasm`
>    and `--cwasm` modes (enforced by `cargo test` in `alioth-vmm/tests/`);
> 2. **Motor OS Ring-0 `vmm-core-host` + Ring-3 `vmm-io-host`** as each capability
>    lands across Steps `(c)`–`(f)`; and
> 3. **Linux Ring-0 `vmm-core-host` + Ring-3 `vmm-io-host`** in Step `(g)`.
>
> Any difference in host capabilities (such as KVM's pre-decoded `VmExit::Mmio`
> vs. Motor OS Ring 0's raw `VmExit::MmioFault`, `HostCaps::DOORBELLS`, or
> `HostCaps::HW_IOAPIC`) is negotiated strictly at **runtime** via
> `VmmHostCore::caps()` and the `VmmHostCore` / `VmmCoreBridge` / `VmmHostIo`
> C-ABI imports—never via compile-time divergence in the Wasm guests.

### 2.2 Repository Boundary Invariant: Read-Only Motor OS, Modify & Publish Only `alioth-vmm`

> **Non-Negotiable Repository Rule Across Steps `(a1)`–`(g)`**:
> **Nothing in this plan modifies Motor OS (`../motor-dev/motor-os`) directly.**
> `alioth-vmm` is the sole repository we modify, test, and publish:
> - **Read-Only Reuse of `../motor-dev/motor-os`**: Crates and scripts inside
>   `alioth-vmm` may depend via Cargo `path` on unchanged Motor OS libraries and
>   vendored crates (`src/sys/lib/{moto-rt,moto-sys,frusa}`,
>   `src/third_party/*`), embed prebuilt `rt.vdso`
>   (`src/sys/lib/rt.vdso/rt.vdso`), boot stock `vm_images/release/*` artifacts
>   in regression tests, and invoke
>   `../motor-dev/motor-os/vm_images/release/tools/imager` (`mkfs`, `mkdir`,
>   `put`) on **copied or scratch** disk images inside `alioth-vmm/target/` or
>   `/tmp` (see <https://github.com/moturus/motor-os/blob/main/docs/build.md>
>   for how `../motor-dev/motor-os` is built).
> - **All Custom Kernel, Loader, & Host Code Lives in `alioth-vmm`**: Step `(a1)`
>   copies Motor OS's `kernel` and `x64.kloader` crates into `alioth-vmm/tests/`
>   (starting with a pure, zero-diff source copy commit), Step `(a2)` creates
>   `test-init` in `alioth-vmm/tests/`, Step `(c)` adds Ring-0 VMM support inside
>   `alioth-vmm/tests/kernel`, and Step `(e)` builds Motor OS Ring-3
>   `vmm-io-host` inside `alioth-vmm`.
> - **Copy-on-Modify for Kernel Dependencies**: Dependencies of `tests/kernel`
>   and `tests/kloader` remain referenced from `../motor-dev/motor-os` while
>   unmodified. Whenever a later step requires modifying a Motor OS kernel
>   dependency (for example, adding a new `CAP_VMM` capability to `moto-sys`),
>   that dependency crate is also copied under `alioth-vmm/tests/` following the
>   same `(a1)` rule—first commit as a pure, unmodified source copy, followed by
>   local `Cargo.toml` path/`[patch]` wiring and the feature change—so
>   `../motor-dev/motor-os` is never edited.

*Scope of the remainder of this document*: Section 3 defines the overall Motor
OS Ring-0 / Ring-3 split architecture that spans Steps `(c)`–`(f)`, and
Sections 4, 5, and 6 detail the concrete designs of **Steps `(a1)`/`(a2)`,
`(b)`, and `(c)`**.

---

## 3. High-Level Architecture on Motor OS (`vmm-core-host` + `vmm-io-host`)

```text
+===================================================================================+
| Motor OS Userspace (Ring 3) — Built in `alioth-vmm`, Process with `CAP_VMM`       |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | vmm-io-host (`alioth-vmm` Motor OS target: `moto-sys` + `moto-rt` + Wasm)   |  |
|  |                                                                             |  |
|  |  +-----------------------------------------------------------------------+  |  |
|  |  | vmm-io.cwasm / vmm-io.wasm  [Step e+; omitted by tiny stub in Step d] |  |  |
|  |  |  - vm.toml parser & payload loader                                    |  |  |
|  |  |  - Virtio SplitQueue walker (reads/writes shared Guest RAM directly)  |  |  |
|  |  |  - virtio-blk (`motor-fs` files) & virtio-net (`sys-io` net channel)  |  |  |
|  |  +-----------------------------------+-----------------------------------+  |  |
|  |                                      | "vmm_io"::* (`VmmHostIo` trait)      |  |
|  |                                      v                                      |  |
|  |  MotorIoHost:                                                               |  |
|  |   - Event loop via `SysCpu::wait([vm_handle, serial_h, net_h])` (no `mio`)  |  |
|  |   - Direct R/W slice access to shared Guest RAM pages (`SysMem`)            |  |
|  |   - Doorbell to Ring 0 via `BridgeShm::io_to_core` + `SysCpu::wake(vm_h)`   |  |
|  +--------------------------------------+--------------------------------------+  |
+=========================================|=========================================+
                          Ring 3 / Ring 0 | Airlock Boundary
            Shared Physical Pages (`BridgeShm` + Guest RAM + Payloads)
                  + Bidirectional `vm_handle: SysHandle` (`wait` / `wake`)
+=========================================|=========================================+
| Motor OS Kernel in `alioth-vmm` (Ring 0) — `tests/kernel/src/vmm/`                |
|                                         v                                         |
|  +-----------------------------------------------------------------------------+  |
|  | vmm-core-host (`MotorHvCore` + `MotorCoreBridge` + `#![no_std]` Wasmtime)   |  |
|  |                                                                             |  |
|  |  +-----------------------------------------------------------------------+  |  |
|  |  | vmm-core.cwasm (AOT precompiled, `wasm32-unknown-unknown`, 0 FP/SIMD) |  |  |
|  |  |  - Exports: `vmm_init`, `vmm_on_vcpu_exit`, `vmm_on_bridge_rx`        |  |  |
|  |  |  - Board, RamBus, PVH/bzImage loader, ACPI, PCIe ECAM, Virtio PCI     |  |  |
|  |  |  - 16450 UART (0x3f8), IoApic (0xfec0_0000), x86_64 MMIO decoder      |  |  |
|  |  |  - `[VcpuCommPage; num_cpus]` in Wasm linear memory                   |  |  |
|  |  +--------------------+---------------------------------+----------------+  |  |
|  |       `VmmHostCore`   |                                 | `VmmCoreBridge`   |  |
|  |                       v                                 v                   |  |
|  |  +----------------------------------------+  +---------------------------+  |  |
|  |  | Ring-0 Hardware Virtualization Backend |  | Kernel `BridgeShm` Driver |  |  |
|  |  |  - AMD SVM (`VMRUN`) / Intel VMX       |  |  - Pins shared pages via  |  |  |
|  |  |  - Stage-2 MMU: NPT / EPT (`gpa->hpa`) |  |    `PAGING_DIRECT_MAP`    |  |  |
|  |  |  - Thin x2APIC (`ICR`, `TSC_DEADLINE`) |  |  - Fast Doorbell Table -> |  |  |
|  |  |  - `pvclock` MSRs (`0x4b564d00..01`)   |  |    push `c2i` + wake R3   |  |  |
|  |  |  - Non-blocking `Scheduler` vCPU Jobs  |  |    with 0 Wasm calls!     |  |  |
|  |  +----------------------------------------+  +---------------------------+  |  |
|  +-----------------------------------------------------------------------------+  |
+===================================================================================+
```

### 3.1 How `vmm-io-host` Looks on Motor OS (Ring 3)

On Linux, `vmm-io-host` (`LinuxIoHost`) glues `vmm-io` to POSIX `memfd_create`,
`eventfd`, `mio::Poll`, `/dev/net/tun`, `pread`/`pwrite`, and `termios`, and
spawns `vmm-core-host` as a child process. On Motor OS, **`vmm-core-host` is
already inside the kernel** (`alioth-vmm/tests/kernel`), so `vmm-io-host`
(`MotorIoHost`, built inside `alioth-vmm` for `--target x86_64-unknown-motor`)
becomes a clean, single-process Ring-3 service built on native Motor OS
primitives:

1. **Wasm Hosting & Non-Invasive Image Staging**:
   - Uses Motor OS-compatible Wasmtime (`W^X`
     `SysMem::map2(F_SHARE_SELF | F_EXECUTABLE)` and explicit trap checks) to
     instantiate `vmm-io.cwasm` (or `vmm-io.wasm` when Cranelift is linked).
   - **Staged Bring-Up Advantage**: Because the Ring-0 <-> Ring-3
     boundary is defined strictly by `BridgeShm` (`#[repr(C)]`) + `SysHandle`
     wakeups, Ring 0 neither knows nor cares whether Ring 3 runs full
     `vmm-io.cwasm` or a 150-line native Rust bootstrap (`vmm-io-tiny`). Steps
     `(c)` and `(d)` embed `vmm-io-tiny` inside `tests/test-init` (serial + boot
     payload only), and Step `(e)` swaps in full `vmm-io-host` + `vmm-io.cwasm`
     without changing the Ring-0 ABI.
   - **Zero Edits to `../motor-dev/motor-os`**: In Step `(e)`, L1 boots the
     Airlock-enabled `kloader` built from `alioth-vmm/tests/{kernel,kloader}`
     paired with stock `../motor-dev/motor-os/vm_images/release/initrd` (`sys-io`)
     and a scratch copy of `motor-os.qcow2` (converted to raw in `/tmp` or
     `target/`) into which `vmm-io-host`, `vmm-core.cwasm`, `vmm-io.cwasm`, and
     L2 guest payloads are injected via
     `../motor-dev/motor-os/vm_images/release/tools/imager put`.
2. **Zero-Copy Shared Memory (`SysMem` instead of `memfd` + `mmap`)**:
   - `MotorIoHost` allocates page-aligned regions via `SysMem::alloc` for:
     - `BridgeShm` (64 KiB control header + `core_to_io` / `io_to_core` rings +
       `ram_slots` + `device_queues` + `irq_routes`),
     - Guest RAM arena (`boot_cfg.mem_size` in 2 MiB `PAGE_SIZE_MID` or 4 KiB
       pages),
     - Boot payload buffer (`kloader` + `initrd`), and
     - Precompiled `vmm-core.cwasm` bytes.
   - `io_guest_mem_read` and `io_guest_mem_write` translate `gpa -> shm_offset`
     via `BridgeShm::ram_slots` and copy directly between `vmm-io`'s linear
     memory and the Guest RAM virtual mapping in Ring 3—zero syscalls on bulk
     Virtio DMA.
3. **Unified Wait Loop (`SysCpu::wait` instead of `mio::Poll` + `eventfd`)**:
   - Motor OS has no `epoll`/`mio` fd table; instead, every asynchronous source
     is a `SysHandle` waited on via
     `SysCpu::wait(&mut handles, SysHandle::NONE, SysHandle::NONE, None)`.
   - `MotorIoHost::io_next_event()` drains pending entries in
     `BridgeShm::core_to_io` first, and when empty calls `SysCpu::wait` across
     `[vm_handle, serial_handle, net_handles...]`.
4. **Native Motor OS Device Backends (`VmmHostIo`)**:
   - **Block (`blk_*`)**: Backed by `motor-fs` files via `moto-rt::fs` /
     `sys-io` shared I/O channels (random-offset read/write + flush).
   - **Network (`tap_*`)**: Backed by a packet channel to `sys-io` (L2 virtual
     bridge / routed uplink) rather than `/dev/net/tun`, exposing readiness via
     its `SysHandle` token in `SysCpu::wait`.
   - **Serial (`serial_*`)**: Backed by `SysObj::get(SysHandle::KERNEL, 0, "serial_console")`
     (in `test-guest` / `system-tty` mode) or standard input/output IPC pipes
     when launched from `rush` / `ssh`.

### 3.2 How `vmm-core-host` Looks on Motor OS (Ring 0)

1. **Zero Cranelift in Ring 0**:
   - Cranelift (~9 MB of compiler passes and heap churn) **never** enters the
     Motor OS kernel. Ring 0 links only Wasmtime's minimal `#![no_std] + alloc`
     execution runtime (`default-features = false, features = ["runtime"]`) plus
     `verify_no_fp::validate_cwasm_no_fp`.
   - `.cwasm` artifacts are precompiled ahead of time (on the build host or by
     an unprivileged Ring-3 `wasmtime compile` process) and passed to Ring 0 by
     a process holding `CAP_VMM`.
2. **No New Syscalls Required**:
   - Motor OS intentionally has only four syscalls (`SYS_CPU`, `SYS_MEM`,
     `SYS_OBJ`, `SYS_RAY`). `vmm-core-host` plugs directly into `SYS_OBJ` and
     `SYS_CPU`:
     - `SysObj::create(SysHandle::KERNEL, 0, "vmm:...")` validates `CAP_VMM`,
       pins the shared `BridgeShm` / Guest RAM / payload pages, deserializes
       `vmm-core.cwasm`, runs `vmm_init()`, schedules the guest vCPUs, and
       returns `vm_handle: SysHandle`.
     - `SysCpu::wake(vm_handle)` from Ring 3 triggers Ring 0 to process
       `BridgeShm::io_to_core` (`VirtioIrq` fast MSI injection, `SerialRx`, or
       `RequestShutdown` via `vmm_on_bridge_rx()`).
     - Ring-0 `CoreToIoEntry` pushes (`VirtioNotify`, `SerialTx`, `Shutdown`)
       wake Ring-3 threads waiting in `SysCpu::wait([vm_handle, ...])`.
     - Dropping the last handle (`SysObj::put(vm_handle)`) or process exit
       cleanly halts all guest vCPUs, tears down NPT/EPT tables, and releases
       all pinned frames.
3. **Strictly Non-Blocking Execution**:
   - Every call into `vmm-core.cwasm` (`vmm_init`, `vmm_on_vcpu_exit`,
     `vmm_on_bridge_rx`) is synchronous, deterministic, FPU-free, and completes
     in microseconds without ever blocking inside Wasm.

---

## 4. Detailed Design of Step (a): `test-guest` (`(a1)` + `(a2)` in `alioth-vmm/tests/`)

### 4.1 Key Observation from Motor OS's Boot Chain

Inspecting [`x64.kloader`](../motor-dev/motor-os/src/boot/x64.kloader/src/main.rs),
[`kernel/src/init.rs`](../motor-dev/motor-os/src/sys/kernel/src/init.rs), and
[`imager/src/main.rs`](../motor-dev/motor-os/src/imager/src/main.rs) shows a
clean separation between early boot and device/filesystem bring-up:

```text
PVH VMM (`wasm-vmm`)
  ├── Loads `kloader` ELF segments:
  │     ├── `.start`/`.text` at GPA 0x100200 (entry via `XEN_ELFNOTE_PHYS32_ENTRY`)
  │     └── `.kernel_image`  at GPA 0x100_0000 (`KERNEL_PHYS_START` = 16 MiB)
  └── Loads `initrd` near top of RAM + populates `HvmStartInfo` at GPA 0x1000
        │
        v
`kloader` (`bsp_start`)
  ├── Checks CPUID (`MSR`, `TSC`, `TSC_DEADLINE`, `RDTSCP`, `PDPE1GB`, `pvclock`)
  ├── Maps physical RAM at `PAGING_DIRECT_MAP_OFFSET` (1 << 46) using 1 GiB pages
  ├── Wakes APs via x2APIC `INIT`/`SIPI` (trampoline at GPA 0xc000) using ACPI MADT
  └── Relocates `kernel` ELF in-place at 16 MiB and jumps to `start_cpu`
        │
        v
`kernel` (`init.rs` -> `start_userspace_processes`)
  ├── Initializes `pvclock`, `mm` (phys/virt/user), `logger`, `sched`, and `uspace`
  ├── Reads `InitrdHeader` (magic `0xf402_100f`) from `PvhStartInfo` module 0:
  │     [0..512): InitrdHeader { magic, kloader_*, kernel_*, sys_io_start, sys_io_end }
  ├── Loads ONLY the single ELF slice `initrd[sys_io_start..sys_io_end]` as PID 2
  │   (`PID_SYS_IO`, full capability mask `0xffff_ffff_ffff_ffff`)
  └── When PID 2 exits (`init_exited`), calls `arch::kernel_exit()` -> `outb 0x34, 0x600`
```

Crucially, **neither `kloader` nor `kernel` touches PCI, `virtio-blk`, or
`virtio-net`**. All Virtio probing, `motor-fs` mounting, networking, and
`/system/services/sys-init` spawning live inside userspace `sys-io`.

### 4.2 Sub-Crate Layout Under `alioth-vmm/tests/`

To keep all development inside `alioth-vmm` without modifying
`../motor-dev/motor-os`, Step `(a)` splits into `(a1)` and `(a2)` under
`alioth-vmm/tests/`:

```text
alioth-vmm/tests/
├── Cargo.toml           # Host `vmm-tests` crate (`cargo test` runner)
├── src/lib.rs           # VM test harness + on-demand `test-guest` builder
├── tests/boot_vms.rs    # Linux, full Motor OS, & `test-guest` boot tests
├── kernel/              # Step (a1): copied from `motor-os/src/sys/kernel`
├── kloader/             # Step (a1): copied from `motor-os/src/boot/x64.kloader`
└── test-init/           # Step (a2): minimal PID 2 crate (`x86_64-unknown-motor`)
```

Because `kernel` (`--target kernel.json`), `kloader` (`--target kloader.json`),
and `test-init` (`--target x86_64-unknown-motor`) build against custom bare-metal
and Motor OS targets using the Motor OS Rust toolchain rather than the Linux
host `stable` toolchain in `alioth-vmm/rust-toolchain.toml`, root
`alioth-vmm/Cargo.toml` lists them in `[workspace] exclude = ["tests/kernel",
"tests/kloader", "tests/test-init"]`. Any Motor OS kernel dependency that later
needs modifications (such as `moto-sys` in Step `(c)`) is likewise copied into
`alioth-vmm/tests/` (e.g., `alioth-vmm/tests/moto-sys`, pure verbatim copy in
its first commit) rather than edited in `../motor-dev/motor-os`.

### 4.3 Step (a1): Copy `kernel` + `kloader` Under `alioth-vmm/tests/`

Step `(a1)` brings Motor OS's Ring-0 kernel and PVH loader into `alioth-vmm` in
two clean commits so git history preserves an exact upstream baseline before any
changes:

1. **First Commit — Pure Verbatim Source Copy (Zero Modifications)**:
   - Copy `../motor-dev/motor-os/src/sys/kernel` to `alioth-vmm/tests/kernel`
     and `../motor-dev/motor-os/src/boot/x64.kloader` to
     `alioth-vmm/tests/kloader` with **zero edits** to any copied file
     (`diff -ru ../motor-dev/motor-os/src/sys/kernel tests/kernel` and
     `diff -ru ../motor-dev/motor-os/src/boot/x64.kloader tests/kloader` are
     both empty).
   - Add `exclude = ["tests/kernel", "tests/kloader"]` to `alioth-vmm/Cargo.toml`
     so Linux host `cargo test` continues to pass unchanged.
2. **Second Commit — Build & Dependency Wiring Inside `alioth-vmm`**:
   - Update only the relative `path = "..."` entries in
     `tests/kernel/Cargo.toml` (`moto-rt`, `moto-sys`, `frusa`, `bitflags`,
     `elfloader`, `intrusive-collections`, `x86`, `x86_64`) and
     `tests/kloader/Cargo.toml` (`acpi`, `bitflags`, `elfloader`, `rsdp`, `x86`,
     `x86_64`) to point at `../../../motor-dev/motor-os/src/...` (never writing
     into `../motor-dev/motor-os`).
   - Select the Motor OS toolchain from
     `../motor-dev/motor-os/rust-toolchain.toml` (e.g.,
     `x86_64-unknown-motor-1.99.1-2`) via `rust-toolchain.toml` in
     `tests/{kernel,kloader}` (or `RUSTUP_TOOLCHAIN` in a `tests/` build helper),
     routing `CARGO_TARGET_DIR` and `MOTO_BIN` (`MOTO_KERNEL_ELF`) into
     `alioth-vmm/target/test-guest/`.
   - **Smoke check for `(a1)`**: Boot the `alioth-vmm`-built
     `target/test-guest/kloader` with stock
     `../motor-dev/motor-os/vm_images/release/{initrd,motor-os.qcow2}` in
     `wasm-vmm` to confirm parity before introducing `test-init`.

### 4.4 Step (a2): `test-init` Crate & `initrd-test-guest` Packager in `alioth-vmm/tests/`

Step `(a2)` creates `test-guest`'s minimal userspace payload inside
`alioth-vmm/tests/` with **zero changes to `tests/kernel` or `tests/kloader`**
(and zero changes to `../motor-dev/motor-os`):

1. **`test-init` Crate in `alioth-vmm` (`alioth-vmm/tests/test-init`)**:
   - Built for `--target x86_64-unknown-motor` (~100 LoC) with `CARGO_TARGET_DIR`
     under `alioth-vmm/target/test-guest/`, depending read-only on `moto-rt`,
     `moto-sys`, and `elfloader` in `../../../motor-dev/motor-os/src/...`.
   - **Self-Bootstrapping Runtime (`rt.vdso`)**: Just like `sys-io`
     ([`sys-io/src/rt_vdso.rs`](../motor-dev/motor-os/src/sys/sys-io/src/rt_vdso.rs)),
     embeds `../../../motor-dev/motor-os/src/sys/lib/rt.vdso/rt.vdso` via
     `include_bytes!` and loads it into `RT_VDSO_START` using
     `SysMem::map2(F_SHARE_SELF | F_EXECUTABLE)` inside `motor_runtime_start()`.
     Once `rt_vdso::load()` finishes, full Rust `std` (heap allocation, threads,
     `format!`, atomics, clocks) works with no filesystem or external pager.
   - **Boot Verification & Hardware Virtualization Probe**:
     In `main()`, `test-init`:
     1. Queries `SysMem::query_stats()`, `std::thread::available_parallelism()`,
        and kernel command line.
     2. Executes `cpuid` to detect hardware virtualization available to L1:
        - **AMD-V (`AuthenticAMD`)**: checks `CPUID(0x8000_0001).ECX[2]` (`SVM`)
          and `CPUID(0x8000_000A).EDX` (`NPT`, `NRIPS`, `DecodeAssists`).
        - **Intel VT-x (`GenuineIntel`)**: checks `CPUID(0x1).ECX[5]` (`VMX`).
     3. Writes a structured summary line via `SysRay::log` (routed by the kernel
        to `COM1` serial `0x3f8`):
        ```text
        test-guest: ok | cpus=2 | ram_mib=62 | cmd="test-guest" | hv=svm(npt=1,nrips=1,decode=1)
        ```
     4. Returns from `main()` with status `0` ->
        `SysCpu::exit_process(0)` -> `init_exited()` ->
        `vm_exit: bye.` + ACPI S5 poweroff (`out 0x600, 0x34`).

2. **`initrd-test-guest` Packager in `alioth-vmm/tests/`**:
   - Implemented directly in `alioth-vmm/tests/` (invoked automatically by
     `tests/src/lib.rs` and `vm_scripts/run-test-guest.sh`, writing
     `alioth-vmm/target/test-guest/initrd-test-guest`) using Motor OS's 512-byte
     `InitrdHeader` format (`MAGIC = 0xf402_100f`):
     - Since `wasm-vmm`'s PVH loader already loads `kloader` (and its embedded
       `.kernel_image` section) directly from the `kloader` ELF, the `kloader`
       and `kernel` spans in `initrd-test-guest` can be zero-length
       placeholders for pure PVH boot, shrinking `initrd-test-guest` to just
       4 KiB header + stripped `test-init` ~ **300–500 KiB**!
   - Note: `init.rs::sys_io_bytes()` asserts `initrd.len() > 4096` and checks
     `sys_io_start` page alignment (`4096`), so `sys_io_start = 4096` with a
     >4 KiB stripped `test-init` ELF satisfies `place_sys_io`'s zero-copy
     `vmem_map_reserved_pages` fast path!

---

## 5. Detailed Design of Step (b): Booting `test-guest` in `wasm-vmm`

### 5.1 Integration Test (`tests/`) & Interactive Launcher (`vm_scripts/`)

Step `(b)` wires `test-guest` (`target/test-guest/{kloader,initrd-test-guest}`)
into both `alioth-vmm`'s automated test suite and `vm_scripts/`:

1. **Automated `cargo test` Coverage (`alioth-vmm/tests/tests/boot_vms.rs`)**:
   - Adds `boot_test_guest_cwasm` and `boot_test_guest_wasm` alongside the
     existing Linux and full Motor OS boot tests.
   - `tests/src/lib.rs` builds `tests/kernel`, `tests/kloader`, `tests/test-init`,
     and `initrd-test-guest` once per test run (`OnceLock`), boots `wasm-vmm` in
     both `--cwasm` and `--wasm` modes, verifies the `test-guest: ok | ... | hv=`
     line on serial stdout (`hv=svm(...)` or `hv=vmx(...)`), and asserts that the
     VMM exits autonomously with status `0` via ACPI S5 (without sending
     `Ctrl-a q`).
2. **CLI Script (`alioth-vmm/vm_scripts/run-test-guest.sh`)**:
   - Builds `target/test-guest/{kloader,initrd-test-guest}` on demand and invokes
     `vm_scripts/run-vm.sh` (`--cwasm` default or `--wasm`) with a generated
     config:
     ```toml
     pvh = "/path/to/alioth-vmm/target/test-guest/kloader"
     initramfs = "/path/to/alioth-vmm/target/test-guest/initrd-test-guest"
     cmd_line = "test-guest"
     num_cpus = 2
     mem_size = "64M"
     blk = []
     log_file = "/tmp/wasm-vmm-test-guest.log"
     log_level = "info"
     ```

Unlike `vm_scripts/run-motor-os.sh`, `test-guest` requires **no `moto-tap`
device, no `qemu-img` disk conversion, and no host-wide `flock`**, so multiple
instances can run concurrently in CI or unprivileged sandboxes in ~30 ms per
run.

### 5.2 End-to-End Validation & Nested Virtualization Readiness

Step (b) validates four critical invariants in `wasm-vmm` before Step (c)
begins:

1. **Device-Free Board & Memory Map (`64 MiB` RAM)**:
   - `vmm-core`'s `xen::load` places `initrd-test-guest` at the top of low RAM
     (`~63 MiB`, page-aligned), well above `KERNEL_PHYS_START + KERNEL_IMAGE_LEN`
     (`16 MiB .. ~17 MiB`), satisfying `kloader/src/mm.rs`'s overlap guard.
   - `PciBus` contains only the PCI host bridge (`00:00.0`), confirming Motor OS
     boots cleanly with zero Virtio devices.
2. **Autonomous ACPI S5 Shutdown**:
   - When `test-init` exits `0`, Motor OS's `kernel_exit()` writes `0x34` to PIO
     `0x600`. `vmm-core/src/mem/mem.rs` returns `VmEntry::Shutdown` ->
     `Board::on_vcpu_exit` kicks all APs, sends `CORE_MSG_SHUTDOWN` across
     `BridgeShm`, and `vmm-io-host` exits cleanly with status `0`.
3. **Nested Virtualization Pass-Through (`L0 KVM` -> `L1 test-guest`)**:
   - For Step (d) to run a nested L2 VM inside L1 `test-guest`, `wasm-vmm` must
     expose hardware virtualization extensions from L0 KVM (`nested=1`) to L1:
     - `vmm-core/src/hw/hw_x86_64.rs` (`ArchBoard::new`) already seeds guest
       CPUID directly from `hv.supported_cpuids()` (`KVM_GET_SUPPORTED_CPUID`),
       preserving `CPUID(0x8000_0001).ECX[SVM]` + leaf `0x8000_000A` on AMD and
       `CPUID(0x1).ECX[VMX]` on Intel.
     - Step (b) verifies in `vmm-core-host/src/kvm/` that any required nested
       virtualization MSRs (such as `MSR_VM_CR` / `EFER.SVME` on AMD or
       `IA32_FEATURE_CONTROL` / `IA32_VMX_*` on Intel) are enabled on the KVM
       vCPU so `test-init` in L1 reports `hv=svm(...)` or `hv=vmx(...)` ready.

---

## 6. Detailed Design of Step (c): Porting `vmm-core-host` to Motor OS Ring 0

NOTE: (posk@): this needs review. I want to explore treating guest VCPU threads
as just another type of thread by the kernel (i.e. fp save/restore, preempt, etc.).

### 6.1 Kernel Subsystem Layout (`alioth-vmm/tests/kernel/src/vmm/`)

All Ring-0 VMM development happens inside the copied kernel crate in
`alioth-vmm/tests/kernel` (`../motor-dev/motor-os/src/sys/kernel` remains
unmodified):

```text
alioth-vmm/tests/kernel/src/vmm/
├── mod.rs           # VmInstance lifecycle, CAP_VMM check, SysObj ("vmm:...") hooks
├── arch/
│   ├── mod.rs       # Vendor-neutral ArchHv / ArchVcpu trait (SVM & VMX backends)
│   ├── svm.rs       # AMD-V: EFER.SVME, VM_HSAVE_PA, 4K VMCB, VMRUN/VMLOAD/VMSAVE
│   └── vmx.rs       # Intel VT-x: CR4.VMXE, VMXON, 4K VMCS, VMLAUNCH/VMRESUME
├── stage2.rs        # NPT (AMD) & EPT (Intel) 4-level GPA -> HPA page tables + ASID flush
├── lapic.rs         # Thin per-vCPU x2APIC (ICR INIT/SIPI, IRR/ISR, IA32_TSC_DEADLINE)
├── pvclock.rs       # KVM pvclock MSRs (0x4b564d00, 0x4b564d01) backed by host TSC
├── doorbell.rs      # Sorted fast-path PIO/MMIO doorbell array -> BridgeShm (0 Wasm calls)
├── host_impl.rs     # Implements `vmm_core::host::{VmmHostCore, VmmCoreBridge}`
└── wasm_runtime.rs  # `#![no_std]` Wasmtime Engine, W^X CustomCodeMemory, TLS, Store lock
```

`vmm-core` is imported via local path (`path = "../../vmm-core"`,
`default-features = false`) solely for its zero-copy ABI types and traits
(`vmm_core::host::abi::*`, `VmmHostCore`, `VmmCoreBridge`); **all `vmm-core`
device and board logic runs exclusively inside the sandboxed `vmm-core.cwasm`
module**, never as native Ring-0 code.

---

### 6.2 Hardware Virtualization Layer (`arch/` + `stage2.rs`)

`vmm-core` already handles IOAPIC (`0xfec0_0000`), 16450 UART (`0x3f8`), PCIe,
Virtio PCI, ACPI, and x86_64 MMIO instruction decoding (`VmExit::MmioFault`)
inside Wasm. Consequently, the native Ring-0 hardware layer is remarkably small
(~1,200 LoC):

#### A. Vendor-Neutral `ArchHv` Trait (AMD SVM First, Intel VMX Second)
*(Note: On AMD hosts with `SVM` + `NPT` + `NRIPS` + `DecodeAssists`, `svm.rs` is
the primary target for Steps `(c)`–`(d)`; `vmx.rs` implements the identical
internal trait for Intel VT-x + EPT hosts.)*

- **Per-pCPU Enablement**:
  - **AMD SVM (`svm.rs`)**: Sets `EFER.SVME = 1` on each host CPU during boot
    (when `CPUID.8000_0001:ECX.SVM` is present) and allocates one 4 KiB
    host-save page per pCPU written to `MSR_VM_HSAVE_PA` (`0xc001_0117`). Unlike
    Intel VMX, AMD VMCBs live in ordinary physical memory addressed by physical
    pointer in `RAX` on `VMRUN`—no `VMCLEAR`/`VMPTRLD` cross-CPU migration IPI
    is needed when a vCPU moves between pCPUs!
  - **Intel VMX (`vmx.rs`)**: Sets `CR4.VMXE = 1`, executes `VMXON` per pCPU,
    and tracks `loaded_cpu: Option<uCpus>` per VMCS, issuing a remote `VMCLEAR`
    IPI if a vCPU migrates across pCPUs before `VMPTRLD`.
- **World-Switch & FPU/SIMD Isolation**:
  - Motor OS kernel code runs without touching FPU/SIMD registers, whereas guest
    CPUs freely use `XMM`/`YMM`/`ZMM` (`kloader` calls `enable_sse()`).
  - Around `VMRUN` / `VMRESUME`, `arch::enter_guest`:
    1. Disables host maskable interrupts (`CLI` / `CLGI` on SVM).
    2. Saves the interrupted host user thread's extended state (or swaps a
       dedicated per-vCPU `XSAVE` area using Motor OS's existing `xsave` crate
       + `XCR0` save/restore) so guest SIMD state cannot leak to or corrupt
       host Ring-3 processes.
    3. Syncs `dirty_regs` (`SYNC_REG_GPRS`, `SYNC_REG_RIP_RFLAGS`,
       `SYNC_REG_SREGS`) from `VcpuCommPage` into the VMCB/VMCS + guest GPR
       save frame, injects any pending LAPIC interrupt vector (`EVENTINJ`), and
       executes `VMLOAD` + `VMRUN` + `VMSAVE` (or `VMLAUNCH`/`VMRESUME`).
    4. Restores host `GS`/`FS`/`STAR`/`LSTAR`/`KERNEL_GS_BASE` and host `XCR0`,
       re-enables host interrupts (`STGI` / `STI`), and decodes the VM-exit.
- **Mapping Hardware Exits to `VcpuCommPage`**:
  - **Host Interrupt (`VMEXIT_INTR` / `EXTERNAL_INTERRUPT`)**: Host IRQ runs on
    `STI`; vCPU checks `timer_irq_tick` / `shutdown_requested` and either yields
    to Motor OS `Scheduler` or re-enters the guest with **0 Wasm calls**.
  - **PIO (`VMEXIT_IOIO` / `IO_INSTRUCTION`)**: Checks `doorbell.rs` first;
    otherwise populates `VmExit::Io { port, write, size }`, `insn_len`, `rip`,
    and `gprs[RAX]` in `VcpuCommPage`.
  - **Stage-2 Fault (`VMEXIT_NPF` / `EPT_VIOLATION`)**: Checks `doorbell.rs`
    first; otherwise populates `VmExit::MmioFault { gpa, gva, is_write, insn_len, insn_bytes }`
    (using SVM `DecodeAssists` `GuestInstructionBytes` or walking `cr3` at
    `cs:rip` inside guest RAM) along with `gprs`, `rip`, `rflags`, `cr0`, `cr3`,
    `cr4`, `efer`, and `cs` in `VcpuCommPage`. `vmm-core`'s in-Wasm
    `insn_decode.rs` decodes the instruction in safe Rust!
  - **`CPUID` / `RDMSR` / `WRMSR` / `HLT` / `SHUTDOWN`**: Handled in Ring 0 if
    architectural fast-path (`x2APIC`, `pvclock`, `HLT`), else forwarded via
    `VmExit::{Cpuid, MsrRead, MsrWrite, Shutdown}` to `vmm_on_vcpu_exit`.

#### B. Slotless Stage-2 Page Tables (`stage2.rs`)
- Implements `VmmHostCore::{mem_alloc, mem_free, mem_read, mem_write, gpa_map, gpa_unmap}`:
  - `MemObj` is an array of physical frames (2 MiB `MidPage`s where possible,
    4 KiB `SmallPage`s fallback) either shared from Ring 3's Guest RAM arena
    (`MemObjId(0)` / `BridgeShm::ram_slots`) or allocated from `mm::phys`.
  - Because Motor OS maps all physical memory at `PAGING_DIRECT_MAP_OFFSET`
    (`1 << 46`), `mem_read` and `mem_write` are simple bounds-checked
    `core::ptr::copy_nonoverlapping` via `PAGING_DIRECT_MAP_OFFSET + hpa`—no
    temporary kernel `vmap` needed!
  - `gpa_map` populates 4-level NPT/EPT tables (`READ | WRITE | EXEC`, using
    2 MiB large leaves whenever `gpa`, `hpa`, and `size` are 2 MiB-aligned) and
    allocates a unique hardware ASID/VPID per VM, flushing via `INVLPGA` /
    `INVEPT` + remote TLB shootdown IPI on `gpa_unmap`.
  - Reports `HostCaps::DOORBELLS` (and omits `DECODED_MMIO` and `HW_IOAPIC`, so
    `vmm-core` automatically activates its in-Wasm `IoApic` and `MmioFault`
    instruction decoder!).

---

### 6.3 Minimal In-Kernel `x2APIC` & `pvclock` (`lapic.rs` + `pvclock.rs`)

Inspecting `test-guest`'s boot path (`x64.kloader` + `kernel/src/arch/x64/time.rs`)
identifies the **exact** Ring-0 CPU/timer primitives required for Motor OS (and
later Linux) guests:

1. **`pvclock` (`pvclock.rs`, ~60 LoC)**:
   - Motor OS `kloader` asserts `CPUID(0x4000_0001).EAX` bits `3`
     (`KVM_FEATURE_CLOCKSOURCE2`) and `24` (`KVM_FEATURE_CLOCKSOURCE_STABLE_BIT`),
     and `kernel` (`init_pvclock`) writes guest physical addresses to
     `MSR_KVM_WALL_CLOCK_NEW` (`0x4b564d00`) and `MSR_KVM_SYSTEM_TIME_NEW`
     (`0x4b564d01`).
   - Motor OS Ring 0 *already* maintains calibrated `tsc_mul`, `tsc_shift`, and
     `base_nsec` in `arch::x64::time::GLOBALS`! On guest `WRMSR` to these two
     MSRs, `pvclock.rs` validates the GPA in `stage2` and writes the 12-byte
     `PvClockWallClock` / 32-byte `PvClockVcpuTimeInfo` directly via
     `PAGING_DIRECT_MAP_OFFSET + hpa`.
2. **Thin Per-vCPU `x2APIC` (`lapic.rs`, ~250 LoC)**:
   - Traps MSRs `0x800..=0x83f` + `IA32_APIC_BASE` (`0x1b`) +
     `IA32_TSC_DEADLINE` (`0x6e0`):
     - **ID (`0x802`), LDR (`0x80d`), SVR (`0x80f`), TPR (`0x808`), EOI (`0x80b`)**.
     - **ICR (`0x830`)**: Handles `INIT` (`MpState::InitReceived`), `SIPI`
       (sets target AP `cs.selector = vector << 8`, `cs.base = vector << 12`,
       `rip = 0`, transitions `MpState::Runnable`, and schedules the AP's
       `Scheduler` job!), and fixed/self IPIs (`IRR` bit set + `vcpu_kick`).
     - **LVT Timer (`0x832`) & `IA32_TSC_DEADLINE` (`0x6e0`)**: Compares guest
       TSC deadline against `rdtsc()`; when a vCPU executes `HLT` with a future
       deadline, registers a Motor OS per-CPU `sched::Timer` at that exact TSC
       `Instant` to set the timer vector in `IRR` and wake the vCPU!
     - **`VmmHostCore::inject_msi(addr, data)`**: Decodes x86 MSI address
       (`0xfeeX_XXXX` -> destination `apic_id`) and data (`vector`),
       atomically sets `irr[vector]` on the target vCPU, and calls `vcpu_kick`!

---

### 6.4 Embedding `#![no_std]` Wasmtime in Motor OS Ring 0 (`wasm_runtime.rs`)

[`vmm-core-host/src/wasm_host.rs`](vmm-core-host/src/wasm_host.rs) already
configures Wasmtime via `build_ring0_wasm_config()`:

```rust
let mut config = Config::new();
config.wasm_threads(true);
config.shared_memory(true);
config.wasm_simd(false);
config.wasm_relaxed_simd(false);
config.signals_based_traps(false);
config.memory_init_cow(false);
config.memory_guard_size(0);
```

To run this inside `alioth-vmm/tests/kernel` (`#![no_std] + alloc`) while
executing `vmm-core.cwasm` compiled from the **exact byte-identical
`vmm-core.wasm`** (which imports shared memory `(env, memory)` with `+atomics`)
used on Linux Ring 3:

1. **Cargo Features (`wasmtime` in `no_std` mode, Hosted in `alioth-vmm`)**:
   - Depend on the **exact same `wasmtime` version** pinned in
     `alioth-vmm/Cargo.toml` (so `.cwasm` artifacts compiled on the host
     deserialize directly in Ring 0) with `default-features = false` and
     `features = ["runtime", "custom-sync-primitives"]`. Any `no_std` `threads`
     feature-gate patch (`SharedMemory` locks backed by
     `custom-sync-primitives`, trapping `memory.atomic.wait32/64` in `no_std`
     since `vmm-core` never blocks) lives strictly inside `alioth-vmm` via
     `[patch.crates-io]`—never modifying `../motor-dev/motor-os` and pulling in
     zero `std`, `cranelift`, `wasmtime-wasi`, or `wasmtime-fiber`.
   - All `.cwasm` inputs pass `verify_no_fp::validate_cwasm_no_fp(&cwasm_bytes)`
     prior to `unsafe { Module::deserialize(&engine, &cwasm_bytes) }`,
     guaranteeing at machine-code level that executing `vmm-core.cwasm` will
     never execute an `XMM`/`YMM`/`ZMM` or `x87` instruction in Ring 0.
2. **`W^X` Executable Code Publishing (`CustomCodeMemory`)**:
   - Implement `wasmtime::CustomCodeMemory` over Motor OS's kernel virtual
     memory allocator (`mm::virt`):
     - Allocate backing frames via `mm::phys`, copy the deserialized `.text` /
       trampoline bytes through `PAGING_DIRECT_MAP_OFFSET` (`RW`, `NX`), and map
       those frames into a `VmemKind::KernelStatic` virtual range with page-table
       flags `PRESENT | GLOBAL` (read + execute, **never writable**), then flush
       TLB on `unpublish`. Zero `RWX` mappings ever exist in Ring 0.
3. **Minimal Custom Platform Symbols (`wasmtime/src/runtime/vm/sys/custom/capi.rs`)**:
   - With `custom-virtual-memory` and `custom-native-signals` disabled,
     Wasmtime allocates `vmm-core`'s `SharedMemory` backing from the kernel
     `alloc` heap and requires only:
     - `wasmtime_tls_get(slot: usize) -> *mut u8` and
       `wasmtime_tls_set(slot: usize, ptr: *mut u8)`, implemented as two
       `[*mut u8; 2]` slots in `StaticPerCpu` (safe because Motor OS kernel jobs
       are never preempted while inside `vmm_on_vcpu_exit` or
       `vmm_on_bridge_rx`), and
     - `wasmtime_sync_lock_*` / `wasmtime_sync_rwlock_*` (`custom-sync-primitives`),
       backed directly by Motor OS's kernel `SpinLock`.
4. **Concurrency Across Guest vCPUs**:
   - **Step (c)/(d) — Single SpinLock-Protected `(Store, Instance)` over `SharedMemory`**:
     Guest vCPUs execute in parallel in hardware (`VMRUN`/`VMRESUME`), and
     Ring-0 fast paths (`HLT`, `x2APIC`, `TSC_DEADLINE`, `pvclock`, `QueueNotify`
     doorbells) run lock-free without entering Wasm. Slow-path exits acquire
     `vm.wasm_lock: SpinLock<(Store, Instance)>` for <1 µs while still binding
     `("env", "memory")` to the standard `SharedMemory` import of `vmm-core.wasm`.
   - **Step (e+) Parallel Slow-Path Scaling — Per-vCPU `(Store, Instance)` Pairs**:
     Because `SharedMemory` is already enabled from Step `(c)`, scaling to
     parallel slow-path exits simply instantiates `num_cpus` `(Store, Instance)`
     pairs sharing `SharedMemory`, bound to disjoint stacks via `vmm-core`'s
     existing `vmm_stack_top` and `vmm_bind_vcpu` exports—matching Linux Ring 3's
     execution model identically.

---

### 6.5 Integration with Motor OS Scheduler & `SysObj` Airlock

#### A. Non-Blocking Per-vCPU `Scheduler` Jobs
Motor OS's kernel forbids blocking inside syscalls or kernel tasks; instead,
CPUs execute non-blocking `Job`s (`sched/scheduler.rs`). Each guest vCPU maps
naturally onto a kernel `Job`:

```text
vcpu_job_fn(vm: Arc<VmInstance>, vcpu_id: u32)
  1. If vm.is_shutting_down() || vcpu.mp_state != MpState::Runnable -> return (parked).
  2. Loop up to BURST_LIMIT:
       a. If current_scheduler().timer_irq_tick || current_scheduler().has_other_work():
            re-enqueue `vcpu_job_fn` -> return (cooperative yield to host threads!).
       b. `exit = arch::enter_guest(vcpu_id, &mut comm_page[vcpu_id])`
       c. Match `exit`:
            - HostIntr          -> continue (loop check (a) yields if needed)
            - FastLapic/PvClock -> handle in Ring 0 -> continue
            - FastDoorbell(d,q) -> push `CORE_MSG_VIRTIO_NOTIFY` to `BridgeShm`,
                                   wake `vm_handle` Ring-3 waiter -> continue
            - Hlt               -> if pending `IRR`: continue;
                                   else arm `sched::Timer` for `tsc_deadline`
                                   and return WITHOUT re-enqueuing (0% idle CPU!)
            - SlowExit          -> lock `vm.wasm_lock`, call `vmm_on_vcpu_exit(vcpu_id)`:
                                   if `VmAction::Shutdown` -> wake Ring-3 & stop VM;
                                   else continue
```

When an external event wakes a parked/running vCPU (`inject_msi`, `SIPI`, or
`vcpu_kick`), `VmInstance` atomically transitions the vCPU from parked to queued
(enqueueing `vcpu_job_fn` on its target CPU) or calls
`arch::irq::wake_remote_cpu(running_pcpu)` (`IRQ_WAKEUP` IPI) to force an
immediate `VMEXIT_INTR` out of `VMRUN`/`VMRESUME`.

#### B. Ring-3 <-> Ring-0 `SysObj` Lifecycle (`CAP_VMM`)
1. **Privilege (`CAP_VMM` via Copied `tests/moto-sys`)**: When `CAP_VMM` (e.g.,
   `1 << 14`, or other VMM ABI definitions) is added to `moto-sys`, copy
   `../motor-dev/motor-os/src/sys/lib/moto-sys` into
   `alioth-vmm/tests/moto-sys` (pure verbatim source copy in the first commit,
   then re-point `tests/kernel`, `tests/test-init`, and Motor OS Ring-3
   `vmm-io-host` via `path` / `[patch]` and add `CAP_VMM` in
   `tests/moto-sys/src/caps.rs`), leaving `../motor-dev/motor-os` untouched.
   Unmodified `rt.vdso` already forwards arbitrary `u64` capability masks via
   `MOTOR_OS_CAPS`, and in Step `(d)` `test-init` runs as `PID_SYS_IO` with
   `0xffff_ffff_ffff_ffff`, holding `CAP_VMM` automatically.
2. **Creation (`SysObj::create`)**:
   ```rust
   let vm_handle = SysObj::create(
       SysHandle::KERNEL,
       0,
       &format!(
           "vmm:bridge={bridge_va};ram={ram_va};ram_sz={ram_sz};\
            payload={payload_va};payload_sz={payload_sz};\
            cwasm={cwasm_va};cwasm_sz={cwasm_sz}"
       ),
   )?;
   ```
   The kernel validates `CAP_VMM` and user mappings, pins the backing physical
   frames, registers `ram` as `MemObjId(0)` (updating `BridgeShm::ram_slots` on
   `gpa_map`), validates & deserializes `vmm-core.cwasm`, runs `vmm_init()`,
   enqueues runnable BSP `vcpu_job_fn(0)`, and returns `vm_handle`.
3. **Runtime Doorbells (`SysCpu::wait` / `SysCpu::wake`)**:
   - **Ring 0 -> Ring 3**: Pushing to `BridgeShm::core_to_io`
     (`SerialTx`, `VirtioStart`, `VirtioNotify`, `Shutdown`) signals `vm_handle`,
     waking Ring 3 from `SysCpu::wait(&mut [vm_handle, ...], ...)`.
   - **Ring 3 -> Ring 0**: Pushing to `BridgeShm::io_to_core`
     (`VirtioIrq`, `SerialRx`, `RequestShutdown`) followed by
     `SysCpu::wake(vm_handle)` invokes `VmInstance::on_user_wake()` in Ring 0:
     - `IO_MSG_VIRTIO_IRQ` looks up `(msi_addr, msi_data)` in `BridgeShm` and
       calls `inject_msi` **directly in Ring 0** (0 Wasm calls!).
     - `IO_MSG_SERIAL_RX` / `IO_MSG_REQUEST_SHUTDOWN` calls `vmm_on_bridge_rx()`.
4. **Teardown (`SysObj::put(vm_handle)` or Process Exit)**:
   - Marks `shutdown_requested = 1`, kicks any active pCPUs out of `VMRUN` /
     `VMRESUME`, cancels per-vCPU `sched::Timer`s, drops the Wasm `Store` +
     `CustomCodeMemory` `R+X` mapping, frees NPT/EPT tables, and unpins shared
     frames so no dangling DMA or Stage-2 translation can outlive the VM.
