# Airlock on Motor OS: Ring-0 `vmm-core-host` & Ring-3 `vmm-io-host`

## 1. Overview & Motivation

As described in [`architecture.md`](architecture.md), **WASM VMM** (`alioth-vmm`)
splits the VMM into two WebAssembly planes specifically designed to move the hot
VM-exit path into an OS kernel (Ring 0) while keeping complex device and chipset
emulation inside a sandboxed WebAssembly airlock:

1. **`vmm-core` (`wasm32-unknown-unknown`, `#![no_std] + alloc`, 0 WASI, 0 FP/SIMD)**:
   Owns guest physical memory layout (`RamBus`), `bzImage` / Xen PVH loading,
   ACPI tables, PCIe ECAM, Virtio PCI modern transport + MSI-X, 16450 UART,
   `IoApic` (`0xfec0_0000`), and x86_64 MMIO instruction decoding
   (`VmExit::MmioFault`). Driven synchronously by the host via `vmm_init`,
   `vmm_on_vcpu_exit`, and `vmm_on_bridge_rx` over `VcpuCommPage`.
2. **`vmm-io` (`wasm32-wasip1`) + `vmm-io-host` (`IoHost`)**:
   Runs in userspace (Ring 3). Owns `vm.toml` parsing, boot payload opening,
   Virtio `SplitQueue` descriptor-ring walking over shared Guest RAM,
   `virtio-blk`, `virtio-net`, and serial console I/O, communicating with Ring 0
   through lock-free shared-memory rings (`BridgeShm`) and doorbells.

### Why Port to Motor OS Ring 0 First?

Motor OS provides a clean proving ground before porting `vmm-core-host` into the
Linux kernel:
- **Pure `#![no_std] + alloc` Rust Microkernel**: `motor-os/src/sys/kernel` is
  written in Rust with non-preemptible Ring-0 execution, explicit cooperative
  scheduling (`sched::Scheduler`), direct physical memory mapping
  (`PAGING_DIRECT_MAP_OFFSET`), and strict `W^X` enforcement.
- **Native Shared-Memory + Wait/Wake IPC**: Motor OS's four-syscall interface
  (`SYS_OBJ`, `SYS_MEM`, `SYS_CPU`, `SYS_RAY`) pairs shared physical pages
  (`SysMem`) with wait/wake handles (`SysCpu::wait` / `SysCpu::wake`) — matching
  `BridgeShm` directly with zero POSIX file-descriptor impedance mismatch.
- **`no_std`-Compatible Wasmtime Runtime**: Paired with our minimal `no_std`
  `threads` patch in `../wasmtime` (`52.0.0-dev`, branch `posk/nostd-threads`),
  Wasmtime runs inside Motor OS Ring 0 with explicit bounds/trap checks
  (`signals_based_traps(false)`), `W^X` `CustomCodeMemory`, and 4 KiB-aligned
  `SharedMemory` (`MotorMemoryCreator`) — zero Cranelift, zero `std`, and zero
  floating-point or SIMD instructions.

---

## 2. End-to-End Development Roadmap (`a` – `g`)

```text
  [DONE] (a1) Copy Motor OS `kernel` + `x64.kloader` under `alioth-vmm/tests/`
  [DONE] (a2) Create `test-init` crate + `initrd-test-guest` packager in `tests/`
  [DONE] (b)  Boot `test-guest` in Linux `wasm-vmm` (PVH, ACPI S5, nested SVM/VMX)
  [DONE] (c)  Port `vmm-core-host` into `tests/kernel` (Ring 0: SVM + NPT + Wasmtime)
  [DONE] (d)  Nested smoke: Linux `wasm-vmm` [L0] -> `test-guest` [L1] -> `test-guest` [L2]
           |
           v
  [NEXT] (e)  Nested full Motor OS: Ring-3 `vmm-io-host` + `vmm-io.cwasm` staged via `imager`
           |
           v
         (f)  Nested Alpine Linux: `bzImage` boot, Linux MSR/CPUID/xAPIC/IOAPIC & MMIO coverage
           |
           v
         (g)  Port Ring-0 `vmm-core-host` to Linux Kernel (kthread / folios / tdp_mmu, <16 KiB stack)
```

| Step | Status | Milestone | Key Deliverables & Exit Criteria |
| :--- | :----- | :-------- | :------------------------------- |
| **(a1)** | Done | Copy `kernel` + `kloader` into `tests/` | Verbatim source copy followed by `../motor-dev` path wiring; builds `tests/kloader` ELF. |
| **(a2)** | Done | Create `test-init` & `initrd-test-guest` | Minimal Ring-3 test init (`PID_SYS_IO`) logging HV caps on `COM1` and exiting via ACPI S5. |
| **(b)** | Done | Boot `test-guest` in Linux `wasm-vmm` | `boot_test_guest_{cwasm,wasm}` + `vm_scripts/run-test-guest.sh` with nested SVM/VMX pass-through. |
| **(c)** | Done | Port `vmm-core-host` to Motor OS Ring 0 | `tests/kernel/src/vmm/`: AMD SVM + NPT, `x2APIC` + `pvclock`, `#![no_std]` Wasmtime, `CAP_VMM`, `"vmm:..."` `SysObj`. |
| **(d)** | Done | Nested `L0 -> L1 -> L2` `test-guest` | `boot_nested_test_guest_{cwasm,wasm}` + `vm_scripts/run-nested-test-guest.sh` (~105 ms SMP L2 boot & clean teardown). |
| **(e)** | Next | Nested Full Motor OS | Port `vmm-io-host` (`IoHost`) to Motor OS Ring 3; stage via `imager` and boot SMP full Motor OS in L2. |
| **(f)** | Planned | Nested Alpine Linux | `bzImage` boot, `xAPIC` + `IoApic` IRQ 4, Linux MSRs, `MmioFault` coverage, `virtio-blk` + net in L2. |
| **(g)** | Planned | Port Core Host to Linux Ring 0 | Linux kernel module hosting byte-identical `vmm-core.cwasm` + `BridgeShm` over `folio`s & `tdp_mmu`. |

### 2.1 Cross-Host Invariant: Byte-Identical Wasm Guests

> **Non-Negotiable Invariant Across Steps `(a1)`–`(g)`**:
> Every step finishes with **one pair of byte-identical `vmm-core.wasm` and
> `vmm-io.wasm` guest binaries** (with AOT `.cwasm` artifacts compiled directly
> from those exact `.wasm` bytes and zero host-specific `#[cfg]` forks) runnable
> unmodified by Linux Ring-3 (`vmm-core-host` + `vmm-io-host`), Motor OS
> (Ring-0 `vmm-core-host` + Ring-3 `vmm-io-host`), and ultimately Linux Ring 0.
> Host differences (such as KVM's `VmExit::Mmio` vs. Motor OS's `VmExit::MmioFault`)
> are negotiated strictly at runtime via `VmmHostCore::caps()`.

### 2.2 Repository Boundary Invariant: Read-Only `../motor-dev/motor-os`

> **Non-Negotiable Repository Rule**:
> **`../motor-dev/motor-os` is strictly read-only.** All custom kernel, loader,
> capability (`tests/moto-sys`), test-init, and Motor OS host crates live inside
> `alioth-vmm`. Whenever a Motor OS crate requires modification, it is copied
> into `alioth-vmm/tests/` first (verbatim copy commit followed by path wiring
> and changes), while unmodified Motor OS libraries and `vm_images/release/tools/imager`
> are consumed read-only from `../motor-dev/motor-os`.

---

## 3. High-Level Motor OS Split Architecture

```text
+===================================================================================+
| Motor OS Userspace (Ring 3) — Process with `CAP_VMM`                              |
|                                                                                   |
|  +-----------------------------------------------------------------------------+  |
|  | `MotorIoHost` (`vmm-io-host` on `x86_64-unknown-motor`; `vmm-io-tiny` in d) |  |
|  |  - Hosts `vmm-io.cwasm` / `vmm-io.wasm` (`IoHost` imports)                  |  |
|  |  - Allocates page-aligned `BridgeShm`, Guest RAM, payloads, & `.cwasm`      |  |
|  |  - Event loop via `SysCpu::wait([vm_handle, ...])`                          |  |
|  |  - Zero-copy Guest RAM DMA + `BridgeShm::io_to_core` + `SysCpu::wake(vm_h)` |  |
|  +--------------------------------------+--------------------------------------+  |
+=========================================|=========================================+
                          Ring 3 / Ring 0 | Airlock Boundary
           Pinned Shared Pages (`BridgeShm` + Guest RAM + Boot Payloads)
                 + Bidirectional `vm_handle: SysHandle` (`wait` / `wake`)
+=========================================|=========================================+
| Motor OS Kernel in `alioth-vmm` (Ring 0) — `tests/kernel/src/vmm/`                |
|                                         v                                         |
|  +-----------------------------------------------------------------------------+  |
|  | `VmInstance` (`MotorHvCore` + `MotorCoreBridge` + `MotorWasmRuntime`)       |  |
|  |  - `vmm-core-motor.cwasm` (validated by `validate_cwasm_no_fp`, R+X `W^X`)  |  |
|  |  - Per-vCPU `(Store, Instance)` workers + `RxWasmWorker` on `SharedMemory`  |  |
|  |  - AMD SVM (`VMRUN`) + 4 KiB NPT (`stage2.rs`), `x2APIC`, `pvclock`         |  |
|  |  - Fast `DoorbellTable` (`QueueNotify` -> `core_to_io` with 0 Wasm calls)   |  |
|  |  - Kernel vCPU & RX `process::Thread`s owned by the Ring-3 VMM `Process`    |  |
|  +-----------------------------------------------------------------------------+  |
+===================================================================================+
```

---

## 4. Implemented Foundation (Steps `(a1)`–`(d)`) & Ring-0 VMM ABI

Steps `(a1)` through `(d)` are implemented under `tests/` and verified by
`./tests/kernel/build.sh` and `cargo test --release`:

### 4.1 Crates & Build Pipeline under `tests/`

- **`tests/kernel`** (target [`tests/kernel/x86_64-unknown-none.json`](tests/kernel/x86_64-unknown-none.json),
  named `x86_64-unknown-none` so Wasmtime resolves native `Arch::X86_64` execution
  with `+soft-float,-mmx,-sse,-sse2,-avx`): Motor OS kernel extended with
  [`tests/kernel/src/vmm/`](tests/kernel/src/vmm/mod.rs).
  [`tests/kernel/build.sh`](tests/kernel/build.sh) builds `kloader`, `kernel`,
  and `test-init`, runs Clippy, disassembles the linked kernel ELF to enforce
  **zero** `%xmm`/`%ymm`/`%zmm`/`%mm` instructions, and packages `initrd-test-guest`.
- **`tests/moto-sys`** ([`tests/moto-sys/src/caps.rs`](tests/moto-sys/src/caps.rs)):
  Adds `CAP_VMM: u64 = 1 << 14` (`0x4000`).
- **`vmm-core-motor.cwasm`** ([`vmm-core-host/build.rs`](vmm-core-host/build.rs)):
  Compiled from the byte-identical `vmm-core.wasm` for `x86_64-unknown-none` with
  `signals_based_traps(false)`, `memory_reservation(0)`, `memory_guard_size(0)`,
  and SSE/AVX disabled, and machine-code verified for zero FP/SIMD registers.
- **`tests/test-init`** ([`tests/test-init/src/main.rs`](tests/test-init/src/main.rs)):
  Boots standalone in Step `(b)` or drives nested `L1 -> L2` SMP `test-guest`
  execution in Step `(d)` via its minimal native `BridgeShm` bootstrap.

### 4.2 Ring-0 Implementation Highlights (`tests/kernel/src/vmm/`)

- **`wasm_runtime.rs`**: Links `../wasmtime` (`default-features = false`,
  `features = ["runtime", "custom-sync-primitives", "threads"]`) with
  `Config::x86_float_abi_ok(true)` (`__cpuid` feature detection, zero `xmm` calls
  emitted because `vmm-core` has zero float signatures), `MotorCodeMemory`
  (`CustomCodeMemory` mapping physical pages `R+X` via `vmem_map_phys_pages_rx` —
  never `RWX`), `MotorMemoryCreator` (4 KiB page-aligned `SharedMemory` allocation),
  `StaticPerCpu` TLS slots, and kernel `SpinLock` sync hooks. Pre-instantiates
  parallel per-vCPU `VcpuWasmWorker` `(Store, Instance)` pairs plus a dedicated
  `RxWasmWorker` for `vmm_on_bridge_rx()`.
- **`verify_no_fp.rs` & TOCTOU-Free Code Loading**: `create_vm` copies user
  `.cwasm` pages into private kernel frames (`CwasmCodeBacking`) *before* running
  `validate_cwasm_no_fp`, ensuring Ring 3 cannot mutate `.text` after validation.
- **`arch/svm.rs`, `stage2.rs`, `lapic.rs`, `pvclock.rs`, `doorbell.rs`**:
  Complete AMD SVM (`VMRUN`/`VMLOAD`/`VMSAVE` + `XMM0..XMM15` save/restore in
  `svm_vmrun_asm`, ASID allocation, `GuestInstBytes` `NPF` pass-through for
  `VmExit::MmioFault`), 4 KiB NPT Stage-2 page tables, Ring-0 `x2APIC` (`ICR`
  `INIT`/`SIPI`/IPI + `TSC_DEADLINE`), KVM `pvclock`, and lock-free `DoorbellTable`.
  *(Note: `arch/vmx.rs` is currently a capability-probe stub; Intel VMX world
  switch + EPT can be added if needed on Intel hosts.)*
- **`vcpu_thread.rs` & `Process::spawn_kernel_thread`**: Spawns `num_cpus` kernel
  vCPU threads (`vcpu_thread_entry`) plus an `rx_worker_entry` thread owned by
  the calling Ring-3 `Process`, reusing Motor OS `tcb.pause()`/`Thread::wait()`
  (`0%` host CPU on guest `HLT` or pre-`SIPI`), `tcb.xsave`, preemption ticks,
  and automatic cleanup on `SysObj::put` or process exit/kill.

### 4.3 Ring-3 <-> Ring-0 `SysObj` & `SysCpu` ABI Contract

Any Ring-3 VMM host holding `CAP_VMM` (`0x4000`) drives a VM through three syscalls:

1. **Create & Start VM (`SysObj::create`)**:
   ```rust
   let url = format!(
       "vmm:shm_addr=0x{shm_va:x};ram_addr=0x{ram_va:x};ram_size=0x{ram_sz:x};\
        payload_addr=0x{payload_va:x};payload_size=0x{payload_sz:x};\
        cwasm_addr=0x{cwasm_va:x};cwasm_size=0x{cwasm_sz:x}"
   );
   let vm_handle = SysObj::create(SysHandle::KERNEL, 0, &url)?;
   ```
   - All four user regions (`BridgeShm`, Guest RAM `[4 MiB ..= 2 GiB]`, packed
     boot payload `kernel_bytes || initrd_bytes`, and `vmm-core-motor.cwasm`
     `<= 16 MiB`) must be 4 KiB page-aligned in the caller's address space.
   - Ring 0 pins `BridgeShm` (`RW`), Guest RAM (`RW`), and payload (`RO`), copies
     and validates `.cwasm`, runs `vmm_init()`, populates `BridgeShm::ram_slots`
     as `gpa_map` runs, spawns the kernel vCPU and RX threads, and returns
     `vm_handle`.
2. **Runtime Doorbells (`SysCpu::wait` / `SysCpu::wake`)**:
   - **Ring 0 -> Ring 3**: Enqueuing to `BridgeShm::core_to_io` (`VirtioStart`,
     `VirtioNotify`, `VirtioReset`, `SerialTx`, `Shutdown`) wakes `vm_handle`,
     unblocking Ring 3 from `SysCpu::wait(&mut [vm_handle, ...], ...)`.
   - **Ring 3 -> Ring 0**: Enqueuing to `BridgeShm::io_to_core` (`VirtioIrq`,
     `SerialRx`, `RequestShutdown`) and calling `SysCpu::wake(vm_handle)` wakes
     Ring 0's `rx_worker` thread:
     - `IO_MSG_VIRTIO_IRQ` resolves `(msi_addr, msi_data)` in `BridgeShm` and
       calls `MotorHvCore::inject_msi` directly in Ring 0 (**0 Wasm calls**).
     - `IO_MSG_SERIAL_RX` and `IO_MSG_REQUEST_SHUTDOWN` invoke `vmm_on_bridge_rx()`.
3. **Teardown (`SysObj::put(vm_handle)` or Process Exit)**:
   - Requests VM shutdown, kicks all running or halted vCPU and RX kernel
     threads out of `VMRUN` / `Thread::wait()`, and drops `VmInstance` (freeing
     Wasm stores, `R+X` code mappings, NPT tables, and pinned page references).

---

## 5. Step `(e)` Design: Nested Full Motor OS (`L0 -> L1 -> L2`)

### 5.1 Goal & Scope

Boot **full Motor OS** in L1 using our Ring-0-enabled `tests/kloader` paired with
**stock** `../motor-dev/motor-os/vm_images/release/initrd` (`sys-io`) and a
scratch copy of `motor-os.qcow2` staged via `imager`. Inside L1 Ring 3, run
`motor-io-host` (`tests/motor-io-host/`, `--target x86_64-unknown-motor`)
hosting the **byte-identical `vmm-io.wasm`** (or its Motor OS AOT-precompiled
`vmm-io.cwasm`) paired with Ring-0 `vmm-core.cwasm`, booting SMP **full Motor OS**
in L2 with `virtio-blk`, `rush` shell, `virtio-net`, and `russhd`.

### 5.2 Hosting Byte-Identical `vmm-io.wasm` via `moturus/wasmtime`

1. **Switch `vmm-io` Target from `wasm32-wasip1-threads` to `wasm32-wasip1`**:
   - `vmm-io` is 100% single-threaded (it spawns zero threads, and Guest RAM
     lives outside Wasm linear memory); `wasm32-wasip1-threads` was only a
     holdover from the pre-split monolithic `vmm-runner`.
   - Compiling `vmm-io` for `wasm32-wasip1` produces a single, byte-identical
     `vmm-io.wasm` across Linux and Motor OS with a standard non-shared exported
     `memory` (which also simplifies Linux [`vmm-io-host/src/wasm_host.rs`](vmm-io-host/src/wasm_host.rs)
     by dropping unused `SharedMemory` and `wasi::thread-spawn` glue).
2. **Reuse Unmodified `moturus/wasmtime` (`../motor-dev/motor-os/external-sources/wasmtime`)**:
   - Because `tests/motor-io-host` is a standalone Ring-3 userspace crate
     communicating with `tests/kernel` (Ring 0) strictly via `BridgeShm`
     (`#[repr(C)]`) + `SysObj`/`SysCpu`, it links directly against
     `../motor-dev/motor-os/external-sources/wasmtime` (`motor-50.0.0`:
     `wasmtime` + `wasmtime-wasi` p1) with **zero Wasmtime porting or custom
     WASI shims**.
   - Out of the box, `moturus/wasmtime` supplies:
     - Motor OS `CodeMemory` (`SysMem::map2` dual-alias `W^X` code publishing),
     - `Reservations` (`MemoryCreator` backed by lazy `SysMem::map` pages),
     - `OperatingSystem::Motor` `Tunables` (`signals_based_traps = false`,
       `memory_guard_size = 0`, `memory_init_cow = false`), and
     - Native Motor OS `wasmtime_wasi::p1::add_to_linker_sync` (filesystem,
       clocks, RNG, args/env, stdio).
3. **Both `--wasm` and `--cwasm` Execution Modes (Two Canonical `.wasm` Files Only)**:
   - Only two `.wasm` binaries exist across the entire project: `vmm-core.wasm`
     and `vmm-io.wasm`.
   - In `--wasm` mode (when built with Cranelift), `motor-io-host` loads
     `vmm-io.wasm` directly.
   - In `--cwasm` (runtime-only) mode, the host build precompiles `vmm-io.wasm`
     for `--target x86_64-unknown-motor` using `moturus/wasmtime` into a separate
     Motor output directory (`target/motor/vmm-io.cwasm`) alongside the Ring-0
     core artifact (`target/motor/vmm-core.cwasm`), so staged artifacts keep the
     canonical names `vmm-core.cwasm` and `vmm-io.cwasm`.

### 5.3 Granting `CAP_VMM` (`0x4000`) Under Unmodified Stock `sys-init` & `rush`

In Motor OS (`Process::new_child` and `docs/caps.md`), a `System` process
(`CAP_SYS = 0x1`) is authorized to grant child capability bits it does not
itself hold (except `CAP_VSOCK`, `CAP_NET`, and `CAP_FS_WRITE`, which must be
held by the parent), and stock `rt.vdso` forwards arbitrary hex `u64` masks from
`MOTOR_OS_CAPS`:

1. **Serial Console / Automated Test Launch (`system-tty`)**:
   When L1 boots with `system-tty`, `sys-tty` runs `/system/bin/rush -i` with
   `System` capabilities (`CAP_SYS | CAP_SPAWN | CAP_LOG | CAP_NET | CAP_FS_WRITE | ...`).
   Launching:
   ```sh
   MOTOR_OS_CAPS=0x434c /system/bin/motor-io-host -c /vm/vm.toml
   ```
   (`CAP_SPAWN(0x4) | CAP_LOG(0x8) | CAP_INTERACTIVE(0x40) | CAP_NET(0x100) | CAP_FS_WRITE(0x200) | CAP_VMM(0x4000)`,
   or `0x430d` for `System` role) grants `CAP_VMM` with **zero changes** to stock
   `initrd` or binaries.
2. **SSH Launch (`russhd`)**:
   Stock `/system/cfg/sys-init.cfg` starts `russhd` as `svc:1020:...` (`0x3fc`,
   `Interactive` role without `CAP_SYS` or `CAP_VMM`), and non-`System` parents
   can only delegate bits they already hold. Staging an updated
   `/system/cfg/sys-init.cfg` onto the scratch L1 image via `imager put` with
   `svc:17404:/system/services/russhd /system/cfg/sshd.toml` (`1020 | 16384`)
   lets SSH sessions spawn `motor-io-host` with `CAP_VMM` as well.

### 5.4 `MotorIoHost` (`VmmHostIo`) Backends & Event Loop

1. **Shared Memory & Ring-0 VM Creation (`io_register_vm_config`)**:
   - Allocate 4 KiB page-aligned regions via `SysMem::alloc` for `BridgeShm`,
     Guest RAM (`boot_cfg.mem_size`), packed boot payload (`kloader` + `initrd`
     read from `motor-fs`), and Ring-0 `vmm-core.cwasm`.
   - Call `SysObj::create(SysHandle::KERNEL, 0, "vmm:shm_addr=...;ram_addr=...")`
     to start the Ring-0 VM and store `vm_handle: SysHandle`.
   - `io_guest_mem_read` and `io_guest_mem_write` translate `gpa -> shm_offset`
     through `BridgeShm::ram_slots` and `memcpy` directly against the pinned
     Ring-3 Guest RAM slice.
2. **Block Backend (`blk_*`)**:
   - Backed by `std::fs::OpenOptions` (`File` on `motor-fs` through `sys-io`),
     using `Seek::seek(SeekFrom::Start(offset))` + `read_exact` / `write_all`
     (protected by a per-disk `Mutex<File>`) and `File::sync_all()` on `blk_flush`.
3. **Serial Console & Nested Escape Key (`serial_*`)**:
   - Writes `SerialTx` bytes to stdout; reads console input from a background
     stdin reader thread (waking the main `SysCpu::wait` loop via a `SysHandle`
     when bytes arrive).
   - Uses **`Ctrl-b q`/`x`** by default (configurable via environment variable)
     so interactive nested sessions in L2 are not intercepted by L0
     `vmm-io-host`'s `Ctrl-a q`/`x`.
4. **Network Backend (`tap_*`) via `moto_sdk::io::ip_device::IpDevice`**:
   - Stock `moto-sdk` provides `moto_sdk::io::ip_device::IpDevice`
     (`src/sys/lib/moto-sdk/src/io/ip_device.rs`), allowing an `Interactive` or
     `System` process holding `CAP_NET` to dynamically register a dedicated L3
     point-to-point IP interface with `sys-io`.
   - `MotorIoHost` registers an `IpDevice` (e.g., `vmm0`, `192.168.5.1/24`),
     while L2's scratch `/system/cfg/sys-net.toml` is configured with
     `192.168.5.2/24` and gateway `192.168.5.1` (avoiding subnet collision with
     L1's `192.168.4.2/24` on `moto-tap`).
   - On TX/RX, `MotorIoHost` strips/prepends `virtio_net_hdr` (12B) + Ethernet
     header (14B) for IPv4/IPv6 packets and replies locally to L2 ARP requests
     (`WHO-HAS 192.168.5.1`). L1 can then `ping 192.168.5.2` and
     `ssh 192.168.5.2` directly into L2's `russhd` (and L0 can reach L2 directly
     via an optional host route `ip route add 192.168.5.0/24 via 192.168.4.2 dev moto-tap`)
     with zero in-process TCP/IP stack inside `MotorIoHost`.
5. **Unified Event Loop (`io_next_event`)**:
   - Drain pending `BridgeShm::core_to_io` entries first (`VirtioStart`,
     `VirtioNotify`, `VirtioReset`, `SerialTx`, `Shutdown`).
   - Poll registered `IpDevice` RX / stdin queues; when idle, sleep in
     `SysCpu::wait(&mut [vm_handle, net_ipc_handle, stdin_wake_handle], ...)`
     for `0%` idle CPU usage.

### 5.5 Crate Layout & Phased Bring-Up

1. **Standalone Crate at `tests/motor-io-host/`**:
   - Placed at `tests/motor-io-host/` (excluded from the root Linux Cargo
     workspace, mirroring `tests/{kernel,kloader,moto-sys,test-init}`) and built
     with the Motor OS `x86_64-unknown-motor` toolchain (`motor-clang` linker)
     against `../motor-dev/motor-os/external-sources/wasmtime` and `moto-sdk`.
   - Shares the OS-agnostic `VmmHostIo` / ABI definitions with `vmm-io` and
     `vmm-io-host` so the `"vmm"::*` Wasm import surface stays single-sourced.
2. **Phased Rollout**:
   - **Step `(e.1)` — `wasm32-wasip1` Switch + Disk + Shell (`--no-network`)**:
     Switch `vmm-io` to `wasm32-wasip1` (verifying all existing Linux `cargo test`
     suites), implement `tests/motor-io-host` (`BridgeShm`, `blk_*`, `serial_*`),
     stage artifacts + `l2-motor-os.raw` into scratch `l1-motor-os.raw` via
     `imager` (`L1 RAM = 1024–1536 MiB`, `L2 RAM = 256 MiB`, `2` SMP vCPUs), and
     boot L2 full Motor OS over `virtio-blk` to an interactive `rush` prompt.
   - **Step `(e.2)` — `IpDevice` Networking + `russhd`**:
     Add the `IpDevice` L2<->L3 + ARP `tap_*` backend in `tests/motor-io-host`,
     verify SSH into L2's `russhd`, and wire up `vm_scripts/run-nested-motor-os.sh`
     plus `boot_nested_motor_os_*` in `tests/tests/boot_vms.rs`.
