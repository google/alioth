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
2. **`vmm-io` (`wasm32-wasip1-threads`) + `vmm-io-host` (`IoHost`)**:
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
