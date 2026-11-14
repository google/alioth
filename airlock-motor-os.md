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
  [DONE] (e)  Nested full Motor OS: Ring-3 `motor-io-host` + `vmm-io.{cwasm,wasm}` + `IpDevice`
  [DONE] (f)  Nested Alpine Linux: `bzImage` boot, Linux MSR/CPUID/xAPIC/IOAPIC & OpenSSH in L2
           |
           v
  [NEXT] (g)  Port Ring-0 `vmm-core-host` to Linux Kernel (kthread / folios / tdp_mmu, <16 KiB stack)
```

| Step | Status | Milestone | Key Deliverables & Exit Criteria |
| :--- | :----- | :-------- | :------------------------------- |
| **(a1)** | Done | Copy `kernel` + `kloader` into `tests/` | Verbatim source copy followed by `../motor-dev` path wiring; builds `tests/kloader` ELF. |
| **(a2)** | Done | Create `test-init` & `initrd-test-guest` | Minimal Ring-3 test init (`PID_SYS_IO`) logging HV caps on `COM1` and exiting via ACPI S5. |
| **(b)** | Done | Boot `test-guest` in Linux `wasm-vmm` | `boot_test_guest_{cwasm,wasm}` + `vm_scripts/run-test-guest.sh` with nested SVM/VMX pass-through. |
| **(c)** | Done | Port `vmm-core-host` to Motor OS Ring 0 | `tests/kernel/src/vmm/`: AMD SVM + NPT, `x2APIC` + `pvclock`, `#![no_std]` Wasmtime, `CAP_VMM`, `"vmm:..."` `SysObj`. |
| **(d)** | Done | Nested `L0 -> L1 -> L2` `test-guest` | `boot_nested_test_guest_{cwasm,wasm}` + `vm_scripts/run-nested-test-guest.sh` (~105 ms SMP L2 boot & clean teardown). |
| **(e)** | Done | Nested Full Motor OS | `tests/motor-io-host` (`moturus/wasmtime` + `IpDevice`), `boot_nested_motor_os_{cwasm,wasm}`, `vm_scripts/run-nested-motor-os.sh` (`rush` + `russhd` SSH). |
| **(f)** | Done | Nested Alpine Linux | `boot_nested_linux_initrd_{cwasm,wasm}`, `boot_nested_alpine_{cwasm,wasm}`, `vm_scripts/run-nested-linux.sh` (`bzImage` 6.14 + `virtio-blk` + `IpDevice` + OpenSSH). |
| **(g)** | Next | Port Core Host to Linux Ring 0 | Linux kernel module hosting byte-identical `vmm-core.cwasm` + `BridgeShm` over `folio`s & `tdp_mmu`. |

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
|  | `MotorIoHost` (`tests/motor-io-host` on `x86_64-unknown-motor`)             |  |
|  |  - Hosts `vmm-io.cwasm` / `vmm-io.wasm` via unmodified `moturus/wasmtime`   |  |
|  |  - Allocates page-aligned `BridgeShm`, Guest RAM, payloads, & `.cwasm`      |  |
|  |  - `motor-fs` block I/O, raw serial (`Ctrl-b`), & `IpDevice` `virtio-net`   |  |
|  |  - Event loop via `SysCpu::wait([vm_handle, ...])` + zero-copy Guest DMA    |  |
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

## 4. Implemented Foundation (Steps `(a1)`–`(e)`) & Ring-0 VMM ABI

Steps `(a1)` through `(e)` are implemented under `tests/` and verified by
`./tests/kernel/build.sh`, `./tests/motor-io-host/build.sh`, and
`cargo test --release`:

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
- **`tests/motor-io-host`** ([`tests/motor-io-host/src/main.rs`](tests/motor-io-host/src/main.rs),
  [`motor_host.rs`](tests/motor-io-host/src/motor_host.rs),
  [`ip_tap.rs`](tests/motor-io-host/src/ip_tap.rs)):
  Ring-3 userspace `VmmHostIo` embedder (`x86_64-unknown-motor`) linked against
  unmodified `../motor-dev/motor-os/external-sources/wasmtime` (`moturus/wasmtime`
  + `wasmtime-wasi` p1) and `moto-sdk`. Hosts the byte-identical `vmm-io.wasm`
  (`motor-io-host-wasm` with Cranelift JIT) and precompiled
  `target/motor/vmm-io.cwasm` (`motor-io-host-cwasm`), driving `motor-fs` block
  I/O, raw serial (`Ctrl-b q`/`x` default escape), and `MotorIpTap`
  (`moto_sdk::io::ip_device::IpDevice` L2<->L3 framing + local ARP + TX checksum
  finalization). Verified end-to-end by `boot_nested_motor_os_{cwasm,wasm}` and
  [`vm_scripts/run-nested-motor-os.sh`](vm_scripts/run-nested-motor-os.sh).

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

## 5. Step `(f)` Design: Nested Alpine Linux (`L0 -> L1 Motor OS -> L2 Alpine Linux`)

### 5.1 Goal & Scope

Boot SMP **Linux 6.14** (`../linux-blobs/bzImage`) inside L1 **full Motor OS**
using Ring-3 `tests/motor-io-host` + Ring-0 `tests/kernel/src/vmm/` paired with
the **byte-identical `vmm-core.wasm` (`vmm-core.cwasm`) and `vmm-io.wasm`
(`vmm-io.cwasm`)**:
1. First with BusyBox `../linux-blobs/initramfs.cpio.gz` (`console=ttyS0 rdinit=/init`)
   to validate Linux 6.14 SMP kernel bring-up, timer/APIC calibration, `IoApic`
   IRQ 4 (`COM1`), PCIe ECAM / Virtio PCI `MmioFault` decoding, and clean
   `poweroff` (`ACPI S5`).
2. Then with full **Alpine Linux** (`../linux-blobs/alpine.raw`,
   `console=ttyS0 root=/dev/vda3 rw`) over `virtio-blk` and `virtio-net`
   (`MotorIpTap` / `IpDevice`), verifying interactive `ttyS0` login, ICMP, SSH
   into L2's OpenSSH `sshd`, and clean `L2 -> L1 -> L0` teardown in both
   `--cwasm` and `--wasm` modes.

### 5.2 Existing Coverage (`0` Host-Specific Wasm Forks)

Most of the Linux guest stack is already implemented and shared across hosts:
- **`vmm-core` (`wasm32-unknown-unknown`)**:
  - 64-bit Linux `bzImage` + `BootParams` + E820 + `initramfs` loader
    ([`vmm-core/src/loader/linux.rs`](vmm-core/src/loader/linux.rs)).
  - ACPI `RSDP`, `XSDT`, `FADT` (`VGA_NOT_PRESENT | CMOS_RTC_NOT_PRESENT`,
    `SLEEP_CONTROL_REG` `0x600`, `RESET_REG` `0x604`), `MADT` (`IoApic` +
    `LocalX2apic`), and `MCFG` (`0xe000_0000`), with `COM1` wired to edge-triggered
    GSI 4 on `IoApic` (`0xfec0_0000`).
  - Unmapped ISA/CMOS PIO handling (`0x70`/`0x71` returning `0` so RTC probes
    never spin on `RTC_UIP`; all other unmapped ports floating high to `0xff..`)
    and `VmExit::MmioFault` instruction emulation
    ([`vmm-core/src/hw/insn_decode.rs`](vmm-core/src/hw/insn_decode.rs)).
- **`tests/motor-io-host` (`x86_64-unknown-motor`)**:
  - Already supports `kernel = "..."` (`EXEC_TYPE_LINUX`), optional
    `initramfs = "..."`, `cmd_line = "..."`, `blk = [...]`, `Ctrl-b` console
    escape, and `MotorIpTap` custom subnet CIDRs (`if_name = "vmm0:192.168.8.1/24"`).

### 5.3 Ring-0 Hypervisor Extensions for Linux 6.14 (`tests/kernel/src/vmm/`)

Unlike Motor OS (which enters `x2APIC` + `TSC_DEADLINE` directly and touches a
minimal MSR/CPUID set), Linux 6.14's x86_64 boot path probes several additional
architectural and KVM paravirtual interfaces that `tests/kernel/src/vmm/` should
handle cleanly in Ring 0:

1. **Paravirtual TSC & APIC Frequency Leaf (`CPUID 0x4000_0010` + `KVM_FEATURE_NOP_IO_DELAY`)**:
   - Our virtual board intentionally omits legacy i8254 PIT (`0x40`), CMOS RTC,
    HPET, and ACPI PM timer hardware. On Linux KVM, `kvm_get_tsc_khz()` and
    `calibrate_APIC_clock()` avoid legacy timer calibration loops via
    `CPUID 0x4000_0010`.
   - Extend `MotorHvCore::supported_cpuids`
     ([`tests/kernel/src/vmm/host_impl.rs`](tests/kernel/src/vmm/host_impl.rs)):
     - Raise `0x4000_0000.eax` from `0x4000_0001` to `0x4000_0010`.
     - Add `KVM_FEATURE_NOP_IO_DELAY` (`1 << 1`) to `0x4000_0001.eax`.
     - Populate `0x4000_0010`: `eax = tsc_khz` (computed from Motor OS's
       calibrated TSC), `ebx = 1_000_000` (1 GHz virtual LAPIC bus frequency in
       kHz, matching `DIV_CONF` countdown scaling).
2. **Dual-Mode `VcpuLapic`: Early `xAPIC` MMIO (`0xfee0_0000`) + Countdown Timer (`lapic.rs`)**:
   - At vCPU reset, `IA32_APIC_BASE` (`0xfee0_0900` on BSP, `0xfee0_0800` on APs)
     starts with `EXTD` (`1 << 10`) = `0`. Before calling `enable_x2apic()` (or
     if `nox2apic` is passed), Linux maps physical `0xfee0_0000` via `fixmap` and
     accesses `APIC_ID` (`0x20`), `APIC_LVR` (`0x30`), `APIC_SPIV` (`0xf0`),
     `APIC_EOI` (`0xb0`), `APIC_ICR2`/`APIC_ICR` (`0x310`/`0x300`), and LVT/timer
     registers via MMIO.
   - Intercept `VMEXIT_NPF` faults in `[0xfee0_0000 .. 0xfee0_1000)` when xAPIC
     MMIO is enabled (`(apic_base & (1 << 11)) != 0 && (apic_base & (1 << 10)) == 0`)
     and route them to the existing per-vCPU `VcpuLapic` (translating 16-byte
     xAPIC offsets to `0x800 + (offset >> 4)`, formatting `APIC_ID` as
     `vcpu_id << 24`, and latching 32-bit `ICR_HI` at `0x310`).
   - Support one-shot and periodic `INIT_COUNT` (`0x380` / `0x838`), `CUR_COUNT`
     (`0x390` / `0x839`), and `DIV_CONF` (`0x3e0` / `0x83e`) backed by the same
     1 GHz virtual bus clock advertised in `CPUID 0x4000_0010.ebx`, alongside
     `TSC_DEADLINE`.
3. **Architectural TSC & Linux Boot MSR Coverage (`arch/svm.rs`, `host_impl.rs`)**:
   - Handle `MSR_IA32_TSC` (`0x10`, returning `rdtsc_now().wrapping_add(tsc_offset)`
     on `RDMSR` and updating `vmcb.control.tsc_offset` on `WRMSR`) and per-vCPU
     `MSR_IA32_TSC_ADJUST` (`0x3b`) in `svm.rs` so Linux's SMP `check_tsc_warp`
     and `tsc_store_and_check_tsc_adjust` see consistent TSC state across vCPUs.
   - Audit MSRs probed during Linux 6.14 boot (`MSR_IA32_MISC_ENABLE` `0x1a0`,
     MTRR MSRs `0xfe`/`0x200..0x2ff`, `MSR_IA32_SPEC_CTRL` `0x48` /
     `MSR_IA32_PRED_CMD` `0x49`, `MSR_IA32_ARCH_CAPABILITIES` `0x10a`,
     `MSR_MCG_CAP`/`MSR_MCG_CTL` `0x179`/`0x17b`, AMD `MSR_K7_HWCR` `0xc001_0015`
     / `MSR_F10H_DE_CFG` `0xc001_1029` / perfctr MSRs), ensuring architectural
     reads/writes succeed cleanly and genuinely unsupported MSRs probed via
     `rdmsr_safe` behave as Linux expects.
4. **`VmExit::MmioFault` Decoder Verification (`vmm-core/src/hw/insn_decode.rs`)**:
   - On Linux KVM, `HostCaps::DECODED_MMIO` decoded most Linux MMIO instructions
     in host KVM, whereas Motor OS Ring 0 routes every ECAM (`0xe000_0000`),
     `IoApic` (`0xfec0_0000`), and Virtio PCI BAR access through
     `VmExit::MmioFault` -> `vmm-core/src/hw/insn_decode.rs`.
   - Any additional x86_64 addressing mode or opcode emitted by GCC in `bzImage`
     6.14 (`pci_generic_config_read`/`write`, `io_apic.c`, `vp_modern_*`) will be
     added to `insn_decode.rs` (unit-tested in `vmm-core` and shared directly with
     Step `(g)` Linux Ring 0).

### 5.4 Disk Sizing, Scratch Staging, & Zero-Edit `192.168.8.0/24` Networking

1. **L1 Image Sizing (`imager resize`) & Memory Budget**:
   - Stock `motor-os.qcow2` has a `260 MiB` virtual disk, while
     `../linux-blobs/alpine.raw` is `1.0 GiB` (`15 MiB` `bzImage`, `1.2 MiB`
     `initramfs.cpio.gz`).
   - For Sub-step `(f.1)` (`initramfs`), `bzImage` + `initramfs.cpio.gz` (`~16 MiB`
     total) fit inside a standard `260 MiB` L1 image.
   - For Sub-step `(f.2)` (full Alpine), create the staged L1 template via:
     ```sh
     imager resize -i motor-os.qcow2 -o l1-alpine-template.raw --size 2G
     ```
     and stage `bzImage` plus a scratch copy of `alpine.raw` (`--mode rw-rw-r--`)
     under `/user/vm/`. Run L1 with `1536M` RAM (`4` vCPUs) and L2 with `256M`
     RAM (`2` SMP vCPUs) so L1's `sys-io` block cache, `moturus/wasmtime`, and
     pinned L2 Guest RAM have comfortable headroom.
2. **Matching Stock Alpine Networking (`192.168.8.1/24` <-> `192.168.8.2/24`)**:
   - Stock `../linux-blobs/alpine.raw` configures `/etc/network/interfaces`
     statically with `address 192.168.8.2/24` and `gateway 192.168.8.1`.
   - Configuring L2's `[net.dev0]` with `if_name = "vmm0:192.168.8.1/24"` uses
     `MotorIpTap`'s existing CIDR support so L1's `IpDevice` (`192.168.8.1/24`)
     matches unmodified `alpine.raw` out of the box.
   - Because L1's external interface on `moto-tap` is `192.168.4.2/24`,
     `192.168.8.0/24` is conflict-free inside L1. SSH from L0 into L2 uses
     `ProxyCommand="ssh ... -W %h:%p -p 2222 motor@192.168.4.2"` (`russhd`
     direct-tcpip forwarding inside L1), so TCP connections to `192.168.8.2:22`
     originate inside L1's network stack and never collide with L0's `puff-tap`
     (`192.168.8.1/24`).
   - For passwordless SSH in automated tests, inject Motor OS's `test.key.pub`
     into `/root/.ssh/authorized_keys` (and ensure `PermitRootLogin prohibit-password`
     is enabled) on the **scratch copy** of `alpine.raw` via `debugfs -w` prior
     to `imager put` — leaving `../linux-blobs/alpine.raw` completely untouched.

### 5.5 Phased Bring-Up & Deliverables

1. **Sub-step `(f.1)` — Ring-0 Linux Support + Nested `bzImage` + `initramfs`**:
   - Implement the Ring-0 CPUID `0x4000_0010`, `VcpuLapic` xAPIC MMIO + countdown
     timer, and `MSR_IA32_TSC` / Linux MSR updates in `tests/kernel/src/vmm/`
     (plus any `insn_decode.rs` additions uncovered during boot).
   - Boot SMP Linux 6.14 + `initramfs.cpio.gz` inside L1 Motor OS in both
     `--cwasm` and `--wasm` modes, verify BusyBox initramfs banner, interactive
     `ttyS0` (`COM1` IRQ 4) command execution, and clean `poweroff -f` (`ACPI S5`).
   - Add `boot_nested_linux_initrd_{cwasm,wasm}` to
     [`tests/tests/boot_vms.rs`](tests/tests/boot_vms.rs).
2. **Sub-step `(f.2)` — Nested Full Alpine Linux (`virtio-blk` + `IpDevice` + SSH)**:
   - Stage the 2 GiB L1 template holding `bzImage`, scratch `alpine.raw` (with
     `authorized_keys`), `motor-io-host-{cwasm,wasm}`, `vmm-core.cwasm`, and
     `vmm-io.{cwasm,wasm}`.
   - Boot SMP full Alpine Linux in L2 to `alpine-vm login:`, verify `ping -c 2 192.168.8.1`,
     SSH from L0 -> L1 `russhd` (`192.168.4.2:2222`) -> L2 OpenSSH `sshd`
     (`root@192.168.8.2:22`), and clean `poweroff` -> L1 `rush` -> L0 teardown.
   - Add `boot_nested_alpine_{cwasm,wasm}` in
     [`tests/tests/boot_vms.rs`](tests/tests/boot_vms.rs) and interactive launcher
     `vm_scripts/run-nested-linux.sh` (`--cwasm` / `--wasm`, `--initrd`).
