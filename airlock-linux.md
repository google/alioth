# Airlock on Linux: Out-of-Tree Ring-0 `airlock.ko` (`vmm-core-host`) & Ring-3 `vmm-io-host`

## 1. Overview & Goals

With the Motor OS Ring-0 hypervisor (`tests/kernel/src/vmm/`), nested Linux/Motor OS
execution, and `virtio-iommu` PCI device passthrough complete (see
[`architecture.md`](architecture.md), [`airlock-motor-os.md`](airlock-motor-os.md),
and [`vfio-passthrough.md`](vfio-passthrough.md)), the next milestone — referred
to as **Step `(f)`** in the high-level project plan (and tracked as **Step `(g)`**
after the expanded Motor OS sub-steps in [`airlock-motor-os.md`](airlock-motor-os.md))
— moves `vmm-core-host` into **Linux Ring 0** as a standalone loadable kernel
module: **`airlock.ko`**.

### Core Requirements & Non-Negotiable Invariants

1. **100% Out-of-Tree Build Inside `alioth-vmm` (Zero Kernel Patches)**:
   - `airlock.ko` lives entirely inside `alioth-vmm/vmm-core-kmod/` and builds
     against any prepared Linux kernel build tree (`KDIR`, such as an out-of-tree
     build of `../linux-stable` or `/lib/modules/$(uname -r)/build`) **without
     patching a single line of Linux kernel source**.
2. **Complete Independence from KVM (`kvm.ko` Loaded or Unloaded)**:
   - `airlock.ko` has **zero symbol or Kconfig dependencies on `kvm.ko`,
     `kvm-amd.ko`, or `kvm-intel.ko`**.
   - It works identically when `CONFIG_KVM=n`, when `kvm` modules are unloaded,
     when `kvm` + `kvm-amd` are loaded before or after `airlock.ko`, and even
     when KVM VMs and Airlock VMs run concurrently on the same host CPUs.
3. **Byte-Identical `vmm-core` Wasm Binary Across Motor OS & Linux Ring 0**:
   - `airlock.ko` implements `VmmHostCore` + `VmmCoreBridge` in `#![no_std] + alloc`
     Rust, embeds the same `#![no_std]` Wasmtime runtime (`../wasmtime`), and
     loads the **exact same precompiled `vmm-core-motor.cwasm`** (compiled from
     the single byte-identical `vmm-core.wasm` for `x86_64-unknown-none` with
     zero FP/SIMD instructions) that our Motor OS Ring-0 kernel loads.
4. **Seamless Integration with Existing Linux Ring-3 `vmm-io-host`**:
   - Existing `vmm-io-host` (`vmm-io-host-cwasm` / `vmm-io-host-wasm`) gains an
     `--airlock` backend mode that keeps 100% of its Ring-3 device plane
     (`vmm-io.{cwasm,wasm}`, `BridgeShm`, `memfd` Guest RAM, `eventfd` doorbells,
     block I/O, TAP networking, and raw serial) while replacing the Ring-3
     `vmm-core-host` child process with `/dev/airlock` ioctls.
5. **Dual-L0 Nested Verification (`wasm-vmm` & `cloud-hypervisor-static` with `virtio-iommu`)**:
   - Every integration test in `tests/tests/boot_vms.rs` and interactive script
     in `vm_scripts/` boots an L0 hypervisor **with `virtio-iommu`** (either our
     Linux Ring-3 `wasm-vmm` or `cloud-hypervisor-static` via `--vmm chv`), runs
     **Linux in L1**, loads **`airlock.ko`**, and boots **Motor OS** or **Alpine
     Linux** as an **L2 nested guest** (covering both emulated VirtIO devices and
     IOMMU-isolated PCI passthrough).

---

## 2. Out-of-Tree Build Architecture: Why Hybrid Cargo `staticlib` + Thin C Kbuild Shim Wins

### 2.1 Consulting `../linux-stable`: Why Pure Kbuild `.rs` (`CONFIG_RUST=y`) Is Not Enough

Inspecting `../linux-stable` (`7.4-rc3`, specifically
`scripts/Makefile.build:347-382` and `arch/x86/Makefile:27-239`) reveals two
hard limitations of Kbuild's native `obj-m := foo.o` (`.rs` -> `.o`) rule for
`airlock.ko`:

1. **No Cargo Multi-Crate Dependency Graph**:
   `cmd_rustc_o_rs` invokes `rustc` directly on a single `.rs` crate root with
   `--sysroot=/dev/null` and `-Zallow-features=arbitrary_self_types,asm_goto,generic_arg_infer,used_with_arg`.
   It cannot compile `../wasmtime` (`runtime`, `custom-sync-primitives`,
   `threads` — ~30 `#![no_std]` Cargo crates + `build.rs` scripts), `vmm-core`,
   `zerocopy`, and `sha2`.
2. **Brittle `rustc` Exact-Version Coupling & `CONFIG_RUST=y` Requirement**:
   Linux's in-tree `libcore.rlib` and `libkernel.rlib` lock `.rmeta` hashes to
   the exact `rustc` version used to compile `vmlinux` (e.g., if `vmlinux` was
   built with `rustc 1.92.0` while userspace has `rustc 1.98.1`, or if
   `CONFIG_RUST=n`, Kbuild rejects external `.rs` modules).

### 2.2 Chosen Out-of-Tree Architecture (`alioth-vmm/vmm-core-kmod/`)

We build `airlock.ko` **100% out-of-tree inside `alioth-vmm/vmm-core-kmod/`** by
combining a **Cargo `#![no_std] + alloc` `staticlib`** (95% of the module: all
hypervisor, NPT, LAPIC, `pvclock`, doorbell, PCI/IOMMU, and Wasmtime logic in
Rust) with a **~400-line C + assembly Kbuild shim** (`airlock_shim.c` +
`svm_enter.S`):

```text
alioth-vmm/vmm-core-kmod/
├── Makefile                 # Wrapper: probes $(KDIR)/include/config/auto.conf -> runs Cargo -> runs Kbuild M=$PWD
├── Kbuild                   # obj-m := airlock.o ; airlock-y := c/airlock_shim.o c/svm_enter.o airlock_rust.o
├── c/
│   ├── airlock_kapi.h       # Narrow C <-> Rust FFI contract (`airlock_kapi_*` & `airlock_rust_*`)
│   ├── airlock_shim.c       # miscdevice `/dev/airlock`, anon_inode, GUP/folios, vmap+ROX, eventfd, kthread, hrtimer, iommu/pci
│   └── svm_enter.S          # SYM_FUNC_START(airlock_svm_vmrun) with Linux objtool / UNTRAIN_RET_VM / FILL_RETURN_BUFFER macros
└── rust/
    ├── Cargo.toml           # crate-type = ["staticlib"], depends on `vmm-core`, `../wasmtime`, `sha2`, `zerocopy`
    └── src/
        ├── lib.rs           # `#![no_std]` + `extern crate alloc`, `LinuxKernelAllocator`, `panic_handler`, FFI entrypoints
        ├── kapi.rs          # Safe Rust wrappers around `airlock_kapi_*` (SpinLock, Mutex, Pages, PinnedRam, Eventfd, Iommu)
        ├── wasm_runtime.rs  # Ported from `tests/kernel/src/vmm/wasm_runtime.rs` (`LinuxCodeMemory`, `LinuxMemoryCreator`)
        ├── verify_no_fp.rs  # Shared with `tests/kernel/src/vmm/verify_no_fp.rs`
        ├── host_impl.rs     # `LinuxHvCore: VmmHostCore` + `LinuxCoreBridge: VmmCoreBridge`
        ├── vcpu_thread.rs   # Per-vCPU kthread run loop + eventfd `io_to_core` wakeup handler
        ├── stage2.rs        # 4 KiB / 2 MiB Stage-2 NPT MMU backed by Linux `alloc_page` frames
        ├── lapic.rs         # xAPIC MMIO + x2APIC MSR + `hrtimer`-backed `TSC_DEADLINE` / countdown timer
        ├── pvclock.rs       # KVM-compatible `pvclock` (`MSR_KVM_SYSTEM_TIME_NEW`)
        ├── doorbell.rs      # Lock-free sorted `DoorbellTable` (`QueueNotify` -> `core_to_io` + `eventfd_signal`, 0 Wasm calls)
        ├── pci_host.rs      # `VmmHostCore::pci_*` backed by Linux `iommu_domain` + `pci_dev` + MSI-X `request_irq`
        └── arch/
            ├── mod.rs
            ├── svm.rs       # KVM-independent AMD SVM world-switch & MSR/CPUID/NPF/IOIO handling
            └── vmx.rs       # Capability probe + trait boundary for Intel VMX + EPT
```

### 2.3 Matching Linux x86_64 Codegen, `objtool`, & `modpost` Without Patching `$KDIR`

As verified in `../linux-stable/arch/x86/Makefile`, x86_64 kernel modules must
satisfy strict ABI and `objtool` rules. `vmm-core-kmod/Makefile` inspects
`$(KDIR)/include/config/auto.conf` and builds `libairlock_rust.a` with the exact
matching flags:

1. **Base Kernel Rust Flags (`--target x86_64-unknown-none`, `-Z build-std=core,alloc`)**:
   - `-Ccode-model=kernel` (emits 32-bit signed `R_X86_64_32S` / `R_X86_64_PC32`
     relocations required for modules loaded in `0xffffffffa0000000..`)
   - `-Crelocation-model=static`
   - `-Cno-redzone=y`
   - `-Ctarget-feature=-mmx,-sse,-sse2,-sse3,-ssse3,-sse4.1,-sse4.2,-avx,-avx2,+soft-float`
   - `-Cforce-frame-pointers=y` and `-Cpanic=abort`
2. **Speculative-Execution & Control-Flow Flags Probed from `auto.conf`**:
   - `CONFIG_MITIGATION_RETHUNK=y` -> `-Zfunction-return=thunk-extern` (emits
     `jmp __x86_return_thunk` instead of bare `ret`, required by `objtool`)
   - `CONFIG_MITIGATION_RETPOLINE=y` -> `-Zretpoline` (or indirect-branch thunking)
   - `CONFIG_X86_KERNEL_IBT=y` -> `-Zcf-protection=branch -Cjump-tables=n` (emits
     `endbr64` on all Rust functions so kernel indirect calls pass `CR4.CET`)
   - `CONFIG_CALL_PADDING=y` -> `-Zpatchable-function-entry=16,16`
3. **Relocatable Object Packaging (`libairlock_rust.a` -> `airlock_rust.o_shipped`)**:
   - `ld -r --whole-archive libairlock_rust.a -o airlock_rust.raw.o` merges all
     Cargo `.rlib` objects into one relocatable ELF.
   - `objcopy --keep-global-symbols=keep_syms.txt --remove-section=.eh_frame`
     localizes all internal Rust/Wasmtime symbols (leaving only `airlock_rust_*`
     visible to `airlock_shim.c`), preventing any symbol namespace collision with
     the kernel or other modules, and Kbuild links
     `airlock_shim.o + svm_enter.o + airlock_rust.o` into `airlock.ko` (running
     `objtool` and `modpost` normally).
   - Just like `tests/kernel/build.sh`, the build script disassembles
     `airlock_rust.o` with `objdump -d` and fails the build if **any**
     `%xmm`/`%ymm`/`%zmm`/`%mm` register appears.

> **Result**: `airlock.ko` builds completely outside `../linux-stable`, requires
> **neither `CONFIG_RUST=y` nor `CONFIG_KVM=y/m`**, and works against both our
> L1 guest kernel built from `../linux-stable` (via `make O=target/linux-kbuild`,
> keeping `../linux-stable` 100% clean) and standard host distro headers.

---

## 3. Complete System Architecture (`L0 -> L1 Linux + airlock.ko -> L2 Guest`)

```text
+=========================================================================================+
| L1 Linux Userspace (Ring 3) — Existing `vmm-io-host-{cwasm,wasm} --airlock`             |
|                                                                                         |
|  +-----------------------------------------------------------------------------------+  |
|  | `LinuxIoHost` + `vmm-io.{cwasm,wasm}` (Unmodified Wasm Binary!)                   |  |
|  |  - Parses `vm.toml` (`kernel`/`pvh`, `blk`, `net`, `pci`, `iommu`)                |  |
|  |  - Allocates `BridgeShm` (`memfd`), Guest RAM (`memfd`), payload (`memfd`)        |  |
|  |  - Creates `c2i_fd` & `i2c_fd` (`eventfd`), opens `/dev/airlock`                  |  |
|  |  - `ioctl(AIRLOCK_IOC_CREATE_VM)` passes VAs + FDs + `vmm-core-motor.cwasm`       |  |
|  |  - Runs `mio::Poll` event loop (block `pread`/`pwrite`, TAP, tty, `c2i_fd`)       |  |
|  +-----------------------------------------+-----------------------------------------+  |
+============================================|============================================+
                              Ring 3 / Ring 0 | Airlock Boundary
             Pinned `memfd` Pages (`pin_user_pages_fast`) + `eventfd_ctx` Doorbells
+============================================|============================================+
| L1 Linux Kernel (Ring 0) — Out-of-Tree Loadable Module `airlock.ko`                     |
|                                            v                                            |
|  +-----------------------------------------------------------------------------------+  |
|  | `VmInstance` (`LinuxHvCore` + `LinuxCoreBridge` + `MotorWasmRuntime`)             |  |
|  |  - Loads & FP-verifies **exact same** `vmm-core-motor.cwasm` (`R+X` `W^X` `vmap`) |  |
|  |  - Per-vCPU `kthread`s (`airlock-vcpu/%u-%u`) + `i2c_fd` poll waitqueue callback  |  |
|  |  - KVM-independent AMD SVM (`VMRUN`) + 4 KiB / 2 MiB NPT (`stage2.rs`)            |  |
|  |  - Ring-0 `VcpuLapic` (`hrtimer` deadline/periodic) + `pvclock` + `DoorbellTable` |  |
|  |  - `LinuxPciHost`: `iommu_paging_domain_alloc` + `pci_dev` + MSI-X `request_irq`  |  |
|  |    (talks automatically to L1's `drivers/iommu/virtio-iommu.c` -> L0 IOMMU!)      |  |
|  +-----------------------------------------------------------------------------------+  |
+============================================|============================================+
                                L1 / L0 Nested | Hardware Boundary
+============================================|============================================+
| L0 Host Hypervisor (`wasm-vmm` with `iommu = true` OR `cloud-hypervisor-static`)        |
|  - Nested SVM (`nested=on`), `virtio-iommu` (`00:01.0` + ACPI `VIOT`), `blk`, `net`     |
+=========================================================================================+
```

---

## 4. Key Kernel-Level Design Details

### 4.1 KVM Independence & Zero-Conflict Hardware Coexistence (`arch/svm.rs` + `svm_enter.S`)

Consulting `../linux-stable/arch/x86/virt/hw.c` and
`../linux-stable/include/linux/kvm_types.h` exposes two critical facts about how
modern Linux (`7.x`) manages x86 virtualization hardware:

1. `x86_virt_get_ref()` and `x86_virt_put_ref()` are marked
   `EXPORT_SYMBOL_FOR_KVM` (`EXPORT_SYMBOL_FOR_MODULES(..., "kvm,kvm-intel,kvm-amd")`)
   and are compiled out completely when `CONFIG_KVM=n`. `airlock.ko` therefore
   must not call them.
2. In `arch/x86/virt/hw.c:229-239`, when `kvm-amd` starts its first VM,
   `x86_svm_enable_virtualization_cpu()` executes:
   ```c
   rdmsrq(MSR_EFER, efer);
   if (efer & EFER_SVME)
       return -EBUSY;
   wrmsrq(MSR_EFER, efer | EFER_SVME);
   ```
   And in `arch/x86/kvm/svm/svm.c:596`, `kvm-amd` writes its own `sd->save_area_pa`
   into `MSR_VM_HSAVE_PA` (`0xc001_0117`) while clearing `EFER_SVME` and
   `MSR_VM_HSAVE_PA` when its last VM closes!

If `airlock.ko` naively enabled `EFER_SVME` globally at `insmod` time, starting a
KVM VM afterward would fail with `-EBUSY`; conversely, if `kvm-amd` closed its
last VM while `airlock.ko` was loaded, `kvm-amd` would clear `EFER_SVME` out from
under `airlock.ko`!

#### Airlock's Per-Slice IRQ-Off SVM Sharing Protocol

`airlock.ko` avoids **all** global state conflicts with `kvm-amd` by scoping
`EFER.SVME` and `MSR_VM_HSAVE_PA` strictly to the non-preemptible, IRQ-disabled
world-switch window on the current physical CPU:

1. At module init (`airlock_init`), `airlock.ko` verifies `CPUID.8000_0001:ECX.SVM`,
   `CPUID.8000_000A` (NPT + NASIDs), and `(rdmsr(MSR_VM_CR) & VM_CR_SVMDIS) == 0`,
   and pre-allocates two zeroed 4 KiB pages per possible CPU
   (`alloc_pages_node(cpu_to_node(cpu), GFP_KERNEL | __GFP_ZERO, 0)`):
   `airlock_hsave_pa[cpu]` and `airlock_host_vmsave_pa[cpu]`. **It does not
   modify `MSR_EFER` or `MSR_VM_HSAVE_PA` at `insmod` time.**
2. Inside `airlock_vcpu_run_slice()` on vCPU `kthread`:
   - Call `kernel_fpu_begin_mask(0)` (saving Linux host task/user FPU state) and
     restore the guest's `XCR0` + `XSAVE` / `FXRSTOR` state.
   - Enter `local_irq_save(flags)` (preemption + local maskable IRQs disabled on
     this pCPU — neither a KVM vCPU task nor a `kvm-amd` `on_each_cpu` IPI can
     execute on this CPU until `local_irq_restore(flags)`):
     1. Check `signal_pending(current) || need_resched() || vcpu.kicked`: if set,
        bail out immediately before guest entry.
     2. Read `orig_efer = rdmsr(MSR_EFER)` and `orig_hsave_pa = rdmsr(MSR_VM_HSAVE_PA)`.
     3. If `(orig_efer & EFER_SVME) == 0`, set `wrmsr(MSR_EFER, orig_efer | EFER_SVME)`.
     4. Set `wrmsr(MSR_VM_HSAVE_PA, airlock_hsave_pa[cpu])`.
     5. **ASID Hygiene**: If `orig_hsave_pa != 0` (meaning `kvm-amd` is also
        active on this CPU), or if `last_pcpu != cpu` or `stage2.tlb_gen` changed,
        set `vmcb.control.tlb_ctl = TLB_CONTROL_FLUSH_ASID` (`3`) so guest ASID
        tags never collide with a concurrent KVM guest.
     6. Save host `VMSAVE(airlock_host_vmsave_pa[cpu])` and swap `MSR_TSC_AUX` +
        `MSR_IA32_SPEC_CTRL` (when `!X86_FEATURE_V_SPEC_CTRL`).
     7. Execute `CLGI` -> `raw_local_irq_enable()` (`STI` under `GIF=0`, matching
        `arch/x86/kvm/svm/svm.c:4592` so `V_INTR_MASKING=1` keeps physical IRQs
        enabled while in guest mode) -> `VMLOAD(vmcb_pa)` -> `VMRUN(vmcb_pa)` ->
        `VMSAVE(vmcb_pa)` -> `VMLOAD(airlock_host_vmsave_pa[cpu])` ->
        `FILL_RETURN_BUFFER` + `UNTRAIN_RET_VM` -> `raw_local_irq_disable()`
        (`CLI` while still under `GIF=0`!).
     8. Restore host `MSR_TSC_AUX`, `wrmsr(MSR_VM_HSAVE_PA, orig_hsave_pa)`, and
        — if `(orig_efer & EFER_SVME) == 0` — restore `wrmsr(MSR_EFER, orig_efer)`
        *(note: per AMD APM Vol. 2 §15.5 / §15.16, clearing `EFER.SVME` does not
        prevent subsequent `VMRUN`s once re-enabled, and if `orig_efer` stay-on
        optimization is desired when `!kvm`, we still clear `EFER.SVME` before
        re-enabling IRQs so `modprobe kvm_amd` at any instant succeeds with `0`
        `-EBUSY` errors; `RDMSR`/`WRMSR(EFER)` adds only ~35 cycles to a VM exit
        while guaranteeing 100% transparent coexistence!)*.
     9. Execute `STGI`, then `local_irq_restore(flags)` so any physical host
        interrupt that triggered `VMEXIT_INTR` vectors cleanly through Linux's
        standard IDT with host `GS_BASE`, `TR`, `MSR_VM_HSAVE_PA`, and `EFER`
        already 100% restored.
   - Save guest FPU/XMM state and call `kernel_fpu_end()`.
3. Register a `reboot_notifier` (`register_reboot_notifier`) and emergency clean
   teardown on `rmmod airlock` so no CPU is ever left in guest mode across reboot.

*(For Intel hosts, the `ArchHypervisor` trait boundary in `arch/vmx.rs` mirrors
this exact split; when `CR4.VMXE == 0`, `airlock.ko` manages its own per-CPU
`VMXON` region, and if `kvm-intel` actively holds `VMXON` on that CPU (`CR4.VMXE == 1`),
either rejects concurrent VMX start cleanly with `-EBUSY` or runs when KVM has
0 active VMs — since modern Linux `hw.c` only holds `CR4.VMXE` while at least one
KVM VM exists.)*

---

### 4.2 Loading `vmm-core-motor.cwasm` in Linux Ring 0 (`W^X`, `IBT`, & Stack Budget)

1. **Exact Same `.cwasm` Artifact as Motor OS Ring 0**:
   `vmm-core-host/build.rs` already precompiles the single byte-identical
   `vmm-core.wasm` with `target("x86_64-unknown-none")`,
   `signals_based_traps(false)`, `memory_guard_size(0)`, and
   `memory_reservation(0)`, producing `vmm-core-motor.cwasm` and verifying via
   `validate_cwasm_no_fp` that its `.text` contains **zero** FP/SIMD instructions.
   `airlock.ko` loads **that exact file** (also symlinked/exposed as
   `vmm-core-airlock.cwasm` / accepted directly by `vmm-io-host --airlock`).
2. **TOCTOU-Free `W^X` Executable Mapping Without `set_memory_x` (`LinuxCodeMemory`)**:
   As verified in `../linux-stable/mm/vmalloc.c:3624` and
   `arch/x86/mm/pat/set_memory.c`, Linux does not export `set_memory_x` or
   `execmem_alloc` to external modules, and `vmap()` applies `pgprot_nx(prot)`.
   However, `vmap()` **is** exported (`EXPORT_SYMBOL(vmap)`) and maps an array of
   `struct page *` frames using dedicated **4 KiB leaf PTEs** (`PAGE_SHIFT`) in
   `init_mm`, and `lookup_address()` **is** exported (`EXPORT_SYMBOL_GPL(lookup_address)`):
   - `CwasmCodeBacking` allocates `N` private `struct page *` frames via
     `alloc_page(GFP_KERNEL | __GFP_ZERO)` and copies the user `.cwasm` buffer
     into them via `copy_from_user` through the kernel direct map (`RW + NX`), so
     Ring 3 can never mutate the image after copy.
   - `validate_cwasm_no_fp` validates the ELF + machine code while all mappings
     are still `NX`.
   - `vmap(pages, N, VM_MAP, PAGE_KERNEL_RO)` creates a virtually contiguous
     `RO + NX` mapping backed by 4 KiB PTEs (never splitting 2 MiB direct-map
     hugepages).
   - `LinuxCodeMemory::publish_executable(ptr, len)` walks the 4 KiB `vmap` PTEs
     for `[ptr .. ptr + len)` via `lookup_address(va, &level)`, clears `_PAGE_RW`
     and `_PAGE_NX` (`PAGE_KERNEL_ROX` — strictly `R+X`, never `RWX`), and
     executes `on_each_cpu(airlock_flush_tlb_local, ...)` (`__native_flush_tlb_global()`).
   - On VM teardown (`Drop`), `unpublish_executable` restores `_PAGE_NX` on those
     PTEs + flushes TLBs *before* `vunmap()` and `__free_page()`.
3. **Kernel IBT (`CONFIG_X86_KERNEL_IBT`) Compatibility**:
   Cranelift's x86_64 backend does not emit `endbr64` instructions at Wasm
   trampoline targets. On kernels compiled with `CONFIG_X86_KERNEL_IBT=y` where
   hardware CET IBT is active (`cpu_feature_enabled(X86_FEATURE_IBT)`), indirect
   calls into `.cwasm` would raise `#CP` unless `MSR_IA32_S_CET.ENDBR_EN` is
   temporarily cleared — the exact mechanism Linux itself uses in
   `arch/x86/include/asm/ibt.h` (`ibt_save(true)` / `ibt_restore()`) when calling
   UEFI Runtime Services. Our C shim provides a 10-line `airlock_call_wasm(...)`
   wrapper that disables preemption (or saves per-task CET state across preempt)
   and brackets the non-blocking Wasm invocation with `MSR_IA32_S_CET`
   `ENDBR_EN` clear/restore when `X86_FEATURE_IBT` is active.
4. **Respecting Linux's `16 KiB` Kernel Stack (`THREAD_SIZE = 16 KiB`, `CONFIG_FRAME_WARN = 2048`)**:
   - All VM, vCPU, Stage-2 MMU, PCI, and Wasmtime `Store` structures are heap-allocated
     (`Box` / `Arc` backed by `kvmalloc_node` / `kmalloc`), keeping per-frame
     stack usage well below `2 KiB`.
   - Wasm guest execution uses its own disjoint shadow stacks inside
     `LinuxLinearMemory` (`vmm_stack_top(slot_id)`), and Cranelift's host call
     frames for `vmm-core` use `< 2 KiB` of host kernel stack.
   - `WASMTIME_TLS` uses a per-CPU `[[AtomicUsize; 2]; NR_CPUS]` array (or swaps
     the 2-word TLS slot inside `airlock_wasm_enter` / `sched_in` if preemption is
     enabled during cold `vmm_init`), ensuring `wasmtime_tls_get`/`set` works
     safely across `NR_CPUS`.

---

### 4.3 `/dev/airlock` UAPI & Integration with Existing `vmm-io-host`

`airlock.ko` registers a `miscdevice` at `/dev/airlock` (`mode = 0660`). Its UAPI
is intentionally tiny — just **one** device ioctl returning an anonymous-inode
`vm_fd` (`anon_inode_getfd("airlock-vm", &airlock_vm_fops, vm, O_RDWR | O_CLOEXEC)`):

```c
#define AIRLOCK_IOCTL_MAGIC 0xA4

struct airlock_create_vm {
    __u64 shm_uaddr;      /* 4 KiB-aligned user VA of mmap'd BridgeShm memfd      */
    __u64 shm_size;       /* sizeof(BridgeShm), page-aligned                      */
    __u64 ram_uaddr;      /* 4 KiB-aligned user VA of mmap'd Guest RAM memfd      */
    __u64 ram_size;       /* Guest RAM byte size ([4 MiB ..= 64 GiB])             */
    __u64 payload_uaddr;  /* 4 KiB-aligned user VA of packed kernel||initrd       */
    __u64 payload_size;   /* Byte length of boot payload (0 if none)              */
    __u64 cwasm_uaddr;    /* User pointer to vmm-core-motor.cwasm bytes           */
    __u64 cwasm_size;     /* Byte length of .cwasm image (<= 16 MiB)              */
    __s32 c2i_eventfd;    /* Ring 0 -> Ring 3 doorbell eventfd                    */
    __s32 i2c_eventfd;    /* Ring 3 -> Ring 0 doorbell eventfd                    */
};

#define AIRLOCK_IOC_CREATE_VM _IOW(AIRLOCK_IOCTL_MAGIC, 0x01, struct airlock_create_vm)
```

#### How `vmm-io-host` Drives `/dev/airlock` (`--airlock`)

Look at how cleanly this plugs into [`vmm-io-host/src/main.rs`](vmm-io-host/src/main.rs)
and [`vmm-io-host/src/linux_host.rs`](vmm-io-host/src/linux_host.rs):

1. **CLI Selection**:
   `vmm-io-host` accepts `--airlock` (or `VMM_AIRLOCK=1`, optionally
   `--airlock-dev /dev/airlock`). Without `--airlock`, it continues spawning
   `vmm-core-host-{cwasm,wasm}` over Linux KVM as before (`100%` backward
   compatible). With `--airlock`, `--core-wasm` defaults to
   `vmm-core-motor.cwasm`.
2. **Deferred VM Start Inside `LinuxIoHost::io_register_vm_config`**:
   Today on Linux KVM, `main.rs` spawns `vmm-core-host` before `vmm-io` parses
   `vm.toml`, and `vmm-core-host` blocks on `cfg_fd` until
   `io_register_vm_config` populates `BridgeShm` (`ram_fd` `ftruncate` + `mmap`,
   `payload_fd` write, `boot_info`, `virtio_devs`, `pci_devs`).
   In `--airlock` mode (matching `MotorIoHost::io_register_vm_config` on Motor OS!),
   `io_register_vm_config` already has `shm` (`BridgeShm`), `ram_base`/`ram_len`
   (`MAP_SHARED` `memfd`), packed `payload` (`mmap`), `c2i_fd`, and `i2c_fd`
   ready — so it immediately invokes `ioctl(airlock_dev_fd, AIRLOCK_IOC_CREATE_VM, &req)`
   and stores the returned `vm_fd`!
3. **Zero-Copy Steady-State I/O & Doorbells**:
   - **Ring 0 -> Ring 3**: When `vmm-core` (or the Ring-0 `DoorbellTable` fast
     path on guest `QueueNotify`!) pushes to `BridgeShm::core_to_io`, `airlock.ko`
     calls `eventfd_signal(c2i_ctx)`. `LinuxIoHost`'s existing `mio::Poll` wakes
     on `TOKEN_CORE_BRIDGE` (`c2i_fd`) **with zero changes to `linux_host.rs`'s
     event loop or `vmm-io.wasm`!**
   - **Ring 3 -> Ring 0**: When `LinuxIoHost` pushes to `BridgeShm::io_to_core`
     and writes `1` to `i2c_fd`, `airlock.ko`'s registered `wait_queue_entry_t`
     poll wakeup callback on `i2c_fd` fires immediately:
     - For `IO_MSG_VIRTIO_IRQ`, it resolves `(msi_addr, msi_data)` in `BridgeShm`
       and injects the MSI into the target `VcpuLapic` + `smp_send_reschedule` /
       `wake_up_process` **directly in the wakeup callback (0 kthread hops, 0 Wasm
       calls)**!
     - For `IO_MSG_SERIAL_RX` or `IO_MSG_REQUEST_SHUTDOWN`, it wakes the per-VM
       `airlock-rx` kthread to invoke `vmm_on_bridge_rx()`.
4. **Automatic Leak-Free Teardown**:
   Closing `vm_fd` (explicitly on clean shutdown or automatically by the Linux
   VFS if `vmm-io-host` crashes or receives `SIGKILL`) invokes
   `airlock_vm_release()`:
   - Sets `shutdown_requested = 1`, wakes and `kthread_stop()`s all `airlock-vcpu`
     and `airlock-rx` kthreads,
   - Detaches any passed-through PCI devices, frees MSI-X IRQs and the VM's
     `iommu_domain` **before** unpinning Guest RAM,
   - Drops `MotorWasmRuntime` (restoring `NX` and `vunmap`ping `.cwasm`) and NPT
     page tables,
   - Releases `eventfd_ctx_put` and calls `unpin_user_pages_dirty_lock(..., true)`
     on Guest RAM + `BridgeShm`.

---

### 4.4 Stage-2 NPT, Timers, & IOMMU-Isolated PCI Passthrough in `airlock.ko`

1. **Pinned Guest RAM (`pin_user_pages_fast`) & Stage-2 NPT (`stage2.rs`)**:
   - `airlock_shim.c` pins `BridgeShm` (`FOLL_WRITE | FOLL_LONGTERM`) and Guest
     RAM (`FOLL_WRITE | FOLL_LONGTERM`), recording each page's physical address
     `page_to_phys(page)` (and `vmap`ping `BridgeShm`'s few pages into kernel VA
     space so Ring 0 reads/writes `BridgeShm` directly).
   - `stage2.rs` builds standard 4-level AMD NPT page tables from `alloc_page(GFP_KERNEL | __GFP_ZERO)`
     frames (automatically using **2 MiB large NPT PDEs** whenever a 2 MiB GPA
     chunk is backed by physically contiguous pages such as THP / hugepages,
     falling back seamlessly to 4 KiB NPT PTEs otherwise).
2. **High-Resolution Timers (`hrtimer`) & Blocking `HLT` (`wait_event_interruptible`)**:
   - Each vCPU owns a Linux `struct hrtimer` (`CLOCK_MONOTONIC`, `HRTIMER_MODE_REL` /
     `ABS`) armed whenever the guest programs `MSR_IA32_TSC_DEADLINE` or xAPIC/x2APIC
     `INIT_COUNT` and enters `HLT`.
   - On guest `HLT` (or AP `MpState::Uninitialized` pre-`SIPI`), the vCPU kthread
     sleeps in `wait_event_interruptible` (`0%` host CPU while idle!), waking
     instantly on LAPIC IRR injection, `INIT`/`SIPI`, `hrtimer` expiry, or signal/teardown.
3. **PCI Device Passthrough via Linux's Native `iommu_domain` + `virtio-iommu` (`pci_host.rs`)**:
   Because L0 (`wasm-vmm` with `iommu = true` or `cloud-hypervisor-static` with
   `iommu=virtio`) exposes `virtio-iommu` (`00:01.0`) + ACPI `VIOT`, L1 Linux's
   built-in `drivers/iommu/virtio-iommu.c` automatically registers all L1 PCI
   endpoints with the Linux IOMMU subsystem!
   `airlock.ko` implements `VmmHostCore::pci_*` directly on Linux's exported
   `EXPORT_SYMBOL_GPL` IOMMU and PCI APIs (requiring **zero VFIO/KVM glue**):
   - **Device Binding before Launch**: In L1 Linux, any PCI BDF destined for L2
     (e.g. `0000:00:03.0`) is unbound from its L1 kernel driver (`virtio-pci`)
     via sysfs (`/sys/bus/pci/devices/0000:00:03.0/driver/unbind` or kernel
     cmdline `pci-stub.ids=...`).
   - **`pci_attach(host_bdf)`**:
     1. Looks up `struct pci_dev *` via `pci_get_domain_bus_and_slot(0, bus, devfn)`
        and claims exclusive DMA ownership via
        `iommu_group_claim_dma_owner(pdev->dev.iommu_group, vm_owner)` (failing
        closed with `HvError::Unsupported` if no IOMMU group or no hardware/virtio
        IOMMU translation domain is available!).
     2. Allocates a per-VM paging IOMMU domain via
        `iommu_paging_domain_alloc(&pdev->dev)` (if not yet created for this VM),
        replays all existing Guest RAM `gpa_map` regions into it via
        `iommu_map(dom, gpa, hpa, len, IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE, GFP_KERNEL)`
        (coalescing physically contiguous page runs!), and attaches the endpoint
        via `iommu_attach_device(dom, &pdev->dev)` (or `iommu_attach_group`).
     3. Calls `pci_enable_device_mem(pdev)`, resets the function (`__pci_reset_function_locked`
        / VirtIO `device_status = 0`), sizes `BAR0..BAR5` via `pci_resource_start`/`len`/`flags`,
        and exposes MMIO BARs as `MemBacking::PciBarMmio` (mapped `UC` in Stage-2 NPT
        with **0 L1 VM-exits on `QueueNotify` doorbells**!).
   - **`pci_configure_msix`**:
     Allocates physical MSI-X vectors via `pci_alloc_irq_vectors(pdev, n, n, PCI_IRQ_MSIX)`
     and binds a Ring-0 hardirq handler (`request_irq(pci_irq_vector(pdev, idx), airlock_msix_isr, 0, ...)`)
     that calls `hv.inject_msi_from_isr(guest_addr, guest_data)` + wakes the target
     vCPU (**0 Ring-3 hops, 0 Wasm calls**).

---

### 4.5 All-PCI Passthrough Topology (`initramfs`-Only L1 Linux & Zero Ring-3 VM-Exits)

When **all** guest PCI endpoints (`00:02.0` `virtio-blk` and `00:03.0` `virtio-net`)
are passed through from L0 to L2 (`pci = ["00:02.0", "00:03.0"]`,
`num_virtio_devs == 0`):

1. **Diskless `initramfs`-Only L1 Linux (Zero L1 PCI Devices Used)**:
   - L0 (`wasm-vmm` with `iommu = true` or `cloud-hypervisor-static` with
     `iommu=virtio`, omitting `virtio-rng` since L1 enables
     `CONFIG_RANDOM_TRUST_CPU=y` `RDRAND`) exposes only `00:01.0`
     (`virtio-iommu`), `00:02.0` (`virtio-blk` backed directly by L2's
     `alpine.raw` or `motor-os.raw`), and `00:03.0` (`virtio-net` backed directly
     by L0's `puff-tap` or `moto-tap`).
   - L1 Linux boots purely from `initramfs` (`rootfs` in RAM) with kernel cmdline
     `pci-stub.ids=1af4:1042,1af4:1041` so L1's `virtio-pci` driver never claims
     `00:02.0` or `00:03.0`, while L1's built-in `virtio-iommu` driver claims
     `00:01.0` in Ring 0 to isolate L2 DMA.
   - L1's `/init` runs `insmod /lib/modules/airlock.ko` and invokes
     `vmm-io-host --airlock` with `pci = ["00:02.0", "00:03.0"]` and L2's boot
     kernel (`bzImage` for L2 Alpine, or `kloader` + `initrd` for L2 Motor OS)
     bundled inside L1's `initramfs` (and powers off L1 via `poweroff -f` -> L0
     ACPI S5 as soon as L2 shuts down).
2. **Strict Zero L1 Ring-3 VM-Exit Guarantee**:
   - Every L2 vCPU runs inside an L1 Ring-0 `airlock-vcpu/%u-%u` `kthread` —
     there is **no** `ioctl(KVM_RUN)` userspace loop, so **a vCPU VM-exit never
     transitions to L1 Ring 3**.
   - Steady-state BAR MMIO & `QueueNotify` writes go directly through Stage-2 NPT
     `UC` mappings (`0` L1 Ring-3 transitions and `0` L1 Ring-0 VM-exits), DMA is
     translated directly by `virtio-iommu`, MSI-X interrupts are injected directly
     from L1 Ring-0 hardirq context (`airlock_msix_isr` -> `VcpuLapic`), and
     cold-path exits (`ECAM`, MSI-X table MMIO, `IoApic`, `CPUID`, MSRs, `HLT`,
     `pvclock`) execute 100% inside L1 Ring 0 (`airlock.ko` +
     `vmm-core-motor.cwasm`).
   - Ring-3 `vmm-io-host --airlock` sleeps at `0%` CPU in `epoll_wait`, waking
     asynchronously on `c2i_fd` **only** to forward `COM1` (`0x3f8`) console log
     bytes (`CORE_MSG_SERIAL_TX`, non-blocking ring push while the vCPU stays in
     Ring 0) and on final L2 `CORE_MSG_SHUTDOWN`.

---

## 5. L1 Linux Guest Environment, Test Matrix, & `vm_scripts/`

### 5.1 Building the L1 Linux Kernel (`bzImage`) & `airlock.ko` Out-of-Tree

Our existing `../linux-blobs/bzImage` (`6.14.11`) is a static monolithic kernel
without matching module build headers on disk. Since `../linux-stable` (`7.4-rc3`)
is right in the workspace root, we add a reproducible, incremental helper
(`tests/src/bin/build_linux_airlock.rs` / `vmm-core-kmod/build.sh`) that:

1. **Keeps `../linux-stable` 100% Read-Only & Clean**:
   Builds L1's kernel strictly out-of-tree into `alioth-vmm/target/linux-kbuild/`
   (`make -C ../linux-stable O=.../target/linux-kbuild`) from a minimal, fast-compiling
   fragment (`vmm-core-kmod/l1-guest.config`: `SMP`, `MODULES`, `MODULE_UNLOAD`,
   `RANDOM_TRUST_CPU`, `SERIAL_8250_CONSOLE`, `VIRTIO_PCI`, `VIRTIO_BLK`,
   `VIRTIO_NET`, `VIRTIO_IOMMU`, `ACPI_VIOT`, `EXT4_FS`, `BLK_DEV_INITRD`, `NET`,
   `INET`, `PACKET`, `TUN`, `BRIDGE`, `PCI_STUB`, `KVM=m`, `KVM_AMD=m` — ~45 seconds
   incremental/`-j$(nproc)` build, cached across runs!).
   - Having `CONFIG_KVM=m` and `CONFIG_KVM_AMD=m` built as optional `.ko` modules
     lets our automated tests verify **both** states in the exact same L1 image:
     1. Default boot: `kvm.ko` & `kvm-amd.ko` **not loaded** -> `insmod airlock.ko` -> boot L2!
     2. Coexistence test: `insmod kvm.ko && insmod kvm-amd.ko` **loaded** -> `insmod airlock.ko` -> boot L2 (and verify `/dev/kvm` is also non-`-EBUSY`)!
2. **Builds `airlock.ko` Completely Out-of-Tree in `alioth-vmm/vmm-core-kmod/`**:
   Runs Cargo (`airlock-rust` `staticlib`) + `make -C target/linux-kbuild M=$PWD/vmm-core-kmod modules`,
   producing `target/airlock/airlock.ko`.
3. **Stages Both Disk-Backed & `initramfs`-Only L1 Environments**:
   - **Disk-Backed L1 (Scenarios 1–5)**: Copies `airlock.ko` (plus optional
     `kvm.ko`/`kvm-amd.ko` for the coexistence test), static musl
     `vmm-io-host-{cwasm,wasm}`, `vmm-io.{cwasm,wasm}`, `vmm-core-motor.cwasm`,
     and L2 guest images into a scratch L1 Alpine ext4 disk (never touching
     `../linux-blobs/alpine.raw` or `../motor-dev/motor-os`).
   - **`initramfs`-Only L1 for All-PCI Passthrough (Scenarios 6–7)**: Packs a
     lightweight `cpio.gz` overlay on top of BusyBox `initramfs.cpio.gz`
     containing `airlock.ko`, `vmm-io-host-{cwasm,wasm}`, `vmm-io.{cwasm,wasm}`,
     `vmm-core-motor.cwasm`, `vm-l2.toml` (`pci = ["00:02.0", "00:03.0"]`), and
     L2's boot kernel (`bzImage` for Alpine or `kloader` + `initrd` for Motor OS)
     so L1 boots completely diskless and passes **all** PCI devices straight
     through to L2.

---

### 5.2 Automated Integration Test Matrix (`tests/tests/boot_vms.rs`)

Every L1-Linux + `airlock.ko` nested test runs with **L0 `virtio-iommu` enabled**
across **both** L0 hypervisors (`L0Engine::WasmVmm` with `iommu = true` and
`L0Engine::Chv` `cloud-hypervisor-static` with `--cpus nested=on` and `iommu=virtio`):

| Nested Scenario (`L0 [virtio-iommu] -> L1 Linux [airlock.ko] -> L2 Guest`) | L0 = `wasm-vmm` (`iommu = true`) | L0 = `cloud-hypervisor-static` (`virtio-iommu`) |
| :--- | :--- | :--- |
| **1. Smoke + KVM-Coexistence (`L2 = test-guest`, verifies both `!kvm` and `kvm_amd` loaded)** | `boot_airlock_linux_test_guest_{cwasm,wasm}` | `boot_airlock_linux_test_guest_chv` |
| **2. Nested Full Motor OS (`L2 = Motor OS` with `virtio-blk` + TAP `virtio-net` + SSH)** | `boot_airlock_linux_motor_os_{cwasm,wasm}` | `boot_airlock_linux_motor_os_chv_{cwasm,wasm}` |
| **3. Nested Linux `initramfs` (`L2 = bzImage + initramfs.cpio.gz`)** | `boot_airlock_linux_initrd_{cwasm,wasm}` | `boot_airlock_linux_initrd_chv_{cwasm,wasm}` |
| **4. Nested Full Alpine Linux (`L2 = Alpine` with `virtio-blk` + TAP `virtio-net` + SSH)** | `boot_airlock_linux_alpine_{cwasm,wasm}` | `boot_airlock_linux_alpine_chv_{cwasm,wasm}` |
| **5. IOMMU Passthrough `virtio-net` -> L2 Alpine (`L1` unbinds `00:03.0`, keeps `00:02.0`)** | `boot_airlock_linux_passthrough_net_{cwasm,wasm}` | `boot_airlock_linux_passthrough_net_chv_{cwasm,wasm}` |
| **6. All-PCI Passthrough (`00:02.0` + `00:03.0`) -> L2 Alpine (`initramfs`-only L1, 0 L1 PCI devs)** | `boot_airlock_linux_passthrough_all_alpine_{cwasm,wasm}` | `boot_airlock_linux_passthrough_all_alpine_chv_{cwasm,wasm}` |
| **7. All-PCI Passthrough (`00:02.0` + `00:03.0`) -> L2 Motor OS (`initramfs`-only L1, 0 L1 PCI devs)** | `boot_airlock_linux_passthrough_all_motor_os_{cwasm,wasm}` | `boot_airlock_linux_passthrough_all_motor_os_chv_{cwasm,wasm}` |

*(Notice how cleanly networking works across all topologies: for emulated L2 NICs
in Scenarios 2 & 4, L1 Linux creates a standard kernel TAP interface `tap0` and L0
SSHes into L2 via `ProxyCommand` through L1's `sshd`; in Scenarios 5, 6, & 7, L0
SSHes **directly** into L2 over `puff-tap` (`192.168.8.2:22`) or `moto-tap`
(`192.168.4.2:2222`) with zero L1 network stack involvement!)*

---

### 5.3 Interactive Launcher Scripts (`vm_scripts/`)

Following the exact `--vmm wasm|chv` and `--cwasm|--wasm` conventions of our
Motor OS nested scripts, we add:

1. **`vm_scripts/run-airlock-linux-motor-os.sh [--vmm wasm|chv] [--cwasm|--wasm] [--passthrough-net | --passthrough-all] [--with-kvm-loaded]`**
   - Default / `--passthrough-net`: Boots L0 (`wasm-vmm` or `cloud-hypervisor-static`
     with `virtio-iommu`) -> disk-backed L1 Alpine Linux -> `insmod airlock.ko` ->
     boots **full Motor OS** in L2 (with an L1 TAP device or with `00:03.0` passed
     through).
   - `--passthrough-all`: Boots **diskless `initramfs`-only L1 Linux** with zero
     L1-owned PCI endpoints (`pci-stub.ids=1af4:1042,1af4:1041`), loads
     `airlock.ko`, and passes **all** PCI devices (`00:02.0` `motor-os.raw`
     `virtio-blk` + `00:03.0` `moto-tap` `virtio-net`) straight through to L2
     Motor OS (reachable directly via `./vm_scripts/ssh-into-motor-os.sh`).
2. **`vm_scripts/run-airlock-linux-alpine.sh [--vmm wasm|chv] [--cwasm|--wasm] [--initrd | --passthrough-net | --passthrough-all] [--with-kvm-loaded]`**
   - Default / `--initrd` / `--passthrough-net`: Boots L0 (`wasm-vmm` or
     `cloud-hypervisor-static` with `virtio-iommu`) -> disk-backed L1 Alpine
     Linux -> `insmod airlock.ko` -> boots **Alpine Linux** in L2 (`initramfs`,
     emulated disk+TAP, or `00:03.0` `virtio-net` passthrough).
   - `--passthrough-all`: Boots **diskless `initramfs`-only L1 Linux** with zero
     L1-owned PCI endpoints, loads `airlock.ko`, and passes **all** PCI devices
     (`00:02.0` `alpine.raw` `virtio-blk` + `00:03.0` `puff-tap` `virtio-net`)
     straight through to L2 Alpine Linux (reachable directly via
     `./vm_scripts/ssh-into-alpine.sh`), plus companion SSH helper
     `vm_scripts/ssh-into-airlock-l1.sh` for disk-backed L1 modes.

---

## 6. Comparison Across All Three `vmm-core-host` Backends

| Layer / Primitive | Linux Ring-3 KVM (`vmm-core-host`) | Motor OS Ring 0 (`tests/kernel/src/vmm/`) | Linux Ring 0 `airlock.ko` (`vmm-core-kmod/`) |
| :--- | :--- | :--- | :--- |
| **`vmm-core` Wasm source** | `vmm-core.wasm` (byte-identical) | `vmm-core.wasm` (byte-identical) | `vmm-core.wasm` (byte-identical) |
| **Loaded artifact** | `vmm-core.{cwasm,wasm}` | `vmm-core-motor.cwasm` | **Exact same** `vmm-core-motor.cwasm` |
| **Ring-3 I/O host** | `vmm-io-host` (`LinuxIoHost`) | `motor-io-host` (`MotorIoHost`) | **Same** `vmm-io-host --airlock` (`LinuxIoHost`) |
| **Ring-3 <-> Ring-0 IPC** | `memfd` + `eventfd` (to child proc) | `SysMem` + `SysObj` / `SysCpu` | `memfd` (`pin_user_pages_fast`) + `eventfd_ctx` + `/dev/airlock` |
| **World switch** | `ioctl(KVM_RUN)` | Ring-0 SVM `VMRUN` | Ring-0 SVM `VMRUN` (KVM-independent, per-slice `EFER.SVME`/`HSAVE_PA`) |
| **Stage-2 MMU** | `KVM_SET_USER_MEMORY_REGION` | 4 KiB NPT (`stage2.rs`) | 4 KiB / 2 MiB NPT (`stage2.rs` over `alloc_page`) |
| **LAPIC & timers** | KVM split irqchip | `VcpuLapic` + TSC deadline | `VcpuLapic` + Linux `hrtimer` |
| **Fast `QueueNotify`** | `KVM_IOEVENTFD` | Ring-0 `DoorbellTable` | Ring-0 `DoorbellTable` -> `eventfd_signal(c2i)` (0 Wasm calls) |
| **PCI passthrough + IOMMU** | *(future VFIO)* | `VirtioIommuDriver` + IDT `80..111` | `iommu_paging_domain_alloc` (`virtio-iommu` / AMD-Vi) + `pci_alloc_irq_vectors` |

---

## 7. Proposed Phased Implementation Plan

1. **Sub-step `(l.1)` — L1 Kernel Build Pipeline & Out-of-Tree `airlock.ko` Skeleton**:
   - Create `vmm-core-kmod/` (`Makefile`, `Kbuild`, `c/airlock_shim.c`,
     `c/airlock_kapi.h`, `rust/Cargo.toml`, `rust/src/lib.rs`, `kapi.rs`) and the
     incremental out-of-tree `../linux-stable` L1 `bzImage` builder
     (`target/linux-kbuild`, leaving `../linux-stable` untouched).
   - Verify `airlock.ko` compiles cleanly with zero `%xmm`/`%ymm`/`%zmm`
     instructions, passes `objtool` + `modpost`, loads (`insmod airlock.ko`) and
     unloads (`rmmod airlock`) cleanly inside L1 Linux under both `wasm-vmm` and
     `cloud-hypervisor-static` (both with `kvm` unloaded and with `kvm` +
     `kvm-amd` loaded), and exposes `/dev/airlock`.

2. **Sub-step `(l.2)` — Ring-0 Wasmtime, SVM World-Switch, Stage-2 NPT, & Nested `test-guest` Smoke**:
   - Port/share `wasm_runtime.rs` (`LinuxCodeMemory` `vmap` + `PAGE_KERNEL_ROX` +
     IBT guard, loading `vmm-core-motor.cwasm`), `verify_no_fp.rs`, `host_impl.rs`,
     `arch/svm.rs` + `c/svm_enter.S` (per-slice `EFER.SVME` + `MSR_VM_HSAVE_PA`
     KVM-coexistence protocol), `stage2.rs`, `lapic.rs` (`hrtimer`), `pvclock.rs`,
     `doorbell.rs`, and `vcpu_thread.rs`.
   - Wire `--airlock` into `vmm-io-host` (`AIRLOCK_IOC_CREATE_VM`).
   - Add `boot_airlock_linux_test_guest_{cwasm,wasm}` and
     `boot_airlock_linux_test_guest_chv` in `tests/tests/boot_vms.rs`, verifying
     both `!kvm` and concurrent `kvm-amd`-loaded operation.

3. **Sub-step `(l.3)` — Nested Full Motor OS on `airlock.ko` (`wasm-vmm` & `chv`)**:
   - Stage L2 Motor OS (`kloader`, `initrd`, `motor-os.raw`, TAP networking) inside
     L1 Linux, verify SMP Motor OS boot, `russhd` SSH login, and clean `L2 -> L1 -> L0`
     teardown.
   - Add `boot_airlock_linux_motor_os_{cwasm,wasm}`,
     `boot_airlock_linux_motor_os_chv_{cwasm,wasm}`, and
     `vm_scripts/run-airlock-linux-motor-os.sh [--vmm wasm|chv]`.

4. **Sub-step `(l.4)` — Nested Alpine Linux (`initramfs` & Full Disk+SSH) on `airlock.ko` (`wasm-vmm` & `chv`)**:
   - Verify L2 Linux `bzImage + initramfs.cpio.gz` and full L2 Alpine Linux
     (`virtio-blk` + L1 TAP `virtio-net` + OpenSSH `sshd`) running on `airlock.ko`.
   - Add `boot_airlock_linux_initrd_{,chv_}{cwasm,wasm}`,
     `boot_airlock_linux_alpine_{,chv_}{cwasm,wasm}`, and
     `vm_scripts/run-airlock-linux-alpine.sh [--vmm wasm|chv]`.

5. **Sub-step `(l.5)` — IOMMU-Isolated `virtio-net` PCI Passthrough (`pci_host.rs`, Disk-Backed L1)**:
   - Implement `LinuxPciHost` (`iommu_group_claim_dma_owner`,
     `iommu_paging_domain_alloc`, `iommu_map`/`unmap`, UC BAR NPT mapping, and
     MSI-X `pci_alloc_irq_vectors` + `request_irq` -> Ring-0 `inject_msi`) backed
     by L1 Linux's `virtio-iommu` driver.
   - Add `boot_airlock_linux_passthrough_net_{,chv_}{cwasm,wasm}` and wire
     `--passthrough-net` into `run-airlock-linux-{motor-os,alpine}.sh`.

6. **Sub-step `(l.6)` — All-PCI Passthrough (`initramfs`-Only L1 Passing `00:02.0` + `00:03.0` to L2 Alpine & L2 Motor OS)**:
   - Build the diskless `initramfs`-only L1 packager (`pci-stub` binding of all
     guest PCI devices, zero emulated VirtIO devices, zero L1 Ring-3 VM-exits).
   - Add `boot_airlock_linux_passthrough_all_alpine_{,chv_}{cwasm,wasm}` and
     `boot_airlock_linux_passthrough_all_motor_os_{,chv_}{cwasm,wasm}` in
     `tests/tests/boot_vms.rs`, and wire `--passthrough-all` into both
     `vm_scripts/run-airlock-linux-alpine.sh` and
     `vm_scripts/run-airlock-linux-motor-os.sh`.
