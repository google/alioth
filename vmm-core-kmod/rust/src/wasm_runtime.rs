// SPDX-License-Identifier: GPL-2.0
// `#![no_std]` Linux Ring-0 Wasmtime runtime adapter (`W^X` `CustomCodeMemory` over `vmap` +
// `PAGE_KERNEL_ROX`, page-aligned `MemoryCreator`, CET IBT guard, and worker `Store`s).
#![allow(clippy::missing_safety_doc)]

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::{align_of, size_of};
use core::ptr::{null_mut, NonNull};

use vmm_core::host::abi::VcpuCommPage;
use vmm_core::host::{HvError, VmmCoreBridge, VmmHostCore};
use wasmtime::{
    Config, CustomCodeMemory, Engine, ExternType, Instance, LinearMemory, Linker, MemoryCreator,
    MemoryRequest, MemoryType, Module, SharedMemory, Store, TypedFunc, Val,
};

use crate::host_impl::{
    register_bridge_imports, register_core_imports, CoreBridgeWasmCtx, CoreHvWasmCtx,
};
use crate::kapi::{
    airlock_kapi_exec_alloc_from_user, airlock_kapi_exec_free, airlock_kapi_exec_set_rx,
    AirlockExecBuf, SpinLock, WasmCallGuard, PAGE_SIZE_4K,
};

// ============================================================================
// Page-Aligned Immovable `MemoryCreator` for Ring-0 `SharedMemory`
// ============================================================================

struct LinuxLinearMemory {
    base_ptr: NonNull<u8>,
    layout: Layout,
    byte_len: usize,
}

unsafe impl Send for LinuxLinearMemory {}
unsafe impl Sync for LinuxLinearMemory {}

impl Drop for LinuxLinearMemory {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.base_ptr.as_ptr(), self.layout);
        }
    }
}

unsafe impl LinearMemory for LinuxLinearMemory {
    fn byte_size(&self) -> usize {
        self.byte_len
    }

    fn byte_capacity(&self) -> usize {
        self.layout.size()
    }

    fn grow_to(&mut self, new_size: usize) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            new_size <= self.layout.size(),
            "LinuxLinearMemory growth beyond reserved capacity ({new_size:#x} > {:#x})",
            self.layout.size(),
        );
        self.byte_len = new_size;
        Ok(())
    }

    fn as_ptr(&self) -> *mut u8 {
        self.base_ptr.as_ptr()
    }
}

struct LinuxMemoryCreator {
    growth_headroom: usize,
}

unsafe impl MemoryCreator for LinuxMemoryCreator {
    fn new_memory(&self, request: &MemoryRequest<'_>) -> wasmtime::Result<Box<dyn LinearMemory>> {
        wasmtime::ensure!(
            request.guard_size_in_bytes() == 0 && request.reserved_size_in_bytes() == 0,
            "LinuxMemoryCreator requires zero guard/reservation sizes",
        );
        let minimum = request.minimum();
        let wanted = minimum
            .checked_add(self.growth_headroom)
            .ok_or_else(|| wasmtime::format_err!("linear memory allocation overflow"))?;
        let capped = request.maximum().map_or(wanted, |max| wanted.min(max));
        let page = PAGE_SIZE_4K as usize;
        let raw_cap = capped.max(minimum).max(page);
        let aligned_cap = raw_cap
            .checked_add(page - 1)
            .ok_or_else(|| wasmtime::format_err!("linear memory page alignment overflow"))?
            & !(page - 1);
        let layout = Layout::from_size_align(aligned_cap, page)
            .map_err(|_| wasmtime::format_err!("invalid linear memory layout"))?;
        let base_ptr = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| wasmtime::OutOfMemory::new(layout.size()))?;
        Ok(Box::new(LinuxLinearMemory {
            base_ptr,
            layout,
            byte_len: minimum,
        }))
    }
}

// ============================================================================
// Strict `W^X` `CustomCodeMemory` Backed by `vmap(PAGE_KERNEL_RO)` + `PAGE_KERNEL_ROX`
// ============================================================================

struct LinuxCodeMemory {
    raw_buf: *mut AirlockExecBuf,
    base_va: usize,
}

unsafe impl Send for LinuxCodeMemory {}
unsafe impl Sync for LinuxCodeMemory {}

impl CustomCodeMemory for LinuxCodeMemory {
    fn required_alignment(&self) -> usize {
        PAGE_SIZE_4K as usize
    }

    fn publish_executable(&self, ptr: *const u8, len: usize) -> wasmtime::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let off = (ptr as usize)
            .checked_sub(self.base_va)
            .ok_or_else(|| wasmtime::format_err!("publish_executable ptr below base"))?;
        let rc = unsafe { airlock_kapi_exec_set_rx(self.raw_buf, off, len, true) };
        wasmtime::ensure!(rc == 0, "airlock_kapi_exec_set_rx(true) failed: {rc}");
        Ok(())
    }

    fn unpublish_executable(&self, ptr: *const u8, len: usize) -> wasmtime::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let off = (ptr as usize)
            .checked_sub(self.base_va)
            .ok_or_else(|| wasmtime::format_err!("unpublish_executable ptr below base"))?;
        let rc = unsafe { airlock_kapi_exec_set_rx(self.raw_buf, off, len, false) };
        wasmtime::ensure!(rc == 0, "airlock_kapi_exec_set_rx(false) failed: {rc}");
        Ok(())
    }
}

/// Owns the `vmap`'d private 4 KiB pages containing the validated `.cwasm` image.
/// Must be dropped strictly after `Module` so `CodeMemory::drop` unpublishes `.text` first.
pub struct CwasmCodeBacking {
    raw: *mut AirlockExecBuf,
    ro_ptr: *mut u8,
    byte_len: usize,
}

unsafe impl Send for CwasmCodeBacking {}
unsafe impl Sync for CwasmCodeBacking {}

impl CwasmCodeBacking {
    pub fn from_user(uaddr: u64, byte_len: usize) -> Result<Self, String> {
        if byte_len == 0 {
            return Err("empty .cwasm image".into());
        }
        let mut raw = null_mut();
        let mut ro_ptr = null_mut();
        let rc = unsafe {
            airlock_kapi_exec_alloc_from_user(
                uaddr as usize as *const u8,
                byte_len,
                &mut raw,
                &mut ro_ptr,
            )
        };
        if rc < 0 || raw.is_null() || ro_ptr.is_null() {
            return Err(format!("airlock_kapi_exec_alloc_from_user failed: {rc}"));
        }
        Ok(Self {
            raw,
            ro_ptr,
            byte_len,
        })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ro_ptr as *const u8, self.byte_len) }
    }

    pub fn non_null_slice(&self) -> NonNull<[u8]> {
        let ptr = core::ptr::slice_from_raw_parts_mut(self.ro_ptr, self.byte_len);
        NonNull::new(ptr).unwrap()
    }
}

impl Drop for CwasmCodeBacking {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            unsafe { airlock_kapi_exec_free(self.raw) };
            self.raw = null_mut();
        }
    }
}

pub struct LinuxWasmState<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    pub hv: CoreHvWasmCtx<H>,
    pub bridge: CoreBridgeWasmCtx<B>,
}

pub struct VcpuWasmWorker<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    pub store: Store<LinuxWasmState<H, B>>,
    pub _instance: Instance,
    pub on_vcpu_exit: TypedFunc<u32, i32>,
    pub comm_offset: usize,
}

pub struct RxWasmWorker<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    pub store: Store<LinuxWasmState<H, B>>,
    pub _instance: Instance,
    pub on_bridge_rx: TypedFunc<(), i32>,
}

/// Shared Wasmtime engine, module, linear memory, and bridge-RX worker for one VM.
/// Field order is load-bearing: `_code_backing` drops LAST after `module` unpublishes `.text`.
pub struct LinuxWasmRuntime<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    pub rx_worker: SpinLock<RxWasmWorker<H, B>>,
    pub shared_memory: SharedMemory,
    pub num_cpus: u32,
    pub module: Module,
    pub engine: Engine,
    _code_backing: CwasmCodeBacking,
}

fn bind_worker_stack<T>(
    store: &mut Store<T>,
    instance: &Instance,
    stack_top: u32,
) -> Result<(), String> {
    if stack_top == 0 || (stack_top & 15) != 0 {
        return Err(format!("invalid Wasm worker stack_top {stack_top:#x}"));
    }
    let sp = instance
        .get_global(&mut *store, "__stack_pointer")
        .ok_or_else(|| "missing __stack_pointer global in vmm-core".to_string())?;
    sp.set(&mut *store, Val::I32(stack_top as i32))
        .map_err(|e| format!("failed setting __stack_pointer: {e}"))
}

fn detect_x86_host_feature(feature: &str) -> Option<bool> {
    let l1 = core::arch::x86_64::__cpuid(1);
    let l7 = if core::arch::x86_64::__cpuid(0).eax >= 7 {
        core::arch::x86_64::__cpuid_count(7, 0)
    } else {
        core::arch::x86_64::CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    };
    let ext1 = if core::arch::x86_64::__cpuid(0x8000_0000).eax >= 0x8000_0001 {
        core::arch::x86_64::__cpuid(0x8000_0001)
    } else {
        core::arch::x86_64::CpuidResult {
            eax: 0,
            ebx: 0,
            ecx: 0,
            edx: 0,
        }
    };
    match feature {
        "sse3" => Some((l1.ecx & (1 << 0)) != 0),
        "ssse3" => Some((l1.ecx & (1 << 9)) != 0),
        "fma" => Some((l1.ecx & (1 << 12)) != 0),
        "cmpxchg16b" => Some((l1.ecx & (1 << 13)) != 0),
        "sse4.1" => Some((l1.ecx & (1 << 19)) != 0),
        "sse4.2" => Some((l1.ecx & (1 << 20)) != 0),
        "popcnt" => Some((l1.ecx & (1 << 23)) != 0),
        "avx" => Some((l1.ecx & (1 << 28)) != 0),
        "bmi1" => Some((l7.ebx & (1 << 3)) != 0),
        "avx2" => Some((l7.ebx & (1 << 5)) != 0),
        "bmi2" => Some((l7.ebx & (1 << 8)) != 0),
        "avx512f" => Some((l7.ebx & (1 << 16)) != 0),
        "avx512dq" => Some((l7.ebx & (1 << 17)) != 0),
        "avx512vl" => Some((l7.ebx & (1 << 31)) != 0),
        "avx512vbmi" => Some((l7.ecx & (1 << 1)) != 0),
        "avx512vnni" => Some((l7.ecx & (1 << 11)) != 0),
        "avx512bitalg" => Some((l7.ecx & (1 << 12)) != 0),
        "lzcnt" => Some((ext1.ecx & (1 << 5)) != 0),
        _ => Some(false),
    }
}

pub type InstantiatedWasmVm<H, B> = (Arc<LinuxWasmRuntime<H, B>>, Vec<VcpuWasmWorker<H, B>>);

impl<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> LinuxWasmRuntime<H, B> {
    pub fn instantiate(
        code_backing: CwasmCodeBacking,
        host: Arc<H>,
        bridge: Arc<B>,
    ) -> Result<InstantiatedWasmVm<H, B>, String> {
        crate::verify_no_fp::validate_cwasm_no_fp(code_backing.as_slice())?;

        let mut config = Config::new();
        config.wasm_threads(true);
        config.shared_memory(true);
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        config.signals_based_traps(false);
        config.memory_init_cow(false);
        config.memory_guard_size(0);
        config.memory_reservation(0);
        config.memory_reservation_for_growth(8 << 20);
        config.with_host_memory(Arc::new(LinuxMemoryCreator {
            growth_headroom: 8 << 20,
        }));
        config.with_custom_code_memory(Some(Arc::new(LinuxCodeMemory {
            raw_buf: code_backing.raw,
            base_va: code_backing.ro_ptr as usize,
        })));
        unsafe {
            config.x86_float_abi_ok(true);
            config.detect_host_feature(detect_x86_host_feature);
        }

        let engine = Engine::new(&config).map_err(|e| format!("Engine::new failed: {e}"))?;
        let module = unsafe { Module::deserialize_raw(&engine, code_backing.non_null_slice()) }
            .map_err(|e| format!("Module::deserialize_raw failed: {e}"))?;

        let memory_ty = match module.imports().find_map(|imp| {
            if imp.module() == "env" && imp.name() == "memory" {
                if let ExternType::Memory(ty) = imp.ty() {
                    return Some(ty);
                }
            }
            None
        }) {
            Some(ty) => ty,
            None => MemoryType::shared(17, 16384)
                .map_err(|e| format!("MemoryType::shared failed: {e}"))?,
        };

        let shared_memory = SharedMemory::new(&engine, memory_ty)
            .map_err(|e| format!("SharedMemory::new failed: {e}"))?;

        let mut init_store = Store::new(
            &engine,
            LinuxWasmState {
                hv: CoreHvWasmCtx::new(host.clone(), shared_memory.clone()),
                bridge: CoreBridgeWasmCtx::new(bridge.clone(), shared_memory.clone()),
            },
        );

        let mut linker = Linker::<LinuxWasmState<H, B>>::new(&engine);
        linker
            .define(&init_store, "env", "memory", shared_memory.clone())
            .map_err(|e| format!("linker.define memory failed: {e}"))?;
        register_core_imports(&mut linker, |st| &mut st.hv)
            .map_err(|e| format!("register_core_imports failed: {e}"))?;
        register_bridge_imports(&mut linker, |st| &mut st.bridge)
            .map_err(|e| format!("register_bridge_imports failed: {e}"))?;

        let init_instance = {
            let _ibt = WasmCallGuard::enter();
            linker
                .instantiate(&mut init_store, &module)
                .map_err(|e| format!("init instantiate failed: {e}"))?
        };
        let vmm_init = init_instance
            .get_typed_func::<(), i32>(&mut init_store, "vmm_init")
            .map_err(|e| format!("missing vmm_init: {e}"))?;
        let vmm_num_cpus = init_instance
            .get_typed_func::<(), u32>(&mut init_store, "vmm_num_cpus")
            .map_err(|e| format!("missing vmm_num_cpus: {e}"))?;
        let vmm_stack_top = init_instance
            .get_typed_func::<u32, u32>(&mut init_store, "vmm_stack_top")
            .map_err(|e| format!("missing vmm_stack_top: {e}"))?;

        let init_rc = {
            let _ibt = WasmCallGuard::enter();
            vmm_init
                .call(&mut init_store, ())
                .map_err(|e| format!("vmm_init trapped: {e}"))?
        };
        if init_rc < 0 {
            return Err(format!(
                "vmm_init returned {:?}",
                HvError::from_code(init_rc)
            ));
        }
        let comm_base = init_rc as usize;
        let num_cpus = {
            let _ibt = WasmCallGuard::enter();
            vmm_num_cpus
                .call(&mut init_store, ())
                .map_err(|e| format!("vmm_num_cpus trapped: {e}"))?
        };
        if num_cpus == 0 || num_cpus > 64 {
            return Err(format!("invalid vmm_num_cpus={num_cpus}"));
        }

        let comm_total = (num_cpus as usize)
            .checked_mul(size_of::<VcpuCommPage>())
            .ok_or_else(|| "VcpuCommPage size overflow".to_string())?;
        if comm_base
            .checked_add(comm_total)
            .is_none_or(|end| end > shared_memory.data().len())
        {
            return Err(format!(
                "comm_base {comm_base:#x} out of linear memory bounds"
            ));
        }
        let host_comm_addr = unsafe { shared_memory.data().as_ptr().add(comm_base) as usize };
        if !host_comm_addr.is_multiple_of(align_of::<VcpuCommPage>()) {
            return Err(format!(
                "unaligned VcpuCommPage host addr {host_comm_addr:#x}"
            ));
        }

        let mut vcpu_workers = Vec::with_capacity(num_cpus as usize);
        for vcpu_id in 0..num_cpus {
            let stack_top = {
                let _ibt = WasmCallGuard::enter();
                vmm_stack_top
                    .call(&mut init_store, vcpu_id)
                    .map_err(|e| format!("vmm_stack_top({vcpu_id}) trapped: {e}"))?
            };
            let mut store = Store::new(
                &engine,
                LinuxWasmState {
                    hv: CoreHvWasmCtx::new(host.clone(), shared_memory.clone()),
                    bridge: CoreBridgeWasmCtx::new(bridge.clone(), shared_memory.clone()),
                },
            );
            let instance = {
                let _ibt = WasmCallGuard::enter();
                linker
                    .instantiate(&mut store, &module)
                    .map_err(|e| format!("vcpu {vcpu_id} instantiate failed: {e}"))?
            };
            bind_worker_stack(&mut store, &instance, stack_top)?;
            let bind_fn = instance
                .get_typed_func::<(u32, u32), ()>(&mut store, "vmm_bind_vcpu")
                .map_err(|e| format!("missing vmm_bind_vcpu: {e}"))?;
            {
                let _ibt = WasmCallGuard::enter();
                bind_fn
                    .call(&mut store, (vcpu_id, stack_top))
                    .map_err(|e| format!("vmm_bind_vcpu({vcpu_id}) trapped: {e}"))?;
            }
            let on_vcpu_exit = instance
                .get_typed_func::<u32, i32>(&mut store, "vmm_on_vcpu_exit")
                .map_err(|e| format!("missing vmm_on_vcpu_exit: {e}"))?;

            vcpu_workers.push(VcpuWasmWorker {
                store,
                _instance: instance,
                on_vcpu_exit,
                comm_offset: comm_base + (vcpu_id as usize) * size_of::<VcpuCommPage>(),
            });
        }

        let rx_stack_top = {
            let _ibt = WasmCallGuard::enter();
            vmm_stack_top
                .call(&mut init_store, num_cpus)
                .map_err(|e| format!("vmm_stack_top(rx) trapped: {e}"))?
        };
        let mut rx_store = Store::new(
            &engine,
            LinuxWasmState {
                hv: CoreHvWasmCtx::new(host, shared_memory.clone()),
                bridge: CoreBridgeWasmCtx::new(bridge, shared_memory.clone()),
            },
        );
        let rx_instance = {
            let _ibt = WasmCallGuard::enter();
            linker
                .instantiate(&mut rx_store, &module)
                .map_err(|e| format!("rx instantiate failed: {e}"))?
        };
        bind_worker_stack(&mut rx_store, &rx_instance, rx_stack_top)?;
        let on_bridge_rx = rx_instance
            .get_typed_func::<(), i32>(&mut rx_store, "vmm_on_bridge_rx")
            .map_err(|e| format!("missing vmm_on_bridge_rx: {e}"))?;

        drop(init_store);

        let rt = Arc::new(Self {
            rx_worker: SpinLock::new(RxWasmWorker {
                store: rx_store,
                _instance: rx_instance,
                on_bridge_rx,
            }),
            shared_memory,
            num_cpus,
            module,
            engine,
            _code_backing: code_backing,
        });

        Ok((rt, vcpu_workers))
    }
}
