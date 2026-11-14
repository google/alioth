// `#![no_std]` Ring-0 Wasmtime runtime adapter (`W^X` `CustomCodeMemory`, page-aligned
// `MemoryCreator`, per-CPU TLS, allocation-free custom sync primitives, and worker `Store`s).
#![allow(clippy::missing_safety_doc)]

use alloc::alloc::{alloc_zeroed, dealloc, Layout};
use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicUsize, Ordering};

use vmm_core::host::abi::VcpuCommPage;
use vmm_core::host::{HvError, VmmCoreBridge, VmmHostCore};
use wasmtime::{
    Config, CustomCodeMemory, Engine, ExternType, Instance, LinearMemory, Linker, MemoryCreator,
    MemoryRequest, MemoryType, Module, SharedMemory, Store, TypedFunc, Val,
};

use crate::config::MAX_CPUS;
use crate::mm::user::PinnedUserPage;
use crate::mm::virt::{vmem_allocate_pages, vmem_free, vmem_set_kernel_wx, VmemKind};
use crate::mm::{align_up, AllocationClass, MemorySegment, PAGE_SIZE_SMALL, PAGE_SIZE_SMALL_LOG2};

use super::host_impl::{
    register_bridge_imports, register_core_imports, CoreBridgeWasmCtx, CoreHvWasmCtx,
};

// ============================================================================
// Wasmtime `no_std` + `custom-sync-primitives` Platform C-ABI Hooks
// ============================================================================

static WASMTIME_TLS: [[AtomicUsize; 2]; MAX_CPUS as usize] =
    [const { [AtomicUsize::new(0), AtomicUsize::new(0)] }; MAX_CPUS as usize];

#[no_mangle]
pub unsafe extern "C" fn wasmtime_tls_get(slot: usize) -> *mut u8 {
    let cpu = crate::arch::current_cpu() as usize;
    if cpu < WASMTIME_TLS.len() && slot < 2 {
        WASMTIME_TLS[cpu][slot].load(Ordering::Relaxed) as *mut u8
    } else {
        core::ptr::null_mut()
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_tls_set(slot: usize, ptr: *mut u8) {
    let cpu = crate::arch::current_cpu() as usize;
    if cpu < WASMTIME_TLS.len() && slot < 2 {
        WASMTIME_TLS[cpu][slot].store(ptr as usize, Ordering::Relaxed);
    }
}

const RWLOCK_WRITER_BIT: usize = 1usize << (usize::BITS - 1);

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_lock_acquire(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    while atom
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_lock_release(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    atom.store(0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_lock_free(_lock: *mut usize) {}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_read(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    loop {
        let cur = atom.load(Ordering::Relaxed);
        if (cur & RWLOCK_WRITER_BIT) == 0
            && atom
                .compare_exchange_weak(cur, cur + 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        {
            break;
        }
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_read_release(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    atom.fetch_sub(1, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_write(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    while atom
        .compare_exchange_weak(0, RWLOCK_WRITER_BIT, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_write_release(lock: *mut usize) {
    let atom = unsafe { &*(lock as *const AtomicUsize) };
    atom.store(0, Ordering::Release);
}

#[no_mangle]
pub unsafe extern "C" fn wasmtime_sync_rwlock_free(_lock: *mut usize) {}

// ============================================================================
// Page-Aligned Immovable `MemoryCreator` for Ring-0 `SharedMemory`
// ============================================================================

struct MotorLinearMemory {
    base_ptr: NonNull<u8>,
    layout: Layout,
    byte_len: usize,
}

unsafe impl Send for MotorLinearMemory {}
unsafe impl Sync for MotorLinearMemory {}

impl Drop for MotorLinearMemory {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.base_ptr.as_ptr(), self.layout);
        }
    }
}

unsafe impl LinearMemory for MotorLinearMemory {
    fn byte_size(&self) -> usize {
        self.byte_len
    }

    fn byte_capacity(&self) -> usize {
        self.layout.size()
    }

    fn grow_to(&mut self, new_size: usize) -> wasmtime::Result<()> {
        wasmtime::ensure!(
            new_size <= self.layout.size(),
            "MotorLinearMemory growth beyond reserved capacity ({new_size:#x} > {:#x})",
            self.layout.size(),
        );
        self.byte_len = new_size;
        Ok(())
    }

    fn as_ptr(&self) -> *mut u8 {
        self.base_ptr.as_ptr()
    }
}

struct MotorMemoryCreator {
    growth_headroom: usize,
}

unsafe impl MemoryCreator for MotorMemoryCreator {
    fn new_memory(&self, request: &MemoryRequest<'_>) -> wasmtime::Result<Box<dyn LinearMemory>> {
        wasmtime::ensure!(
            request.guard_size_in_bytes() == 0 && request.reserved_size_in_bytes() == 0,
            "MotorMemoryCreator requires zero guard/reservation sizes",
        );
        let minimum = request.minimum();
        let wanted = minimum
            .checked_add(self.growth_headroom)
            .ok_or_else(|| wasmtime::format_err!("linear memory allocation overflow"))?;
        let capped = request.maximum().map_or(wanted, |max| wanted.min(max));
        let page = PAGE_SIZE_SMALL as usize;
        let raw_cap = capped.max(minimum).max(page);
        let aligned_cap = raw_cap
            .checked_add(page - 1)
            .ok_or_else(|| wasmtime::format_err!("linear memory page alignment overflow"))?
            & !(page - 1);
        let layout = Layout::from_size_align(aligned_cap, page)
            .map_err(|_| wasmtime::format_err!("invalid linear memory layout"))?;
        let base_ptr = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| wasmtime::OutOfMemory::new(layout.size()))?;
        Ok(Box::new(MotorLinearMemory {
            base_ptr,
            layout,
            byte_len: minimum,
        }))
    }
}

// ============================================================================
// Strict `W^X` `CustomCodeMemory` Backed by Motor OS `KernelStatic`
// ============================================================================

struct MotorCodeMemory;

impl CustomCodeMemory for MotorCodeMemory {
    fn required_alignment(&self) -> usize {
        PAGE_SIZE_SMALL as usize
    }

    fn publish_executable(&self, ptr: *const u8, len: usize) -> wasmtime::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let start = ptr as usize as u64;
        let aligned_len = align_up(len as u64, PAGE_SIZE_SMALL);
        let num_pages = aligned_len >> PAGE_SIZE_SMALL_LOG2;
        vmem_set_kernel_wx(start, num_pages, false, true);
        Ok(())
    }

    fn unpublish_executable(&self, ptr: *const u8, len: usize) -> wasmtime::Result<()> {
        if len == 0 {
            return Ok(());
        }
        let start = ptr as usize as u64;
        let aligned_len = align_up(len as u64, PAGE_SIZE_SMALL);
        let num_pages = aligned_len >> PAGE_SIZE_SMALL_LOG2;
        vmem_set_kernel_wx(start, num_pages, true, false);
        Ok(())
    }
}

/// Owns the `KernelStatic` virtual allocation containing the validated `.cwasm` image.
/// Must be dropped strictly after `Module` so `CodeMemory::drop` unpublishes `.text` first.
pub struct CwasmCodeBacking {
    seg: MemorySegment,
    byte_len: usize,
}

impl CwasmCodeBacking {
    pub fn from_pinned_pages(pages: &[PinnedUserPage], byte_len: usize) -> Result<Self, String> {
        if byte_len == 0 {
            return Err("empty .cwasm image".into());
        }
        let aligned_bytes = align_up(byte_len as u64, PAGE_SIZE_SMALL);
        let num_pages = aligned_bytes >> PAGE_SIZE_SMALL_LOG2;
        if (pages.len() as u64) < num_pages {
            return Err("insufficient pinned .cwasm pages".into());
        }
        let seg = vmem_allocate_pages(VmemKind::KernelStatic, num_pages, AllocationClass::Kernel)
            .map_err(|_| "OOM allocating KernelStatic for .cwasm".to_string())?;

        let mut remaining = byte_len;
        for (idx, page) in pages.iter().enumerate() {
            if remaining == 0 {
                break;
            }
            let copy_len = remaining.min(PAGE_SIZE_SMALL as usize);
            let dst = (seg.start + ((idx as u64) << PAGE_SIZE_SMALL_LOG2)) as *mut u8;
            let src = page.kernel_addr() as *const u8;
            unsafe {
                core::ptr::copy_nonoverlapping(src, dst, copy_len);
            }
            remaining -= copy_len;
        }

        // Freeze all pages to RO+NX initially; `CodeMemory::publish` upgrades `.text` to R+X.
        vmem_set_kernel_wx(seg.start, num_pages, false, false);

        Ok(Self { seg, byte_len })
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.seg.start as *const u8, self.byte_len) }
    }

    pub fn non_null_slice(&self) -> NonNull<[u8]> {
        let ptr = core::ptr::slice_from_raw_parts_mut(self.seg.start as *mut u8, self.byte_len);
        NonNull::new(ptr).unwrap()
    }
}

impl Drop for CwasmCodeBacking {
    fn drop(&mut self) {
        let num_pages = self.seg.size >> PAGE_SIZE_SMALL_LOG2;
        // Restore RW+NX across all pages before returning frames to the kernel allocator.
        vmem_set_kernel_wx(self.seg.start, num_pages, true, false);
        vmem_free(self.seg.start, VmemKind::KernelStatic);
    }
}

pub struct MotorWasmState<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    pub hv: CoreHvWasmCtx<H>,
    pub bridge: CoreBridgeWasmCtx<B>,
}

pub struct VcpuWasmWorker<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    pub store: Store<MotorWasmState<H, B>>,
    pub _instance: Instance,
    pub on_vcpu_exit: TypedFunc<u32, i32>,
    pub comm_offset: usize,
}

pub struct RxWasmWorker<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    pub store: Store<MotorWasmState<H, B>>,
    pub _instance: Instance,
    pub on_bridge_rx: TypedFunc<(), i32>,
}

/// Shared Wasmtime engine, module, linear memory, and bridge-RX worker for one VM.
/// Field order is load-bearing: `_code_backing` drops LAST after `module` unpublishes `.text`.
pub struct MotorWasmRuntime<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    pub rx_worker: crate::util::SpinLock<RxWasmWorker<H, B>>,
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

pub type InstantiatedWasmVm<H, B> = (Arc<MotorWasmRuntime<H, B>>, Vec<VcpuWasmWorker<H, B>>);

impl<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> MotorWasmRuntime<H, B> {
    pub fn instantiate(
        code_backing: CwasmCodeBacking,
        host: Arc<H>,
        bridge: Arc<B>,
    ) -> Result<InstantiatedWasmVm<H, B>, String> {
        super::verify_no_fp::validate_cwasm_no_fp(code_backing.as_slice())?;

        let mut config = Config::new();
        config.wasm_threads(true);
        config.shared_memory(true);
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        config.signals_based_traps(false);
        config.memory_init_cow(false);
        config.memory_guard_size(0);
        config.memory_reservation(0);
        // Reserve 8 MiB page-aligned headroom beyond initial linear memory so shared memory fits
        // cleanly in Motor OS's kernel heap without reserving 2 GiB upfront.
        config.memory_reservation_for_growth(8 << 20);
        config.with_host_memory(Arc::new(MotorMemoryCreator {
            growth_headroom: 8 << 20,
        }));
        config.with_custom_code_memory(Some(Arc::new(MotorCodeMemory)));
        // Safety: `validate_cwasm_no_fp` above statically verified that `.text` contains zero
        // floating-point or SIMD instructions/registers, and all host/guest ABI signatures are
        // strictly integer-only, so soft-float `x86_64-unknown-none` has zero float ABI mismatch.
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
            MotorWasmState {
                hv: CoreHvWasmCtx::new(host.clone(), shared_memory.clone()),
                bridge: CoreBridgeWasmCtx::new(bridge.clone(), shared_memory.clone()),
            },
        );

        let mut linker = Linker::<MotorWasmState<H, B>>::new(&engine);
        linker
            .define(&init_store, "env", "memory", shared_memory.clone())
            .map_err(|e| format!("linker.define memory failed: {e}"))?;
        register_core_imports(&mut linker, |st| &mut st.hv)
            .map_err(|e| format!("register_core_imports failed: {e}"))?;
        register_bridge_imports(&mut linker, |st| &mut st.bridge)
            .map_err(|e| format!("register_bridge_imports failed: {e}"))?;

        let init_instance = linker
            .instantiate(&mut init_store, &module)
            .map_err(|e| format!("init instantiate failed: {e}"))?;
        let vmm_init = init_instance
            .get_typed_func::<(), i32>(&mut init_store, "vmm_init")
            .map_err(|e| format!("missing vmm_init: {e}"))?;
        let vmm_num_cpus = init_instance
            .get_typed_func::<(), u32>(&mut init_store, "vmm_num_cpus")
            .map_err(|e| format!("missing vmm_num_cpus: {e}"))?;
        let vmm_stack_top = init_instance
            .get_typed_func::<u32, u32>(&mut init_store, "vmm_stack_top")
            .map_err(|e| format!("missing vmm_stack_top: {e}"))?;

        let init_rc = vmm_init
            .call(&mut init_store, ())
            .map_err(|e| format!("vmm_init trapped: {e}"))?;
        if init_rc < 0 {
            return Err(format!(
                "vmm_init returned {:?}",
                HvError::from_code(init_rc)
            ));
        }
        let comm_base = init_rc as usize;
        let num_cpus = vmm_num_cpus
            .call(&mut init_store, ())
            .map_err(|e| format!("vmm_num_cpus trapped: {e}"))?;
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
            let stack_top = vmm_stack_top
                .call(&mut init_store, vcpu_id)
                .map_err(|e| format!("vmm_stack_top({vcpu_id}) trapped: {e}"))?;
            let mut store = Store::new(
                &engine,
                MotorWasmState {
                    hv: CoreHvWasmCtx::new(host.clone(), shared_memory.clone()),
                    bridge: CoreBridgeWasmCtx::new(bridge.clone(), shared_memory.clone()),
                },
            );
            let instance = linker
                .instantiate(&mut store, &module)
                .map_err(|e| format!("vcpu {vcpu_id} instantiate failed: {e}"))?;
            bind_worker_stack(&mut store, &instance, stack_top)?;
            let bind_fn = instance
                .get_typed_func::<(u32, u32), ()>(&mut store, "vmm_bind_vcpu")
                .map_err(|e| format!("missing vmm_bind_vcpu: {e}"))?;
            bind_fn
                .call(&mut store, (vcpu_id, stack_top))
                .map_err(|e| format!("vmm_bind_vcpu({vcpu_id}) trapped: {e}"))?;
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

        let rx_stack_top = vmm_stack_top
            .call(&mut init_store, num_cpus)
            .map_err(|e| format!("vmm_stack_top(rx) trapped: {e}"))?;
        let mut rx_store = Store::new(
            &engine,
            MotorWasmState {
                hv: CoreHvWasmCtx::new(host, shared_memory.clone()),
                bridge: CoreBridgeWasmCtx::new(bridge, shared_memory.clone()),
            },
        );
        let rx_instance = linker
            .instantiate(&mut rx_store, &module)
            .map_err(|e| format!("rx instantiate failed: {e}"))?;
        bind_worker_stack(&mut rx_store, &rx_instance, rx_stack_top)?;
        let on_bridge_rx = rx_instance
            .get_typed_func::<(), i32>(&mut rx_store, "vmm_on_bridge_rx")
            .map_err(|e| format!("missing vmm_on_bridge_rx: {e}"))?;

        drop(init_store);

        let rt = Arc::new(Self {
            rx_worker: crate::util::SpinLock::new(RxWasmWorker {
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
