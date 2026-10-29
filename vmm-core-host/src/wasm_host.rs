// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::mem::{align_of, size_of};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use vmm_core::host::abi::{
    CoreToIoEntry, IoToCoreEntry, MAX_QUEUES_PER_DEV, MAX_VIRTIO_DEVS, RawCpuid, RawDoorbellSpec,
    RawRegEntry, ShmBootInfo, ShmDeviceMsixRouting, ShmVirtioDeviceSpec, ShmVirtioQueueConfig,
    VcpuCommPage,
};
pub use vmm_core::host::{VmmCoreBridge, VmmHostCore};
use vmm_core::host::{
    HvError, HvResult, IoSpace, MemProt, PayloadKind, RegId, RegVal, VcpuId, VmAction,
};
use wasmtime::{
    Caller, Config, Engine, ExternType, Instance, Linker, MemoryType, Module, SharedMemory, Store,
    Val,
};
use zerocopy::{AsBytes, FromBytes};

/// Host-owned execution loop primitives layered above [`VmmHostCore`].
///
/// Implemented by Ring-3 (`KvmCoreHost`) and Ring-0 (Linux kernel / Motor OS) hosts
/// to drive guest entry and control-plane wakeups outside Wasm.
pub trait VmmHostRunner: VmmHostCore {
    /// Enter guest execution on `vcpu` using `comm` (`entry` + `dirty_regs`) and populate
    /// `comm` (`exit` + `synced_regs`) on VM exit.
    fn enter_guest(&self, vcpu: VcpuId, comm: &mut VcpuCommPage) -> HvResult<()>;

    /// Block the host bridge-RX worker until at least one `IoToCoreEntry` is ready to be
    /// drained by `vmm_on_bridge_rx()`, or return `false` once shutdown has been signaled.
    fn wait_bridge_rx(&self) -> bool;

    /// Wake any thread blocked in [`Self::wait_bridge_rx`] during VM teardown.
    fn wake_bridge_rx(&self);
}

/// Per-Wasm-instance ABI context binding a [`VmmHostCore`] implementation to a Wasmtime store.
pub struct CoreHvWasmCtx<H: VmmHostCore + ?Sized> {
    pub host: Arc<H>,
    pub memory: SharedMemory,
}

impl<H: VmmHostCore + ?Sized> CoreHvWasmCtx<H> {
    pub fn new(host: Arc<H>, memory: SharedMemory) -> Self {
        Self { host, memory }
    }
}

/// Per-Wasm-instance ABI context binding a [`VmmCoreBridge`] implementation to a Wasmtime store.
pub struct CoreBridgeWasmCtx<B: VmmCoreBridge + ?Sized> {
    pub bridge: Arc<B>,
    pub memory: SharedMemory,
}

impl<B: VmmCoreBridge + ?Sized> CoreBridgeWasmCtx<B> {
    pub fn new(bridge: Arc<B>, memory: SharedMemory) -> Self {
        Self { bridge, memory }
    }
}

#[inline]
fn check_bounds(mem: &SharedMemory, ptr: u32, len: usize) -> HvResult<usize> {
    let start = ptr as usize;
    let end = start.checked_add(len).ok_or(HvError::InvalidParam)?;
    if end > mem.data().len() {
        return Err(HvError::InvalidParam);
    }
    Ok(start)
}

#[inline]
fn read_bytes(mem: &SharedMemory, ptr: u32, dst: &mut [u8]) -> HvResult<()> {
    let start = check_bounds(mem, ptr, dst.len())?;
    unsafe {
        std::ptr::copy_nonoverlapping(
            mem.data().as_ptr().add(start) as *const u8,
            dst.as_mut_ptr(),
            dst.len(),
        );
    }
    Ok(())
}

#[inline]
fn write_bytes(mem: &SharedMemory, ptr: u32, src: &[u8]) -> HvResult<()> {
    let start = check_bounds(mem, ptr, src.len())?;
    unsafe {
        std::ptr::copy_nonoverlapping(
            src.as_ptr(),
            mem.data().as_ptr().add(start) as *mut u8,
            src.len(),
        );
    }
    Ok(())
}

#[inline]
fn read_struct<T: FromBytes + AsBytes + Copy>(mem: &SharedMemory, ptr: u32) -> HvResult<T> {
    let mut val = unsafe { std::mem::zeroed::<T>() };
    read_bytes(mem, ptr, val.as_bytes_mut())?;
    Ok(val)
}

#[inline]
fn write_struct<T: AsBytes>(mem: &SharedMemory, ptr: u32, val: &T) -> HvResult<()> {
    write_bytes(mem, ptr, val.as_bytes())
}

#[inline]
fn read_slice<T: FromBytes + AsBytes + Copy>(
    mem: &SharedMemory,
    ptr: u32,
    dst: &mut [T],
) -> HvResult<()> {
    read_bytes(mem, ptr, dst.as_bytes_mut())
}

#[inline]
fn write_slice<T: AsBytes>(mem: &SharedMemory, ptr: u32, src: &[T]) -> HvResult<()> {
    write_bytes(mem, ptr, src.as_bytes())
}

#[inline]
fn unit_rc(res: HvResult<()>) -> i32 {
    match res {
        Ok(()) => 0,
        Err(e) => e.code(),
    }
}

/// Build the Ring-0-compatible Wasmtime [`Config`] (zero SIMD, zero POSIX signal handlers,
/// zero CoW `mmap` tricks, zero virtual-memory guard pages).
pub fn build_ring0_wasm_config() -> Config {
    let mut config = Config::new();
    config.wasm_threads(true);
    config.shared_memory(true);
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
    config.signals_based_traps(false);
    config.memory_init_cow(false);
    config.memory_guard_size(0);
    config
}

/// Register all `"vmm"::*` imports for `vmm-core` against any [`VmmHostCore`] implementation.
pub fn register_core_imports<T, H>(
    linker: &mut Linker<T>,
    get_ctx: impl Fn(&mut T) -> &mut CoreHvWasmCtx<H> + Copy + Send + Sync + 'static,
) -> wasmtime::Result<()>
where
    T: Send + 'static,
    H: VmmHostCore + ?Sized,
{
    linker.func_wrap("vmm", "hv_caps", move |mut caller: Caller<'_, T>| -> u32 {
        get_ctx(caller.data_mut()).host.caps().bits()
    })?;

    linker.func_wrap(
        "vmm",
        "hv_supported_cpuids",
        move |mut caller: Caller<'_, T>, dst_ptr: u32, max_entries: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            const MAX_CPUIDS: usize = 256;
            let cap = (max_entries as usize).min(MAX_CPUIDS);
            let mut buf = [RawCpuid::default(); MAX_CPUIDS];
            let count = match ctx.host.supported_cpuids(&mut buf[..cap]) {
                Ok(n) => n.min(cap),
                Err(e) => return e.code(),
            };
            if let Err(e) = write_slice(&ctx.memory, dst_ptr, &buf[..count]) {
                return e.code();
            }
            count as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_configure",
        move |mut caller: Caller<'_, T>, vcpu: u32, cpuids_ptr: u32, cpuids_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            const MAX_CPUIDS: usize = 256;
            let n = cpuids_len as usize;
            if n > MAX_CPUIDS {
                return HvError::InvalidParam.code();
            }
            let mut buf = [RawCpuid::default(); MAX_CPUIDS];
            if let Err(e) = read_slice(&ctx.memory, cpuids_ptr, &mut buf[..n]) {
                return e.code();
            }
            unit_rc(ctx.host.vcpu_configure(vcpu, &buf[..n]))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_regs",
        move |mut caller: Caller<'_, T>, vcpu: u32, regs_ptr: u32, regs_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            const MAX_BATCH: usize = 64;
            let n = regs_len as usize;
            if n > MAX_BATCH {
                return HvError::InvalidParam.code();
            }
            let mut raw = [RawRegEntry::default(); MAX_BATCH];
            if let Err(e) = read_slice(&ctx.memory, regs_ptr, &mut raw[..n]) {
                return e.code();
            }
            let mut ids = [RegId::MpState; MAX_BATCH];
            let mut vals = [RegVal::Scalar(0); MAX_BATCH];
            for i in 0..n {
                ids[i] = match raw[i].to_id() {
                    Ok(id) => id,
                    Err(e) => return e.code(),
                };
            }
            if let Err(e) = ctx.host.vcpu_get_regs(vcpu, &ids[..n], &mut vals[..n]) {
                return e.code();
            }
            for i in 0..n {
                raw[i].set_val(vals[i]);
            }
            unit_rc(write_slice(&ctx.memory, regs_ptr, &raw[..n]))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_set_regs",
        move |mut caller: Caller<'_, T>, vcpu: u32, regs_ptr: u32, regs_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            const MAX_BATCH: usize = 64;
            let n = regs_len as usize;
            if n > MAX_BATCH {
                return HvError::InvalidParam.code();
            }
            let mut raw = [RawRegEntry::default(); MAX_BATCH];
            if let Err(e) = read_slice(&ctx.memory, regs_ptr, &mut raw[..n]) {
                return e.code();
            }
            let mut pairs = [(RegId::MpState, RegVal::Scalar(0)); MAX_BATCH];
            for i in 0..n {
                pairs[i] = match raw[i].to_pair() {
                    Ok(p) => p,
                    Err(e) => return e.code(),
                };
            }
            unit_rc(ctx.host.vcpu_set_regs(vcpu, &pairs[..n]))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_kick",
        move |mut caller: Caller<'_, T>, vcpu: u32| -> i32 {
            unit_rc(get_ctx(caller.data_mut()).host.vcpu_kick(vcpu))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_alloc",
        move |mut caller: Caller<'_, T>, size: u64| -> i32 {
            match get_ctx(caller.data_mut()).host.mem_alloc(size) {
                Ok(id) => id as i32,
                Err(e) => e.code(),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_free",
        move |mut caller: Caller<'_, T>, obj: u32| -> i32 {
            unit_rc(get_ctx(caller.data_mut()).host.mem_free(obj))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_read",
        move |mut caller: Caller<'_, T>, obj: u32, offset: u64, dst_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            unit_rc(ctx.host.mem_read(obj, offset, dst))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_write",
        move |mut caller: Caller<'_, T>, obj: u32, offset: u64, src_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            let src = unsafe {
                std::slice::from_raw_parts(
                    ctx.memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            unit_rc(ctx.host.mem_write(obj, offset, src))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "gpa_map",
        move |mut caller: Caller<'_, T>,
              gpa: u64,
              size: u64,
              obj: u32,
              offset: u64,
              prot: u32|
              -> i32 {
            let prot = MemProt::from_bits_retain(prot);
            unit_rc(
                get_ctx(caller.data_mut())
                    .host
                    .gpa_map(gpa, size, obj, offset, prot),
            )
        },
    )?;

    linker.func_wrap(
        "vmm",
        "gpa_unmap",
        move |mut caller: Caller<'_, T>, gpa: u64, size: u64| -> i32 {
            unit_rc(get_ctx(caller.data_mut()).host.gpa_unmap(gpa, size))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "inject_msi",
        move |mut caller: Caller<'_, T>, addr: u64, data: u32| -> i32 {
            unit_rc(get_ctx(caller.data_mut()).host.inject_msi(addr, data))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "set_gsi_level",
        move |mut caller: Caller<'_, T>, gsi: u32, active: u32| -> i32 {
            unit_rc(
                get_ctx(caller.data_mut())
                    .host
                    .set_gsi_level(gsi, active != 0),
            )
        },
    )?;

    linker.func_wrap(
        "vmm",
        "register_doorbell",
        move |mut caller: Caller<'_, T>, spec_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let raw = match read_struct::<RawDoorbellSpec>(&ctx.memory, spec_ptr) {
                Ok(r) => r,
                Err(e) => return e.code(),
            };
            let spec = match raw.to_spec() {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            unit_rc(ctx.host.register_doorbell(spec))
        },
    )?;

    linker.func_wrap(
        "vmm",
        "unregister_doorbell",
        move |mut caller: Caller<'_, T>, space: u32, addr: u64, size: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let io_space = match IoSpace::from_u32(space) {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            if size > u8::MAX as u32 {
                return HvError::InvalidParam.code();
            }
            unit_rc(ctx.host.unregister_doorbell(io_space, addr, size as u8))
        },
    )?;

    Ok(())
}

/// Register all `"vmm_bridge"::*` imports for `vmm-core` against any [`VmmCoreBridge`].
pub fn register_bridge_imports<T, B>(
    linker: &mut Linker<T>,
    get_ctx: impl Fn(&mut T) -> &mut CoreBridgeWasmCtx<B> + Copy + Send + Sync + 'static,
) -> wasmtime::Result<()>
where
    T: Send + 'static,
    B: VmmCoreBridge + ?Sized,
{
    linker.func_wrap(
        "vmm_bridge",
        "bridge_boot_info",
        move |mut caller: Caller<'_, T>,
              boot_info_out_ptr: u32,
              devs_out_ptr: u32,
              max_devs: u32|
              -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let mut info = ShmBootInfo::default();
            let mut devs = [ShmVirtioDeviceSpec::default(); MAX_VIRTIO_DEVS];
            let cap = (max_devs as usize).min(MAX_VIRTIO_DEVS);
            let count = match ctx.bridge.boot_info(&mut info, &mut devs[..cap]) {
                Ok(n) => n.min(cap),
                Err(e) => return e.code(),
            };
            if let Err(e) = write_struct(&ctx.memory, boot_info_out_ptr, &info) {
                return e.code();
            }
            if count > 0 {
                let elem_bytes = size_of::<ShmVirtioDeviceSpec>() * count;
                if let Err(e) = check_bounds(&ctx.memory, devs_out_ptr, elem_bytes) {
                    return e.code();
                }
                if let Err(e) = write_slice(&ctx.memory, devs_out_ptr, &devs[..count]) {
                    return e.code();
                }
            }
            count as i32
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_read_payload",
        move |mut caller: Caller<'_, T>, kind: u32, offset: u64, dst_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let pkind = match PayloadKind::from_u32(kind) {
                Ok(k) => k,
                Err(e) => return e.code(),
            };
            let start = match check_bounds(&ctx.memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return e.code(),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            match ctx.bridge.read_payload(pkind, offset, dst) {
                Ok(n) => n as i32,
                Err(e) => e.code(),
            }
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_configure_queues",
        move |mut caller: Caller<'_, T>, dev: u32, queues_ptr: u32, num_queues: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let n = num_queues as usize;
            if n > MAX_QUEUES_PER_DEV {
                return HvError::InvalidParam.code();
            }
            let mut queues = [ShmVirtioQueueConfig::default(); MAX_QUEUES_PER_DEV];
            if let Err(e) = read_slice(&ctx.memory, queues_ptr, &mut queues[..n]) {
                return e.code();
            }
            unit_rc(ctx.bridge.configure_device_queues(dev, &queues[..n]))
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_update_irq_route",
        move |mut caller: Caller<'_, T>, dev: u32, routing_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let routing = match read_struct::<ShmDeviceMsixRouting>(&ctx.memory, routing_ptr) {
                Ok(r) => r,
                Err(e) => return e.code(),
            };
            unit_rc(ctx.bridge.update_irq_route(dev, &routing))
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_send_cmd",
        move |mut caller: Caller<'_, T>, entry_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let entry = match read_struct::<CoreToIoEntry>(&ctx.memory, entry_ptr) {
                Ok(e) => e,
                Err(e) => return e.code(),
            };
            unit_rc(ctx.bridge.send_io_cmd(&entry))
        },
    )?;

    linker.func_wrap(
        "vmm_bridge",
        "bridge_recv_cmd",
        move |mut caller: Caller<'_, T>, entry_out_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let mut out = IoToCoreEntry::default();
            let got = match ctx.bridge.recv_io_cmd(&mut out) {
                Ok(g) => g,
                Err(e) => return e.code(),
            };
            if got && let Err(e) = write_struct(&ctx.memory, entry_out_ptr, &out) {
                return e.code();
            }
            i32::from(got)
        },
    )?;

    Ok(())
}

pub struct CoreStoreState<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    pub hv: CoreHvWasmCtx<H>,
    pub bridge: CoreBridgeWasmCtx<B>,
}

fn bind_worker_stack<T>(
    store: &mut Store<T>,
    instance: &Instance,
    stack_top: u32,
) -> Result<(), String> {
    if stack_top == 0 || (stack_top & 15) != 0 {
        return Err(format!("invalid worker stack_top {stack_top:#x}"));
    }
    let sp = instance
        .get_global(&mut *store, "__stack_pointer")
        .ok_or_else(|| "missing exported __stack_pointer global in vmm-core.wasm".to_string())?;
    sp.set(&mut *store, Val::I32(stack_top as i32))
        .map_err(|e| format!("failed to set __stack_pointer to {stack_top:#x}: {e}"))
}

/// Instantiate `#![no_std]` `vmm-core` (zero WASI imports) and drive the host-owned
/// per-vCPU and bridge-RX execution loops against any [`VmmHostRunner`] and [`VmmCoreBridge`].
pub fn run_wasm_core<H: VmmHostRunner + ?Sized, B: VmmCoreBridge + ?Sized>(
    module_path: &Path,
    host: Arc<H>,
    bridge: Arc<B>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[allow(unused_mut)]
    let mut config = build_ring0_wasm_config();
    #[cfg(feature = "compiler")]
    config.target(env!("VMM_HOST_TARGET"))?;
    let engine = Engine::new(&config)?;

    #[cfg(feature = "compiler")]
    let module = {
        let wasm_bytes = std::fs::read(module_path)?;
        crate::verify_no_fp::validate_wasm_no_fp(&wasm_bytes)
            .map_err(|e| format!("Wasm FP/SIMD/WASI validation failed for {module_path:?}: {e}"))?;
        let module = Module::new(&engine, &wasm_bytes)?;
        let compiled_bytes = module.serialize()?;
        crate::verify_no_fp::validate_cwasm_no_fp(&compiled_bytes).map_err(|e| {
            format!("JIT machine-code FP/SIMD validation failed for {module_path:?}: {e}")
        })?;
        module
    };
    #[cfg(not(feature = "compiler"))]
    let module = {
        let cwasm_bytes = std::fs::read(module_path)?;
        crate::verify_no_fp::validate_cwasm_no_fp(&cwasm_bytes)
            .map_err(|e| format!("cwasm FP/SIMD validation failed for {module_path:?}: {e}"))?;
        unsafe { Module::deserialize(&engine, &cwasm_bytes)? }
    };

    let memory_ty = module
        .imports()
        .find_map(|imp| {
            if imp.module() == "env"
                && imp.name() == "memory"
                && let ExternType::Memory(ty) = imp.ty()
            {
                Some(ty)
            } else {
                None
            }
        })
        .unwrap_or_else(|| MemoryType::shared(17, 16384));

    let shared_memory = SharedMemory::new(&engine, memory_ty)?;

    let mut init_store = Store::new(
        &engine,
        CoreStoreState {
            hv: CoreHvWasmCtx::new(host.clone(), shared_memory.clone()),
            bridge: CoreBridgeWasmCtx::new(bridge.clone(), shared_memory.clone()),
        },
    );

    let mut linker = Linker::<CoreStoreState<H, B>>::new(&engine);
    linker.define(&init_store, "env", "memory", shared_memory.clone())?;
    register_core_imports(&mut linker, |state| &mut state.hv)?;
    register_bridge_imports(&mut linker, |state| &mut state.bridge)?;

    let init_instance = linker.instantiate(&mut init_store, &module)?;
    let vmm_init = init_instance.get_typed_func::<(), i32>(&mut init_store, "vmm_init")?;
    let vmm_num_cpus = init_instance.get_typed_func::<(), u32>(&mut init_store, "vmm_num_cpus")?;
    let vmm_stack_top =
        init_instance.get_typed_func::<u32, u32>(&mut init_store, "vmm_stack_top")?;
    let vmm_reset = init_instance.get_typed_func::<(), i32>(&mut init_store, "vmm_reset")?;

    let init_rc = vmm_init.call(&mut init_store, ())?;
    if init_rc < 0 {
        return Err(format!("vmm_init failed: {:?}", HvError::from_code(init_rc)).into());
    }
    let comm_base = init_rc as u32;
    let num_cpus = vmm_num_cpus.call(&mut init_store, ())?;
    if num_cpus == 0 {
        return Err("vmm_num_cpus returned 0".into());
    }

    let comm_total_bytes = (num_cpus as usize)
        .checked_mul(size_of::<VcpuCommPage>())
        .ok_or("VcpuCommPage array size overflow")?;
    let comm_base_start = check_bounds(&shared_memory, comm_base, comm_total_bytes)
        .map_err(|e| format!("invalid VcpuCommPage base {comm_base:#x}: {e}"))?;
    let shm_base_addr = unsafe { shared_memory.data().as_ptr().add(comm_base_start) as usize };
    if !shm_base_addr.is_multiple_of(align_of::<VcpuCommPage>()) {
        return Err(format!(
            "unaligned VcpuCommPage host address {shm_base_addr:#x} (comm_base={comm_base:#x})"
        )
        .into());
    }

    // Pre-instantiate one lightweight `(Store, Instance)` per guest vCPU (`slot = 0..num_cpus`).
    let mut vcpu_workers = Vec::with_capacity(num_cpus as usize);
    for vcpu_id in 0..num_cpus {
        let stack_top = vmm_stack_top.call(&mut init_store, vcpu_id)?;
        let mut store = Store::new(
            &engine,
            CoreStoreState {
                hv: CoreHvWasmCtx::new(host.clone(), shared_memory.clone()),
                bridge: CoreBridgeWasmCtx::new(bridge.clone(), shared_memory.clone()),
            },
        );
        let instance = linker.instantiate(&mut store, &module)?;
        bind_worker_stack(&mut store, &instance, stack_top)?;
        vcpu_workers.push((store, instance, stack_top));
    }

    // Pre-instantiate the dedicated bridge-RX worker (`slot = num_cpus`).
    let rx_stack_top = vmm_stack_top.call(&mut init_store, num_cpus)?;
    let mut rx_store = Store::new(
        &engine,
        CoreStoreState {
            hv: CoreHvWasmCtx::new(host.clone(), shared_memory.clone()),
            bridge: CoreBridgeWasmCtx::new(bridge.clone(), shared_memory.clone()),
        },
    );
    let rx_instance = linker.instantiate(&mut rx_store, &module)?;
    bind_worker_stack(&mut rx_store, &rx_instance, rx_stack_top)?;
    let on_bridge_rx_fn =
        rx_instance.get_typed_func::<(), i32>(&mut rx_store, "vmm_on_bridge_rx")?;

    let host_rx = host.clone();
    let rx_handle = std::thread::Builder::new()
        .name("core-bridge-rx".to_string())
        .spawn(move || {
            while host_rx.wait_bridge_rx() {
                match on_bridge_rx_fn.call(&mut rx_store, ()) {
                    Ok(rc) if rc < 0 => {
                        log::error!(
                            "vmm_on_bridge_rx returned error: {:?}",
                            HvError::from_code(rc)
                        );
                        break;
                    }
                    Ok(rc) if rc == VmAction::Shutdown as i32 => break,
                    Ok(_) => {}
                    Err(e) => {
                        log::error!("vmm_on_bridge_rx trapped: {e}");
                        break;
                    }
                }
            }
        })?;

    const ROUND_CONTINUE: u8 = 0;
    const ROUND_SHUTDOWN: u8 = 1;
    const ROUND_REBOOT: u8 = 2;

    let mut fatal_err: Option<String> = None;

    loop {
        for (vcpu_id, (store, instance, stack_top)) in vcpu_workers.iter_mut().enumerate() {
            if let Err(e) = bind_worker_stack(store, instance, *stack_top) {
                fatal_err = Some(e);
                break;
            }
            let bind_res = instance
                .get_typed_func::<(u32, u32), ()>(&mut *store, "vmm_bind_vcpu")
                .and_then(|f| f.call(&mut *store, (vcpu_id as u32, *stack_top)));
            if let Err(e) = bind_res {
                fatal_err = Some(format!("vmm_bind_vcpu({vcpu_id}) failed: {e}"));
                break;
            }
        }
        if fatal_err.is_some() {
            break;
        }

        let round_action = AtomicU8::new(ROUND_CONTINUE);
        let round_action_ref = &round_action;

        let returned_workers: Vec<(
            Result<(), String>,
            (Store<CoreStoreState<H, B>>, Instance, u32),
        )> = std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(vcpu_workers.len());
            for (idx, (mut store, instance, stack_top)) in vcpu_workers.drain(..).enumerate() {
                let vcpu_id = idx as u32;
                let host_vcpu = host.clone();
                let mem_vcpu = shared_memory.clone();
                let handle = std::thread::Builder::new()
                    .name(format!("vcpu_{vcpu_id}"))
                    .spawn_scoped(s, move || {
                        let res = (|| -> Result<(), String> {
                            let on_exit_fn = instance
                                .get_typed_func::<u32, i32>(&mut store, "vmm_on_vcpu_exit")
                                .map_err(|e| format!("missing vmm_on_vcpu_exit: {e}"))?;
                            let comm_off =
                                comm_base_start + (idx * size_of::<VcpuCommPage>());

                            loop {
                                {
                                    // Safety: `comm_page[vcpu_id]` is 64-byte aligned, in-bounds of
                                    // `SharedMemory`, and exclusively accessed by this host vCPU
                                    // thread while Wasm is not executing on `vcpu_id`.
                                    let comm = unsafe {
                                        &mut *(mem_vcpu.data().as_ptr().add(comm_off)
                                            as *mut VcpuCommPage)
                                    };
                                    host_vcpu.enter_guest(vcpu_id, comm).map_err(|e| {
                                        format!("enter_guest(vcpu {vcpu_id}) failed: {e}")
                                    })?;
                                }

                                let rc = on_exit_fn.call(&mut store, vcpu_id).map_err(|e| {
                                    format!("vmm_on_vcpu_exit({vcpu_id}) trapped: {e}")
                                })?;
                                if rc < 0 {
                                    return Err(format!(
                                        "vmm_on_vcpu_exit({vcpu_id}) failed: {:?}",
                                        HvError::from_code(rc)
                                    ));
                                }
                                match VmAction::from_i32(rc) {
                                    Ok(VmAction::Continue) => {}
                                    Ok(VmAction::Shutdown) => {
                                        round_action_ref.store(ROUND_SHUTDOWN, Ordering::Release);
                                        return Ok(());
                                    }
                                    Ok(VmAction::Reboot) => {
                                        let _ = round_action_ref.compare_exchange(
                                            ROUND_CONTINUE,
                                            ROUND_REBOOT,
                                            Ordering::AcqRel,
                                            Ordering::Acquire,
                                        );
                                        return Ok(());
                                    }
                                    Err(e) => {
                                        return Err(format!(
                                            "invalid VmAction {rc} from vcpu {vcpu_id}: {e}"
                                        ));
                                    }
                                }
                            }
                        })();
                        if res.is_err() {
                            round_action_ref.store(ROUND_SHUTDOWN, Ordering::Release);
                            for peer in 0..num_cpus {
                                if peer != vcpu_id {
                                    let _ = host_vcpu.vcpu_kick(peer);
                                }
                            }
                        }
                        (res, (store, instance, stack_top))
                    })
                    .expect("failed to spawn host vCPU thread");
                handles.push(handle);
            }

            handles
                .into_iter()
                .map(|h| h.join().expect("host vCPU thread panicked"))
                .collect()
        });

        for (res, worker) in returned_workers {
            if let Err(e) = res
                && fatal_err.is_none()
            {
                fatal_err = Some(e);
            }
            vcpu_workers.push(worker);
        }

        if fatal_err.is_some() || round_action.load(Ordering::Acquire) != ROUND_REBOOT {
            break;
        }

        let reset_rc = vmm_reset.call(&mut init_store, ())?;
        if reset_rc < 0 {
            fatal_err = Some(format!(
                "vmm_reset failed: {:?}",
                HvError::from_code(reset_rc)
            ));
            break;
        }
    }

    host.wake_bridge_rx();
    let _ = rx_handle.join();

    if let Some(err) = fatal_err {
        return Err(err.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use vmm_core::host::abi::{CORE_MSG_SHUTDOWN, GPR_RAX, RawVmExit};
    use vmm_core::host::{HostCaps, MemObjId, VmExit};

    #[derive(Default)]
    struct DummyHv {
        mem: Mutex<Vec<Vec<u8>>>,
    }

    impl VmmHostCore for DummyHv {
        fn caps(&self) -> HostCaps {
            HostCaps::DECODED_MMIO | HostCaps::DOORBELLS
        }
        fn supported_cpuids(&self, dst: &mut [RawCpuid]) -> HvResult<usize> {
            if let Some(first) = dst.first_mut() {
                *first = RawCpuid {
                    func: 0x1,
                    has_index: 0,
                    index: 0,
                    eax: 0x0006_06a6,
                    ebx: 0,
                    ecx: 0,
                    edx: 0x078b_fbff,
                };
                Ok(1)
            } else {
                Ok(0)
            }
        }
        fn vcpu_configure(&self, _vcpu: VcpuId, _cpuids: &[RawCpuid]) -> HvResult<()> {
            Ok(())
        }
        fn vcpu_get_regs(
            &self,
            _vcpu: VcpuId,
            _ids: &[RegId],
            _out: &mut [RegVal],
        ) -> HvResult<()> {
            Ok(())
        }
        fn vcpu_set_regs(&self, _vcpu: VcpuId, _regs: &[(RegId, RegVal)]) -> HvResult<()> {
            Ok(())
        }
        fn vcpu_kick(&self, _vcpu: VcpuId) -> HvResult<()> {
            Ok(())
        }
        fn mem_alloc(&self, size: u64) -> HvResult<MemObjId> {
            let mut mem = self.mem.lock();
            let id = mem.len() as MemObjId;
            mem.push(vec![0u8; size as usize]);
            Ok(id)
        }
        fn mem_free(&self, _obj: MemObjId) -> HvResult<()> {
            Ok(())
        }
        fn mem_read(&self, obj: MemObjId, offset: u64, dst: &mut [u8]) -> HvResult<()> {
            let mem = self.mem.lock();
            let buf = mem.get(obj as usize).ok_or(HvError::InvalidParam)?;
            let start = offset as usize;
            dst.copy_from_slice(&buf[start..start + dst.len()]);
            Ok(())
        }
        fn mem_write(&self, obj: MemObjId, offset: u64, src: &[u8]) -> HvResult<()> {
            let mut mem = self.mem.lock();
            let buf = mem.get_mut(obj as usize).ok_or(HvError::InvalidParam)?;
            let start = offset as usize;
            buf[start..start + src.len()].copy_from_slice(src);
            Ok(())
        }
        fn gpa_map(
            &self,
            _gpa: u64,
            _size: u64,
            _obj: MemObjId,
            _offset: u64,
            _prot: MemProt,
        ) -> HvResult<()> {
            Ok(())
        }
        fn gpa_unmap(&self, _gpa: u64, _size: u64) -> HvResult<()> {
            Ok(())
        }
        fn inject_msi(&self, _addr: u64, _data: u32) -> HvResult<()> {
            Ok(())
        }
        fn set_gsi_level(&self, _gsi: u32, _active: bool) -> HvResult<()> {
            Ok(())
        }
        fn register_doorbell(&self, _spec: vmm_core::host::DoorbellSpec) -> HvResult<()> {
            Ok(())
        }
        fn unregister_doorbell(&self, _space: IoSpace, _addr: u64, _size: u8) -> HvResult<()> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct DummyBridge {
        sent: Mutex<Vec<CoreToIoEntry>>,
    }

    impl VmmCoreBridge for DummyBridge {
        fn boot_info(
            &self,
            out_info: &mut ShmBootInfo,
            _out_devs: &mut [ShmVirtioDeviceSpec],
        ) -> HvResult<usize> {
            out_info.num_cpus = 2;
            out_info.mem_size = 16 << 20;
            Ok(0)
        }
        fn read_payload(
            &self,
            _kind: PayloadKind,
            _offset: u64,
            _dst: &mut [u8],
        ) -> HvResult<usize> {
            Ok(0)
        }
        fn configure_device_queues(
            &self,
            _dev: u32,
            _queues: &[ShmVirtioQueueConfig],
        ) -> HvResult<()> {
            Ok(())
        }
        fn update_irq_route(&self, _dev: u32, _routing: &ShmDeviceMsixRouting) -> HvResult<()> {
            Ok(())
        }
        fn send_io_cmd(&self, entry: &CoreToIoEntry) -> HvResult<()> {
            self.sent.lock().push(*entry);
            Ok(())
        }
        fn recv_io_cmd(&self, _out: &mut IoToCoreEntry) -> HvResult<bool> {
            Ok(false)
        }
    }

    #[test]
    fn test_zero_wasi_host_driven_lifecycle_non_kvm() -> wasmtime::Result<()> {
        let config = build_ring0_wasm_config();
        let engine = Engine::new(&config)?;
        let cwasm_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/vmm-core.cwasm"));
        let module = unsafe { Module::deserialize(&engine, cwasm_bytes)? };

        // Verify module has zero WASI imports — only `env`, `vmm`, and `vmm_bridge`.
        for imp in module.imports() {
            assert!(
                matches!(imp.module(), "env" | "vmm" | "vmm_bridge"),
                "unexpected import {}::{}",
                imp.module(),
                imp.name()
            );
        }

        let hv = Arc::new(DummyHv::default());
        let bridge = Arc::new(DummyBridge::default());
        let shared_memory = SharedMemory::new(&engine, MemoryType::shared(18, 16384))?;
        let mut init_store = Store::new(
            &engine,
            CoreStoreState {
                hv: CoreHvWasmCtx::new(hv.clone(), shared_memory.clone()),
                bridge: CoreBridgeWasmCtx::new(bridge.clone(), shared_memory.clone()),
            },
        );
        let mut linker = Linker::new(&engine);
        linker.define(&init_store, "env", "memory", shared_memory.clone())?;
        register_core_imports(&mut linker, |s: &mut CoreStoreState<DummyHv, DummyBridge>| {
            &mut s.hv
        })?;
        register_bridge_imports(&mut linker, |s: &mut CoreStoreState<DummyHv, DummyBridge>| {
            &mut s.bridge
        })?;

        let init_inst = linker.instantiate(&mut init_store, &module)?;
        let vmm_init = init_inst.get_typed_func::<(), i32>(&mut init_store, "vmm_init")?;
        let vmm_num_cpus = init_inst.get_typed_func::<(), u32>(&mut init_store, "vmm_num_cpus")?;
        let vmm_stack_top =
            init_inst.get_typed_func::<u32, u32>(&mut init_store, "vmm_stack_top")?;

        let comm_base = vmm_init.call(&mut init_store, ())?;
        assert!(comm_base > 0, "vmm_init failed with {comm_base}");
        assert_eq!((comm_base as usize) % align_of::<VcpuCommPage>(), 0);
        assert_eq!(vmm_num_cpus.call(&mut init_store, ())?, 2);

        // Bind worker Instance[0] on its disjoint shadow stack and execute exits!
        let stack0 = vmm_stack_top.call(&mut init_store, 0)?;
        let mut worker0_store = Store::new(
            &engine,
            CoreStoreState {
                hv: CoreHvWasmCtx::new(hv, shared_memory.clone()),
                bridge: CoreBridgeWasmCtx::new(bridge.clone(), shared_memory.clone()),
            },
        );
        let worker0_inst = linker.instantiate(&mut worker0_store, &module)?;
        bind_worker_stack(&mut worker0_store, &worker0_inst, stack0).unwrap();
        worker0_inst
            .get_typed_func::<(u32, u32), ()>(&mut worker0_store, "vmm_bind_vcpu")?
            .call(&mut worker0_store, (0, stack0))?;
        let on_exit =
            worker0_inst.get_typed_func::<u32, i32>(&mut worker0_store, "vmm_on_vcpu_exit")?;

        // 1. CPUID(0x1, 0) exit via zero-copy `VcpuCommPage`
        let mut comm = VcpuCommPage {
            rip: 0x2000,
            exit: RawVmExit::from_exit(VmExit::Cpuid { func: 1, index: 0 }),
            ..Default::default()
        };
        write_struct(&shared_memory, comm_base as u32, &comm).unwrap();
        assert_eq!(
            on_exit.call(&mut worker0_store, 0)?,
            VmAction::Continue as i32
        );
        comm = read_struct::<VcpuCommPage>(&shared_memory, comm_base as u32).unwrap();
        assert_eq!(comm.gprs[GPR_RAX], 0x0006_06a6);
        assert_eq!(comm.rip, 0x2002);

        // 2. ACPI S5 shutdown (`outb 0x34, 0x600`) -> returns `VmAction::Shutdown` immediately!
        comm.exit = RawVmExit::from_exit(VmExit::Io {
            port: 0x600,
            write: Some(0x34),
            size: 1,
        });
        write_struct(&shared_memory, comm_base as u32, &comm).unwrap();
        assert_eq!(
            on_exit.call(&mut worker0_store, 0)?,
            VmAction::Shutdown as i32
        );
        assert!(
            bridge
                .sent
                .lock()
                .iter()
                .any(|e| e.msg_type == CORE_MSG_SHUTDOWN)
        );
        Ok(())
    }
}
