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

use std::mem::size_of;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use parking_lot::RwLock;
use vmm_core::host::abi::{
    CoreToIoEntry, IoToCoreEntry, MAX_QUEUES_PER_DEV, MAX_VIRTIO_DEVS, RawCpuid, RawDoorbellSpec,
    RawRegEntry, ShmBootInfo, ShmDeviceMsixRouting, ShmVirtioDeviceSpec, ShmVirtioQueueConfig,
    VcpuCommPage,
};
pub use vmm_core::host::{VmmCoreBridge, VmmHostCore};
use vmm_core::host::{
    HvError, HvResult, IoSpace, MemProt, PayloadKind, RegId, RegVal,
};
use wasmtime::{
    Caller, Config, Engine, ExternType, Linker, MemoryType, Module, SharedMemory, Store,
};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{I32Exit, WasiCtxBuilder};
use zerocopy::{AsBytes, FromBytes};

/// Per-Wasm-thread ABI context binding a [`VmmHostCore`] implementation to a Wasmtime store.
pub struct CoreHvWasmCtx<H: VmmHostCore + ?Sized> {
    pub host: Arc<H>,
    pub memory: SharedMemory,
}

impl<H: VmmHostCore + ?Sized> CoreHvWasmCtx<H> {
    pub fn new(host: Arc<H>, memory: SharedMemory) -> Self {
        Self { host, memory }
    }
}

/// Per-Wasm-thread ABI context binding a [`VmmCoreBridge`] implementation to a Wasmtime store.
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
        "vcpu_run",
        move |mut caller: Caller<'_, T>, vcpu: u32, comm_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let mut comm = match read_struct::<VcpuCommPage>(&ctx.memory, comm_ptr) {
                Ok(c) => c,
                Err(e) => return e.code(),
            };
            if let Err(e) = ctx.host.vcpu_run(vcpu, &mut comm) {
                return e.code();
            }
            unit_rc(write_struct(&ctx.memory, comm_ptr, &comm))
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
        move |mut caller: Caller<'_, T>, blocking: u32, entry_out_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let mut out = IoToCoreEntry::default();
            let got = match ctx.bridge.recv_io_cmd(blocking != 0, &mut out) {
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

fn build_core_wasi() -> wasmtime::Result<WasiP1Ctx> {
    let mut builder = WasiCtxBuilder::new();
    builder
        .allow_blocking_current_thread(true)
        .inherit_stdio()
        .args(&["vmm-core"]);
    Ok(builder.build_p1())
}

struct CoreStoreState<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized> {
    wasi: WasiP1Ctx,
    hv: CoreHvWasmCtx<H>,
    bridge: CoreBridgeWasmCtx<B>,
}

/// Instantiate and execute `vmm-core` against any [`VmmHostCore`] and [`VmmCoreBridge`].
pub fn run_wasm_core<H: VmmHostCore + ?Sized, B: VmmCoreBridge + ?Sized>(
    module_path: &Path,
    host: Arc<H>,
    bridge: Arc<B>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new();
    config.wasm_threads(true);
    config.shared_memory(true);
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
    #[cfg(feature = "compiler")]
    config.target(env!("VMM_HOST_TARGET"))?;
    let engine = Engine::new(&config)?;

    #[cfg(feature = "compiler")]
    let module = {
        let wasm_bytes = std::fs::read(module_path)?;
        crate::verify_no_fp::validate_wasm_no_fp(&wasm_bytes)
            .map_err(|e| format!("Wasm FP/SIMD validation failed for {module_path:?}: {e}"))?;
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

    let mut store = Store::new(
        &engine,
        CoreStoreState {
            wasi: build_core_wasi()?,
            hv: CoreHvWasmCtx::new(host, shared_memory.clone()),
            bridge: CoreBridgeWasmCtx::new(bridge, shared_memory.clone()),
        },
    );

    let mut linker = Linker::<CoreStoreState<H, B>>::new(&engine);
    linker.define(&store, "env", "memory", shared_memory)?;
    p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;
    register_core_imports(&mut linker, |state| &mut state.hv)?;
    register_bridge_imports(&mut linker, |state| &mut state.bridge)?;

    let next_tid = Arc::new(AtomicI32::new(1));
    let spawn_engine = engine.clone();
    let spawn_module = module.clone();

    let spawn_linker_slot: Arc<RwLock<Option<Linker<CoreStoreState<H, B>>>>> =
        Arc::new(RwLock::new(None));
    let spawn_linker_ref = spawn_linker_slot.clone();

    linker.func_wrap(
        "wasi",
        "thread-spawn",
        move |caller: Caller<'_, CoreStoreState<H, B>>, start_arg: i32| -> i32 {
            let tid = next_tid
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    Some(if v >= 0x1fff_fffe { 1 } else { v + 1 })
                })
                .unwrap();

            let engine = spawn_engine.clone();
            let module = spawn_module.clone();
            let linker_opt = spawn_linker_ref.read().clone();
            let Some(child_linker) = linker_opt else {
                return -1;
            };
            let wasi_ctx = match build_core_wasi() {
                Ok(c) => c,
                Err(_) => return -1,
            };
            let child_host = caller.data().hv.host.clone();
            let child_bridge = caller.data().bridge.bridge.clone();
            let memory = caller.data().hv.memory.clone();

            let spawn_res = std::thread::Builder::new()
                .name(format!("core_wasm_thread_{tid}"))
                .spawn(move || {
                    let mut child_store = Store::new(
                        &engine,
                        CoreStoreState {
                            wasi: wasi_ctx,
                            hv: CoreHvWasmCtx::new(child_host, memory.clone()),
                            bridge: CoreBridgeWasmCtx::new(child_bridge, memory),
                        },
                    );
                    let instance = match child_linker.instantiate(&mut child_store, &module) {
                        Ok(inst) => inst,
                        Err(e) => {
                            log::error!("failed to instantiate core module on thread {tid}: {e}");
                            return;
                        }
                    };
                    let start_fn = match instance
                        .get_typed_func::<(i32, i32), ()>(&mut child_store, "wasi_thread_start")
                    {
                        Ok(f) => f,
                        Err(e) => {
                            log::error!("missing wasi_thread_start export on thread {tid}: {e}");
                            return;
                        }
                    };
                    if let Err(e) = start_fn.call(&mut child_store, (tid, start_arg))
                        && e.downcast_ref::<I32Exit>().is_none_or(|c| c.0 != 0)
                    {
                        log::error!("wasi_thread_start on thread {tid} trapped: {e}");
                    }
                });

            match spawn_res {
                Ok(_) => tid,
                Err(_) => -1,
            }
        },
    )?;

    *spawn_linker_slot.write() = Some(linker.clone());

    let instance = linker.instantiate(&mut store, &module)?;
    let start = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    if let Err(err) = start.call(&mut store, ()) {
        if let Some(exit) = err.downcast_ref::<I32Exit>()
            && exit.0 == 0
        {
            return Ok(());
        }
        return Err(err.into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vmm_core::host::abi::RawVmExit;
    use vmm_core::host::{HostCaps, MemObjId, VcpuId, VmExit};

    struct DummyHv;

    impl VmmHostCore for DummyHv {
        fn caps(&self) -> HostCaps {
            HostCaps::DECODED_MMIO | HostCaps::HW_IOAPIC
        }
        fn supported_cpuids(&self, _dst: &mut [RawCpuid]) -> HvResult<usize> {
            Ok(0)
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
        fn vcpu_run(&self, _vcpu: VcpuId, comm: &mut VcpuCommPage) -> HvResult<()> {
            comm.exit = RawVmExit::from_exit(VmExit::Shutdown);
            Ok(())
        }
        fn mem_alloc(&self, _size: u64) -> HvResult<MemObjId> {
            Ok(0)
        }
        fn mem_free(&self, _obj: MemObjId) -> HvResult<()> {
            Ok(())
        }
        fn mem_read(&self, _obj: MemObjId, _offset: u64, _dst: &mut [u8]) -> HvResult<()> {
            Ok(())
        }
        fn mem_write(&self, _obj: MemObjId, _offset: u64, _src: &[u8]) -> HvResult<()> {
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

    struct DummyBridge;

    impl VmmCoreBridge for DummyBridge {
        fn boot_info(
            &self,
            _out_info: &mut ShmBootInfo,
            _out_devs: &mut [ShmVirtioDeviceSpec],
        ) -> HvResult<usize> {
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
        fn send_io_cmd(&self, _entry: &CoreToIoEntry) -> HvResult<()> {
            Ok(())
        }
        fn recv_io_cmd(&self, _blocking: bool, _out: &mut IoToCoreEntry) -> HvResult<bool> {
            Ok(false)
        }
    }

    #[test]
    fn test_register_core_and_bridge_imports_non_kvm() -> wasmtime::Result<()> {
        let mut config = Config::new();
        config.wasm_threads(true);
        config.shared_memory(true);
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);
        let engine = Engine::new(&config)?;
        let cwasm_bytes = include_bytes!(concat!(env!("OUT_DIR"), "/vmm-core.cwasm"));
        let module = unsafe { Module::deserialize(&engine, cwasm_bytes)? };

        let shared_memory = SharedMemory::new(&engine, MemoryType::shared(18, 16384))?;
        let mut store = Store::new(
            &engine,
            CoreStoreState {
                wasi: build_core_wasi()?,
                hv: CoreHvWasmCtx::new(Arc::new(DummyHv), shared_memory.clone()),
                bridge: CoreBridgeWasmCtx::new(Arc::new(DummyBridge), shared_memory.clone()),
            },
        );
        let mut linker = Linker::new(&engine);
        linker.define(&store, "env", "memory", shared_memory)?;
        p1::add_to_linker_sync(&mut linker, |s: &mut CoreStoreState<DummyHv, DummyBridge>| {
            &mut s.wasi
        })?;
        register_core_imports(&mut linker, |s| &mut s.hv)?;
        register_bridge_imports(&mut linker, |s| &mut s.bridge)?;
        linker.func_wrap("wasi", "thread-spawn", |_: i32| -> i32 { -1 })?;

        let _instance = linker.instantiate(&mut store, &module)?;
        Ok(())
    }
}
