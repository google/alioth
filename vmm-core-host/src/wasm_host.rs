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

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use parking_lot::RwLock;
use vmm_core::host::abi::{
    ERR_GENERIC, ERR_INTERRUPTED, ERR_WOULD_BLOCK, EXIT_INTERRUPTED, EXIT_IO, EXIT_MMIO,
    EXIT_REBOOT, EXIT_SHUTDOWN, EXIT_UNKNOWN, MAX_VIRTIO_DEVS, RawCpuid, RawDtRegEntry,
    RawDtRegVal, RawRegVal, RawSegRegEntry, RawSegRegVal, RawVmExit, ShmBootInfo,
    ShmDeviceMsixRouting, ShmVirtioDeviceSpec, ShmVirtioQueueConfig, decode_vm_entry,
    dt_reg_from_u32, mem_map_option_from_u32, reg_from_u32, seg_reg_from_u32, sreg_from_u32,
};
use vmm_core::host::{
    CoreBootInfo, Cpuid, DtReg, DtRegVal, Error as HvError, Handle, MemMapOption, PayloadKind,
    Reg, Result as HvResult, SReg, SegReg, SegRegVal, VirtioDeviceSpec, VirtioQueueConfig,
    VmEntry, VmExit,
};
use wasmtime::{
    Caller, Config, Engine, ExternType, Linker, MemoryType, Module, SharedMemory, Store,
};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{I32Exit, WasiCtxBuilder};
use zerocopy::{AsBytes, FromBytes};

/// Host interface trait for the core hypervisor/vCPU/memory/interrupt domain (`vmm-core-host`).
///
/// All `"vmm"::*` host imports registered by [`register_core_imports`] delegate exclusively
/// to this trait, allowing alternate implementations (e.g. a Ring 0 kernel host in Motor OS).
pub trait VmmHostCore: Send + Sync + 'static {
    fn hv_new(&self) -> HvResult<Handle>;
    fn hv_get_supported_cpuids(&self, hv: Handle) -> HvResult<Vec<Cpuid>>;
    fn hv_create_vm(&self, hv: Handle) -> HvResult<Handle>;
    fn hv_close(&self, hv: Handle);

    fn vm_create_vcpu(&self, vm: Handle, id: u32) -> HvResult<Handle>;
    fn vm_stop_vcpu(&self, vm: Handle, id: u32) -> HvResult<()>;
    fn vm_create_vm_memory(&self, vm: Handle) -> HvResult<Handle>;
    fn vm_create_intx_sender(&self, vm: Handle, pin: u8) -> HvResult<Handle>;
    fn vm_create_msi_sender(&self, vm: Handle) -> HvResult<Handle>;
    fn vm_close(&self, vm: Handle);

    fn vcpu_run(&self, vcpu: Handle, entry: VmEntry) -> HvResult<VmExit>;
    fn vcpu_get_reg(&self, vcpu: Handle, reg: Reg) -> HvResult<u64>;
    fn vcpu_set_regs(&self, vcpu: Handle, vals: &[(Reg, u64)]) -> HvResult<()>;
    fn vcpu_get_seg_reg(&self, vcpu: Handle, reg: SegReg) -> HvResult<SegRegVal>;
    fn vcpu_get_dt_reg(&self, vcpu: Handle, reg: DtReg) -> HvResult<DtRegVal>;
    fn vcpu_get_sreg(&self, vcpu: Handle, reg: SReg) -> HvResult<u64>;
    fn vcpu_set_sregs(
        &self,
        vcpu: Handle,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> HvResult<()>;
    fn vcpu_set_cpuids(&self, vcpu: Handle, cpuids: Vec<Cpuid>) -> HvResult<()>;
    fn vcpu_dump(&self, vcpu: Handle) -> HvResult<()>;
    fn vcpu_close(&self, vcpu: Handle);

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
    fn vm_memory_register_encrypted_range(
        &self,
        mem: Handle,
        addr: u64,
        size: u64,
    ) -> HvResult<()>;
    fn vm_memory_deregister_encrypted_range(
        &self,
        mem: Handle,
        addr: u64,
        size: u64,
    ) -> HvResult<()>;
    fn vm_memory_alloc_anon_mem(&self, mem: Handle, size: u64) -> HvResult<(Handle, u64, u64)>;
    fn vm_memory_close(&self, mem: Handle);

    fn mem_pages_sync(&self, pages: Handle) -> HvResult<()>;
    fn mem_pages_read(&self, pages: Handle, offset: u64, dst: &mut [u8]) -> HvResult<()>;
    fn mem_pages_write(&self, pages: Handle, offset: u64, src: &[u8]) -> HvResult<()>;
    fn mem_pages_close(&self, pages: Handle);

    fn intx_sender_send(&self, sender: Handle) -> HvResult<()>;
    fn intx_sender_close(&self, sender: Handle);

    fn msi_sender_send(&self, sender: Handle, addr: u64, data: u32) -> HvResult<()>;
    fn msi_sender_close(&self, sender: Handle);

    fn core_get_boot_info(&self) -> HvResult<(CoreBootInfo, Vec<VirtioDeviceSpec>)>;
    fn core_read_payload(
        &self,
        kind: PayloadKind,
        offset: u64,
        dst: &mut [u8],
    ) -> HvResult<usize>;
    fn core_virtio_start(
        &self,
        dev: Handle,
        driver_features: u64,
        queues: &[VirtioQueueConfig],
    ) -> HvResult<()>;
    fn core_virtio_notify(&self, dev: Handle, queue_index: u16) -> HvResult<()>;
    fn core_virtio_reset(&self, dev: Handle) -> HvResult<()>;
    fn core_virtio_update_irq(
        &self,
        dev: Handle,
        config_msi: Option<(u64, u32)>,
        queue_msis: &[Option<(u64, u32)>],
    ) -> HvResult<()>;
    fn core_serial_tx(&self, byte: u8) -> HvResult<()>;
    fn core_serial_rx(&self, dst: &mut [u8]) -> HvResult<usize>;
    fn core_notify_shutdown(&self) -> HvResult<()>;
}

/// Per-Wasm-thread ABI context binding a [`VmmHostCore`] implementation to a Wasmtime store.
pub struct CoreWasmCtx<H: VmmHostCore + ?Sized> {
    host: Arc<H>,
    memory: SharedMemory,
    last_error: String,
}

impl<H: VmmHostCore + ?Sized> CoreWasmCtx<H> {
    pub fn new(host: Arc<H>, memory: SharedMemory) -> Self {
        Self {
            host,
            memory,
            last_error: String::new(),
        }
    }

    fn set_err(&mut self, msg: impl Into<String>) -> i32 {
        self.last_error = msg.into();
        ERR_GENERIC
    }

    fn set_err_i64(&mut self, msg: impl Into<String>) -> i64 {
        self.set_err(msg) as i64
    }

    fn set_hv_err(&mut self, e: HvError) -> i32 {
        match e {
            HvError::StdIo { source } => self.set_io_err(source),
            other => self.set_err(other.to_string()),
        }
    }

    fn set_hv_err_i64(&mut self, e: HvError) -> i64 {
        self.set_hv_err(e) as i64
    }

    fn set_io_err(&mut self, e: std::io::Error) -> i32 {
        match e.kind() {
            std::io::ErrorKind::WouldBlock => ERR_WOULD_BLOCK,
            std::io::ErrorKind::Interrupted => ERR_INTERRUPTED,
            _ => self.set_err(e.to_string()),
        }
    }
}

fn check_bounds(mem: &SharedMemory, ptr: u32, len: usize) -> Result<usize, String> {
    let start = ptr as usize;
    let end = start
        .checked_add(len)
        .ok_or_else(|| "guest memory address overflow".to_string())?;
    if end > mem.data().len() {
        return Err(format!(
            "guest memory access out of bounds: {start}..{end} > {}",
            mem.data().len()
        ));
    }
    Ok(start)
}

fn write_bytes(mem: &SharedMemory, ptr: u32, src: &[u8]) -> Result<(), String> {
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

fn read_struct<T: FromBytes + Copy>(mem: &SharedMemory, ptr: u32) -> Result<T, String> {
    let size = std::mem::size_of::<T>();
    let start = check_bounds(mem, ptr, size)?;
    let bytes =
        unsafe { std::slice::from_raw_parts(mem.data().as_ptr().add(start) as *const u8, size) };
    T::read_from(bytes).ok_or_else(|| "failed to decode struct from guest memory".to_string())
}

fn write_struct<T: AsBytes>(mem: &SharedMemory, ptr: u32, val: &T) -> Result<(), String> {
    write_bytes(mem, ptr, val.as_bytes())
}

fn read_vec<T: FromBytes + Copy>(
    mem: &SharedMemory,
    ptr: u32,
    count: u32,
) -> Result<Vec<T>, String> {
    let elem_size = std::mem::size_of::<T>();
    let _total = (count as usize)
        .checked_mul(elem_size)
        .ok_or_else(|| "slice byte length overflow".to_string())?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let item_ptr = (ptr as usize + i * elem_size) as u32;
        out.push(read_struct::<T>(mem, item_ptr)?);
    }
    Ok(out)
}

/// Register all `"vmm"::*` imports for `vmm-core` against any [`VmmHostCore`] implementation.
pub fn register_core_imports<T, H>(
    linker: &mut Linker<T>,
    get_ctx: impl Fn(&mut T) -> &mut CoreWasmCtx<H> + Copy + Send + Sync + 'static,
) -> wasmtime::Result<()>
where
    T: Send + 'static,
    H: VmmHostCore + ?Sized,
{
    linker.func_wrap(
        "vmm",
        "vmm_last_error_len",
        move |mut caller: Caller<'_, T>| -> u32 { get_ctx(caller.data_mut()).last_error.len() as u32 },
    )?;

    linker.func_wrap(
        "vmm",
        "vmm_last_error_read",
        move |mut caller: Caller<'_, T>, dst_ptr: u32, dst_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let err_bytes = ctx.last_error.as_bytes();
            let n = err_bytes.len().min(dst_len as usize);
            if write_bytes(&ctx.memory, dst_ptr, &err_bytes[..n]).is_err() {
                return ERR_GENERIC;
            }
            n as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "hv_new",
        move |mut caller: Caller<'_, T>| -> i64 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.hv_new() {
                Ok(hv) => hv as i64,
                Err(e) => ctx.set_hv_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "hv_get_supported_cpuids",
        move |mut caller: Caller<'_, T>, hv: Handle, dst_ptr: u32, max_entries: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let cpuids = match ctx.host.hv_get_supported_cpuids(hv) {
                Ok(c) => c,
                Err(e) => return ctx.set_hv_err(e),
            };
            let count = cpuids.len().min(max_entries as usize);
            let elem_size = std::mem::size_of::<RawCpuid>();
            for (i, cpuid) in cpuids.into_iter().take(count).enumerate() {
                let raw = RawCpuid::from(cpuid);
                if let Err(e) = write_struct(&ctx.memory, dst_ptr + (i * elem_size) as u32, &raw) {
                    return ctx.set_err(e);
                }
            }
            count as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "hv_create_vm",
        move |mut caller: Caller<'_, T>, hv: Handle| -> i64 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.hv_create_vm(hv) {
                Ok(id) => id as i64,
                Err(e) => ctx.set_hv_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "hv_close",
        move |mut caller: Caller<'_, T>, hv: Handle| {
            get_ctx(caller.data_mut()).host.hv_close(hv);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_create_vcpu",
        move |mut caller: Caller<'_, T>, vm: Handle, id: u32| -> i64 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.vm_create_vcpu(vm, id) {
                Ok(handle) => handle as i64,
                Err(e) => ctx.set_hv_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_stop_vcpu",
        move |mut caller: Caller<'_, T>, vm: Handle, id: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.vm_stop_vcpu(vm, id) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_create_vm_memory",
        move |mut caller: Caller<'_, T>, vm: Handle| -> i64 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.vm_create_vm_memory(vm) {
                Ok(handle) => handle as i64,
                Err(e) => ctx.set_hv_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_create_intx_sender",
        move |mut caller: Caller<'_, T>, vm: Handle, pin: u32| -> i64 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.vm_create_intx_sender(vm, pin as u8) {
                Ok(handle) => handle as i64,
                Err(e) => ctx.set_hv_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_create_msi_sender",
        move |mut caller: Caller<'_, T>, vm: Handle| -> i64 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.vm_create_msi_sender(vm) {
                Ok(handle) => handle as i64,
                Err(e) => ctx.set_hv_err_i64(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_close",
        move |mut caller: Caller<'_, T>, vm: Handle| {
            get_ctx(caller.data_mut()).host.vm_close(vm);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_run",
        move |mut caller: Caller<'_, T>,
              vcpu: Handle,
              entry_kind: u32,
              entry_data: u64,
              exit_out_ptr: u32|
              -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let entry = decode_vm_entry(entry_kind, entry_data);
            let exit = match ctx.host.vcpu_run(vcpu, entry) {
                Ok(exit) => exit,
                Err(e) => return ctx.set_hv_err(e),
            };
            let raw_exit = match exit {
                VmExit::Io { port, write, size } => RawVmExit {
                    addr_or_port: port as u64,
                    data: write.unwrap_or(0) as u64,
                    kind: EXIT_IO,
                    is_write: u8::from(write.is_some()),
                    size,
                    _pad: [0; 2],
                },
                VmExit::Mmio { addr, write, size } => RawVmExit {
                    addr_or_port: addr,
                    data: write.unwrap_or(0),
                    kind: EXIT_MMIO,
                    is_write: u8::from(write.is_some()),
                    size,
                    _pad: [0; 2],
                },
                VmExit::Shutdown => RawVmExit {
                    kind: EXIT_SHUTDOWN,
                    ..Default::default()
                },
                VmExit::Reboot => RawVmExit {
                    kind: EXIT_REBOOT,
                    ..Default::default()
                },
                VmExit::Interrupted => RawVmExit {
                    kind: EXIT_INTERRUPTED,
                    ..Default::default()
                },
                VmExit::Unknown(msg) => {
                    let _ = ctx.set_err(msg);
                    RawVmExit {
                        kind: EXIT_UNKNOWN,
                        ..Default::default()
                    }
                }
            };
            if let Err(e) = write_struct(&ctx.memory, exit_out_ptr, &raw_exit) {
                return ctx.set_err(e);
            }
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_reg",
        move |mut caller: Caller<'_, T>, vcpu: Handle, reg: u32, val_out_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let val = match ctx.host.vcpu_get_reg(vcpu, reg_from_u32(reg)) {
                Ok(v) => v,
                Err(e) => return ctx.set_hv_err(e),
            };
            match write_struct(&ctx.memory, val_out_ptr, &val) {
                Ok(()) => 0,
                Err(e) => ctx.set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_set_regs",
        move |mut caller: Caller<'_, T>, vcpu: Handle, vals_ptr: u32, vals_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let raw_vals = match read_vec::<RawRegVal>(&ctx.memory, vals_ptr, vals_len) {
                Ok(v) => v,
                Err(e) => return ctx.set_err(e),
            };
            let vals: Vec<_> = raw_vals
                .into_iter()
                .map(|r| (reg_from_u32(r.reg), r.val))
                .collect();
            match ctx.host.vcpu_set_regs(vcpu, &vals) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_seg_reg",
        move |mut caller: Caller<'_, T>, vcpu: Handle, reg: u32, val_out_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let val = match ctx.host.vcpu_get_seg_reg(vcpu, seg_reg_from_u32(reg)) {
                Ok(v) => v,
                Err(e) => return ctx.set_hv_err(e),
            };
            let raw = RawSegRegVal::from(val);
            match write_struct(&ctx.memory, val_out_ptr, &raw) {
                Ok(()) => 0,
                Err(e) => ctx.set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_dt_reg",
        move |mut caller: Caller<'_, T>, vcpu: Handle, reg: u32, val_out_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let val = match ctx.host.vcpu_get_dt_reg(vcpu, dt_reg_from_u32(reg)) {
                Ok(v) => v,
                Err(e) => return ctx.set_hv_err(e),
            };
            let raw = RawDtRegVal::from(val);
            match write_struct(&ctx.memory, val_out_ptr, &raw) {
                Ok(()) => 0,
                Err(e) => ctx.set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_sreg",
        move |mut caller: Caller<'_, T>, vcpu: Handle, reg: u32, val_out_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let val = match ctx.host.vcpu_get_sreg(vcpu, sreg_from_u32(reg)) {
                Ok(v) => v,
                Err(e) => return ctx.set_hv_err(e),
            };
            match write_struct(&ctx.memory, val_out_ptr, &val) {
                Ok(()) => 0,
                Err(e) => ctx.set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_set_sregs",
        move |mut caller: Caller<'_, T>,
              vcpu: Handle,
              sregs_ptr: u32,
              sregs_len: u32,
              seg_regs_ptr: u32,
              seg_regs_len: u32,
              dt_regs_ptr: u32,
              dt_regs_len: u32|
              -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let raw_sregs = match read_vec::<RawRegVal>(&ctx.memory, sregs_ptr, sregs_len) {
                Ok(v) => v,
                Err(e) => return ctx.set_err(e),
            };
            let raw_seg_regs =
                match read_vec::<RawSegRegEntry>(&ctx.memory, seg_regs_ptr, seg_regs_len) {
                    Ok(v) => v,
                    Err(e) => return ctx.set_err(e),
                };
            let raw_dt_regs =
                match read_vec::<RawDtRegEntry>(&ctx.memory, dt_regs_ptr, dt_regs_len) {
                    Ok(v) => v,
                    Err(e) => return ctx.set_err(e),
                };
            let sregs: Vec<_> = raw_sregs
                .into_iter()
                .map(|r| (sreg_from_u32(r.reg), r.val))
                .collect();
            let seg_regs: Vec<_> = raw_seg_regs
                .into_iter()
                .map(|r| (seg_reg_from_u32(r.reg), SegRegVal::from(r.val)))
                .collect();
            let dt_regs: Vec<_> = raw_dt_regs
                .into_iter()
                .map(|r| (dt_reg_from_u32(r.reg), DtRegVal::from(r.val)))
                .collect();
            match ctx.host.vcpu_set_sregs(vcpu, &sregs, &seg_regs, &dt_regs) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_set_cpuids",
        move |mut caller: Caller<'_, T>, vcpu: Handle, cpuids_ptr: u32, cpuids_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let raw_cpuids = match read_vec::<RawCpuid>(&ctx.memory, cpuids_ptr, cpuids_len) {
                Ok(v) => v,
                Err(e) => return ctx.set_err(e),
            };
            let cpuids = raw_cpuids.into_iter().map(Into::into).collect();
            match ctx.host.vcpu_set_cpuids(vcpu, cpuids) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_dump",
        move |mut caller: Caller<'_, T>, vcpu: Handle| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.vcpu_dump(vcpu) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_close",
        move |mut caller: Caller<'_, T>, vcpu: Handle| {
            get_ctx(caller.data_mut()).host.vcpu_close(vcpu);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_mem_map",
        move |mut caller: Caller<'_, T>,
              mem: Handle,
              slot: u32,
              gpa: u64,
              size: u64,
              hva: u64,
              flags: u32|
              -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.vm_memory_mem_map(
                mem,
                slot,
                gpa,
                size,
                hva,
                mem_map_option_from_u32(flags),
            ) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_unmap",
        move |mut caller: Caller<'_, T>, mem: Handle, slot: u32, gpa: u64, size: u64| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.vm_memory_unmap(mem, slot, gpa, size) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_max_mem_slots",
        move |mut caller: Caller<'_, T>, mem: Handle, out_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let slots = match ctx.host.vm_memory_max_mem_slots(mem) {
                Ok(s) => s,
                Err(e) => return ctx.set_hv_err(e),
            };
            match write_struct(&ctx.memory, out_ptr, &slots) {
                Ok(()) => 0,
                Err(e) => ctx.set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_register_encrypted_range",
        move |mut caller: Caller<'_, T>, mem: Handle, addr: u64, size: u64| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.vm_memory_register_encrypted_range(mem, addr, size) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_deregister_encrypted_range",
        move |mut caller: Caller<'_, T>, mem: Handle, addr: u64, size: u64| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx
                .host
                .vm_memory_deregister_encrypted_range(mem, addr, size)
            {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_alloc_anon_mem",
        move |mut caller: Caller<'_, T>,
              mem: Handle,
              size: u64,
              addr_out_ptr: u32,
              size_out_ptr: u32|
              -> i64 {
            let ctx = get_ctx(caller.data_mut());
            let (handle, addr, actual_size) = match ctx.host.vm_memory_alloc_anon_mem(mem, size) {
                Ok(v) => v,
                Err(e) => return ctx.set_hv_err_i64(e),
            };
            if let Err(e) = write_struct(&ctx.memory, addr_out_ptr, &addr)
                .and_then(|_| write_struct(&ctx.memory, size_out_ptr, &actual_size))
            {
                ctx.host.mem_pages_close(handle);
                return ctx.set_err_i64(e);
            }
            handle as i64
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_close",
        move |mut caller: Caller<'_, T>, mem: Handle| {
            get_ctx(caller.data_mut()).host.vm_memory_close(mem);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_pages_sync",
        move |mut caller: Caller<'_, T>, pages: Handle| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.mem_pages_sync(pages) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_pages_read",
        move |mut caller: Caller<'_, T>, pages: Handle, offset: u64, dst_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            let res = ctx.host.mem_pages_read(pages, offset, dst);
            match res {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_pages_write",
        move |mut caller: Caller<'_, T>, pages: Handle, offset: u64, src_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let src = unsafe {
                std::slice::from_raw_parts(
                    ctx.memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            let res = ctx.host.mem_pages_write(pages, offset, src);
            match res {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_pages_close",
        move |mut caller: Caller<'_, T>, pages: Handle| {
            get_ctx(caller.data_mut()).host.mem_pages_close(pages);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "intx_sender_send",
        move |mut caller: Caller<'_, T>, sender: Handle| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.intx_sender_send(sender) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "intx_sender_close",
        move |mut caller: Caller<'_, T>, sender: Handle| {
            get_ctx(caller.data_mut()).host.intx_sender_close(sender);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "msi_sender_send",
        move |mut caller: Caller<'_, T>, sender: Handle, addr: u64, data: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.msi_sender_send(sender, addr, data) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "msi_sender_close",
        move |mut caller: Caller<'_, T>, sender: Handle| {
            get_ctx(caller.data_mut()).host.msi_sender_close(sender);
        },
    )?;

    // --- Cross-Split Core <-> IO Bridge Imports ---
    linker.func_wrap(
        "vmm",
        "core_get_boot_info",
        move |mut caller: Caller<'_, T>,
              boot_info_out_ptr: u32,
              devs_out_ptr: u32,
              max_devs: u32|
              -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let (boot_info, specs) = match ctx.host.core_get_boot_info() {
                Ok(v) => v,
                Err(e) => return ctx.set_hv_err(e),
            };
            let mut raw_info = ShmBootInfo {
                num_cpus: boot_info.num_cpus,
                exec_type: match boot_info.exec_type {
                    Some(vmm_core::loader::ExecType::Linux) => {
                        vmm_core::host::abi::EXEC_TYPE_LINUX
                    }
                    Some(vmm_core::loader::ExecType::Pvh) => vmm_core::host::abi::EXEC_TYPE_PVH,
                    None => vmm_core::host::abi::EXEC_TYPE_NONE,
                },
                mem_size: boot_info.mem_size as u64,
                kernel_size: boot_info.kernel_size,
                initramfs_size: boot_info.initramfs_size.unwrap_or(0),
                num_virtio_devs: specs.len() as u32,
                cmd_line_len: 0,
                cmd_line: [0; vmm_core::host::abi::MAX_CMDLINE_LEN],
            };
            if let Some(cmd) = &boot_info.cmd_line {
                let bytes = cmd.as_bytes();
                let n = bytes.len().min(raw_info.cmd_line.len());
                raw_info.cmd_line[..n].copy_from_slice(&bytes[..n]);
                raw_info.cmd_line_len = n as u32;
            }
            if let Err(e) = write_struct(&ctx.memory, boot_info_out_ptr, &raw_info) {
                return ctx.set_err(e);
            }
            let count = specs.len().min(max_devs as usize).min(MAX_VIRTIO_DEVS);
            let elem_size = std::mem::size_of::<ShmVirtioDeviceSpec>();
            for (i, spec) in specs.into_iter().take(count).enumerate() {
                let mut raw_spec = ShmVirtioDeviceSpec {
                    dev: spec.dev,
                    device_features: spec.device_features,
                    device_id: spec.device_id,
                    num_queues: spec.num_queues,
                    config_len: 0,
                    name_len: 0,
                    name: [0; vmm_core::host::abi::MAX_DEV_NAME_LEN],
                    config_bytes: [0; vmm_core::host::abi::MAX_CONFIG_BYTES],
                };
                let name_bytes = spec.name.as_bytes();
                let nlen = name_bytes.len().min(raw_spec.name.len());
                raw_spec.name[..nlen].copy_from_slice(&name_bytes[..nlen]);
                raw_spec.name_len = nlen as u16;
                let clen = spec.config_bytes.len().min(raw_spec.config_bytes.len());
                raw_spec.config_bytes[..clen].copy_from_slice(&spec.config_bytes[..clen]);
                raw_spec.config_len = clen as u16;
                if let Err(e) = write_struct(
                    &ctx.memory,
                    devs_out_ptr + (i * elem_size) as u32,
                    &raw_spec,
                ) {
                    return ctx.set_err(e);
                }
            }
            count as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_read_payload",
        move |mut caller: Caller<'_, T>, kind: u32, offset: u64, dst_ptr: u32, len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let pkind = if kind == 0 {
                PayloadKind::Kernel
            } else {
                PayloadKind::Initramfs
            };
            let start = match check_bounds(&ctx.memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            let res = ctx.host.core_read_payload(pkind, offset, dst);
            match res {
                Ok(n) => n as i32,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_virtio_start",
        move |mut caller: Caller<'_, T>,
              dev: Handle,
              driver_features: u64,
              queues_ptr: u32,
              num_queues: u32|
              -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let raw_queues =
                match read_vec::<ShmVirtioQueueConfig>(&ctx.memory, queues_ptr, num_queues) {
                    Ok(q) => q,
                    Err(e) => return ctx.set_err(e),
                };
            let queues: Vec<VirtioQueueConfig> = raw_queues.into_iter().map(Into::into).collect();
            match ctx.host.core_virtio_start(dev, driver_features, &queues) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_virtio_notify",
        move |mut caller: Caller<'_, T>, dev: Handle, queue_index: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.core_virtio_notify(dev, queue_index as u16) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_virtio_reset",
        move |mut caller: Caller<'_, T>, dev: Handle| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.core_virtio_reset(dev) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_virtio_update_irq",
        move |mut caller: Caller<'_, T>, dev: Handle, routing_ptr: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let routing = match read_struct::<ShmDeviceMsixRouting>(&ctx.memory, routing_ptr) {
                Ok(r) => r,
                Err(e) => return ctx.set_err(e),
            };
            let config_msi = if routing.config_msi.enabled != 0 {
                Some((routing.config_msi.addr, routing.config_msi.data))
            } else {
                None
            };
            let queue_msis: Vec<Option<(u64, u32)>> = routing
                .queue_msis
                .iter()
                .map(|m| {
                    if m.enabled != 0 {
                        Some((m.addr, m.data))
                    } else {
                        None
                    }
                })
                .collect();
            match ctx.host.core_virtio_update_irq(dev, config_msi, &queue_msis) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_serial_tx",
        move |mut caller: Caller<'_, T>, byte: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.core_serial_tx(byte as u8) {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_serial_rx",
        move |mut caller: Caller<'_, T>, dst_ptr: u32, max_len: u32| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            let start = match check_bounds(&ctx.memory, dst_ptr, max_len as usize) {
                Ok(s) => s,
                Err(e) => return ctx.set_err(e),
            };
            let mut bytes = vec![0u8; max_len as usize];
            let count = match ctx.host.core_serial_rx(&mut bytes) {
                Ok(n) => n,
                Err(e) => return ctx.set_hv_err(e),
            };
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    ctx.memory.data().as_ptr().add(start) as *mut u8,
                    count,
                );
            }
            count as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_notify_shutdown",
        move |mut caller: Caller<'_, T>| -> i32 {
            let ctx = get_ctx(caller.data_mut());
            match ctx.host.core_notify_shutdown() {
                Ok(()) => 0,
                Err(e) => ctx.set_hv_err(e),
            }
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

struct CoreStoreState<H: VmmHostCore + ?Sized> {
    wasi: WasiP1Ctx,
    core: CoreWasmCtx<H>,
}

/// Instantiate and execute `vmm-core` against any [`VmmHostCore`] implementation.
pub fn run_wasm_core<H: VmmHostCore + ?Sized>(
    module_path: &Path,
    host: Arc<H>,
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
            core: CoreWasmCtx::new(host, shared_memory.clone()),
        },
    );

    let mut linker = Linker::<CoreStoreState<H>>::new(&engine);
    linker.define(&store, "env", "memory", shared_memory)?;
    p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;
    register_core_imports(&mut linker, |state| &mut state.core)?;

    let next_tid = Arc::new(AtomicI32::new(1));
    let spawn_engine = engine.clone();
    let spawn_module = module.clone();

    let spawn_linker_slot: Arc<RwLock<Option<Linker<CoreStoreState<H>>>>> =
        Arc::new(RwLock::new(None));
    let spawn_linker_ref = spawn_linker_slot.clone();

    linker.func_wrap(
        "wasi",
        "thread-spawn",
        move |caller: Caller<'_, CoreStoreState<H>>, start_arg: i32| -> i32 {
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
            let child_host = caller.data().core.host.clone();
            let memory = caller.data().core.memory.clone();

            let spawn_res = std::thread::Builder::new()
                .name(format!("core_wasm_thread_{tid}"))
                .spawn(move || {
                    let mut child_store = Store::new(
                        &engine,
                        CoreStoreState {
                            wasi: wasi_ctx,
                            core: CoreWasmCtx::new(child_host, memory),
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
