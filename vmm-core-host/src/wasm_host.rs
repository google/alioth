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

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use parking_lot::{Mutex, RwLock};
use vmm_core::host::abi::{
    ERR_GENERIC, ERR_INTERRUPTED, ERR_WOULD_BLOCK, EXIT_INTERRUPTED, EXIT_IO, EXIT_MMIO,
    EXIT_REBOOT, EXIT_SHUTDOWN, EXIT_UNKNOWN, MAX_QUEUES_PER_DEV, MAX_VIRTIO_DEVS, RawCpuid,
    RawDtRegEntry, RawDtRegVal, RawRegVal, RawSegRegEntry, RawSegRegVal, RawVmExit,
    ShmDeviceMsixRouting, ShmVirtioQueueConfig, decode_vm_entry, dt_reg_from_u32,
    mem_map_option_from_u32, reg_from_u32, seg_reg_from_u32, sreg_from_u32, spin_lock, spin_unlock,
};
use vmm_core::host::{
    DtRegVal, Handle, Hypervisor, IntxSender, MemPages, MsiSender, PayloadKind, SegRegVal, Vcpu,
    VirtioQueueConfig, Vm, VmExit, VmMemory,
};
use wasmtime::{
    Caller, Config, Engine, ExternType, Linker, MemoryType, Module, SharedMemory, Store,
};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{I32Exit, WasiCtxBuilder};
use zerocopy::{AsBytes, FromBytes};

use crate::kvm::{CoreBridgeFds, Kvm, SharedCoreBridge};

struct ResourceTable<T: ?Sized> {
    next_id: AtomicU32,
    items: RwLock<HashMap<u32, Arc<T>>>,
}

impl<T: ?Sized> Default for ResourceTable<T> {
    fn default() -> Self {
        Self {
            next_id: AtomicU32::new(1),
            items: RwLock::new(HashMap::new()),
        }
    }
}

impl<T> ResourceTable<T> {
    fn insert(&self, val: T) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.items.write().insert(id, Arc::new(val));
        id
    }
}

impl<T: ?Sized> ResourceTable<T> {
    fn insert_arc(&self, val: Arc<T>) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.items.write().insert(id, val);
        id
    }

    fn get(&self, id: u32) -> Result<Arc<T>, String> {
        self.items
            .read()
            .get(&id)
            .cloned()
            .ok_or_else(|| format!("invalid resource handle {id}"))
    }

    fn remove(&self, id: u32) {
        self.items.write().remove(&id);
    }
}

struct SharedCoreHostResources {
    bridge: Arc<SharedCoreBridge>,
    hypervisors: ResourceTable<Kvm>,
    vms: ResourceTable<RwLock<Box<dyn Vm>>>,
    vcpus: ResourceTable<Mutex<Box<dyn Vcpu>>>,
    vm_memories: ResourceTable<Box<dyn VmMemory>>,
    mem_pages: ResourceTable<dyn MemPages>,
    intx_senders: ResourceTable<Box<dyn IntxSender>>,
    msi_senders: ResourceTable<Box<dyn MsiSender>>,
}

impl SharedCoreHostResources {
    fn new(bridge: Arc<SharedCoreBridge>) -> Self {
        Self {
            bridge,
            hypervisors: ResourceTable::default(),
            vms: ResourceTable::default(),
            vcpus: ResourceTable::default(),
            vm_memories: ResourceTable::default(),
            mem_pages: ResourceTable::default(),
            intx_senders: ResourceTable::default(),
            msi_senders: ResourceTable::default(),
        }
    }
}

fn build_core_wasi() -> wasmtime::Result<WasiP1Ctx> {
    let mut builder = WasiCtxBuilder::new();
    builder
        .allow_blocking_current_thread(true)
        .inherit_stdio()
        .args(&["vmm-core"]);
    Ok(builder.build_p1())
}

pub struct ThreadHostState {
    wasi: WasiP1Ctx,
    shared: Arc<SharedCoreHostResources>,
    memory: SharedMemory,
    last_error: String,
}

impl ThreadHostState {
    fn set_err(&mut self, msg: impl Into<String>) -> i32 {
        self.last_error = msg.into();
        ERR_GENERIC
    }

    fn set_io_err(&mut self, e: std::io::Error) -> i32 {
        match e.kind() {
            std::io::ErrorKind::WouldBlock => ERR_WOULD_BLOCK,
            std::io::ErrorKind::Interrupted => ERR_INTERRUPTED,
            _ => {
                self.last_error = e.to_string();
                ERR_GENERIC
            }
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

fn register_core_imports(linker: &mut Linker<ThreadHostState>) -> wasmtime::Result<()> {
    linker.func_wrap(
        "vmm",
        "vmm_last_error_len",
        |caller: Caller<'_, ThreadHostState>| -> u32 { caller.data().last_error.len() as u32 },
    )?;

    linker.func_wrap(
        "vmm",
        "vmm_last_error_read",
        |caller: Caller<'_, ThreadHostState>, dst_ptr: u32, dst_len: u32| -> i32 {
            let err_bytes = caller.data().last_error.as_bytes();
            let n = err_bytes.len().min(dst_len as usize);
            if write_bytes(&caller.data().memory, dst_ptr, &err_bytes[..n]).is_err() {
                return ERR_GENERIC;
            }
            n as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "hv_new",
        |mut caller: Caller<'_, ThreadHostState>| -> i32 {
            let bridge = caller.data().shared.bridge.clone();
            match Kvm::new(bridge) {
                Ok(kvm) => caller.data().shared.hypervisors.insert(kvm) as i32,
                Err(e) => caller.data_mut().set_err(e.to_string()),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "hv_get_supported_cpuids",
        |mut caller: Caller<'_, ThreadHostState>, hv: u32, dst_ptr: u32, max_entries: u32| -> i32 {
            let res = (|| -> Result<u32, String> {
                let hv_obj = caller.data().shared.hypervisors.get(hv)?;
                let cpuids = hv_obj.get_supported_cpuids().map_err(|e| e.to_string())?;
                let count = cpuids.len().min(max_entries as usize);
                let elem_size = std::mem::size_of::<RawCpuid>();
                for (i, cpuid) in cpuids.into_iter().take(count).enumerate() {
                    let raw = RawCpuid::from(cpuid);
                    write_struct(
                        &caller.data().memory,
                        dst_ptr + (i * elem_size) as u32,
                        &raw,
                    )?;
                }
                Ok(count as u32)
            })();
            match res {
                Ok(n) => n as i32,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "hv_create_vm",
        |mut caller: Caller<'_, ThreadHostState>, hv: u32| -> i32 {
            let res = (|| -> Result<u32, String> {
                let hv_obj = caller.data().shared.hypervisors.get(hv)?;
                let vm = hv_obj.create_vm().map_err(|e| e.to_string())?;
                Ok(caller.data().shared.vms.insert(RwLock::new(vm)))
            })();
            match res {
                Ok(id) => id as i32,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "hv_close",
        |caller: Caller<'_, ThreadHostState>, hv: u32| {
            caller.data().shared.hypervisors.remove(hv);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_create_vcpu",
        |mut caller: Caller<'_, ThreadHostState>, vm: u32, id: u32| -> i32 {
            let res = (|| -> Result<u32, String> {
                let vm_obj = caller.data().shared.vms.get(vm)?;
                let vcpu = vm_obj.read().create_vcpu(id).map_err(|e| e.to_string())?;
                Ok(caller.data().shared.vcpus.insert(Mutex::new(vcpu)))
            })();
            match res {
                Ok(handle) => handle as i32,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_stop_vcpu",
        |mut caller: Caller<'_, ThreadHostState>, vm: u32, id: u32| -> i32 {
            let res = (|| -> Result<(), String> {
                let vm_obj = caller.data().shared.vms.get(vm)?;
                vm_obj.read().stop_vcpu(id).map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_create_vm_memory",
        |mut caller: Caller<'_, ThreadHostState>, vm: u32| -> i32 {
            let res = (|| -> Result<u32, String> {
                let vm_obj = caller.data().shared.vms.get(vm)?;
                let mem = vm_obj
                    .write()
                    .create_vm_memory()
                    .map_err(|e| e.to_string())?;
                Ok(caller.data().shared.vm_memories.insert(mem))
            })();
            match res {
                Ok(handle) => handle as i32,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_create_intx_sender",
        |mut caller: Caller<'_, ThreadHostState>, vm: u32, pin: u32| -> i32 {
            let res = (|| -> Result<u32, String> {
                let vm_obj = caller.data().shared.vms.get(vm)?;
                let sender = vm_obj
                    .read()
                    .create_intx_sender(pin as u8)
                    .map_err(|e| e.to_string())?;
                Ok(caller.data().shared.intx_senders.insert(sender))
            })();
            match res {
                Ok(handle) => handle as i32,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_create_msi_sender",
        |mut caller: Caller<'_, ThreadHostState>, vm: u32| -> i32 {
            let res = (|| -> Result<u32, String> {
                let vm_obj = caller.data().shared.vms.get(vm)?;
                let sender = vm_obj
                    .read()
                    .create_msi_sender()
                    .map_err(|e| e.to_string())?;
                Ok(caller.data().shared.msi_senders.insert(sender))
            })();
            match res {
                Ok(handle) => handle as i32,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_close",
        |caller: Caller<'_, ThreadHostState>, vm: u32| {
            caller.data().shared.vms.remove(vm);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_run",
        |mut caller: Caller<'_, ThreadHostState>,
         vcpu: u32,
         entry_kind: u32,
         entry_data: u64,
         exit_out_ptr: u32|
         -> i32 {
            let vcpu_obj = match caller.data().shared.vcpus.get(vcpu) {
                Ok(v) => v,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let entry = decode_vm_entry(entry_kind, entry_data);
            let exit = match vcpu_obj.lock().run(entry) {
                Ok(exit) => exit,
                Err(e) => return caller.data_mut().set_err(e.to_string()),
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
                    caller.data_mut().last_error = msg;
                    RawVmExit {
                        kind: EXIT_UNKNOWN,
                        ..Default::default()
                    }
                }
            };
            if let Err(e) = write_struct(&caller.data().memory, exit_out_ptr, &raw_exit) {
                return caller.data_mut().set_err(e);
            }
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_reg",
        |mut caller: Caller<'_, ThreadHostState>,
         vcpu: u32,
         reg: u32,
         val_out_ptr: u32|
         -> i32 {
            let res = (|| -> Result<(), String> {
                let vcpu_obj = caller.data().shared.vcpus.get(vcpu)?;
                let val = vcpu_obj
                    .lock()
                    .get_reg(reg_from_u32(reg))
                    .map_err(|e| e.to_string())?;
                write_struct(&caller.data().memory, val_out_ptr, &val)
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_set_regs",
        |mut caller: Caller<'_, ThreadHostState>,
         vcpu: u32,
         vals_ptr: u32,
         vals_len: u32|
         -> i32 {
            let res = (|| -> Result<(), String> {
                let raw_vals = read_vec::<RawRegVal>(&caller.data().memory, vals_ptr, vals_len)?;
                let vals: Vec<_> = raw_vals
                    .into_iter()
                    .map(|r| (reg_from_u32(r.reg), r.val))
                    .collect();
                let vcpu_obj = caller.data().shared.vcpus.get(vcpu)?;
                vcpu_obj.lock().set_regs(&vals).map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_seg_reg",
        |mut caller: Caller<'_, ThreadHostState>,
         vcpu: u32,
         reg: u32,
         val_out_ptr: u32|
         -> i32 {
            let res = (|| -> Result<(), String> {
                let vcpu_obj = caller.data().shared.vcpus.get(vcpu)?;
                let val = vcpu_obj
                    .lock()
                    .get_seg_reg(seg_reg_from_u32(reg))
                    .map_err(|e| e.to_string())?;
                let raw = RawSegRegVal::from(val);
                write_struct(&caller.data().memory, val_out_ptr, &raw)
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_dt_reg",
        |mut caller: Caller<'_, ThreadHostState>,
         vcpu: u32,
         reg: u32,
         val_out_ptr: u32|
         -> i32 {
            let res = (|| -> Result<(), String> {
                let vcpu_obj = caller.data().shared.vcpus.get(vcpu)?;
                let val = vcpu_obj
                    .lock()
                    .get_dt_reg(dt_reg_from_u32(reg))
                    .map_err(|e| e.to_string())?;
                let raw = RawDtRegVal::from(val);
                write_struct(&caller.data().memory, val_out_ptr, &raw)
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_get_sreg",
        |mut caller: Caller<'_, ThreadHostState>,
         vcpu: u32,
         reg: u32,
         val_out_ptr: u32|
         -> i32 {
            let res = (|| -> Result<(), String> {
                let vcpu_obj = caller.data().shared.vcpus.get(vcpu)?;
                let val = vcpu_obj
                    .lock()
                    .get_sreg(sreg_from_u32(reg))
                    .map_err(|e| e.to_string())?;
                write_struct(&caller.data().memory, val_out_ptr, &val)
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_set_sregs",
        |mut caller: Caller<'_, ThreadHostState>,
         vcpu: u32,
         sregs_ptr: u32,
         sregs_len: u32,
         seg_regs_ptr: u32,
         seg_regs_len: u32,
         dt_regs_ptr: u32,
         dt_regs_len: u32|
         -> i32 {
            let res = (|| -> Result<(), String> {
                let raw_sregs =
                    read_vec::<RawRegVal>(&caller.data().memory, sregs_ptr, sregs_len)?;
                let raw_seg_regs =
                    read_vec::<RawSegRegEntry>(&caller.data().memory, seg_regs_ptr, seg_regs_len)?;
                let raw_dt_regs =
                    read_vec::<RawDtRegEntry>(&caller.data().memory, dt_regs_ptr, dt_regs_len)?;
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
                let vcpu_obj = caller.data().shared.vcpus.get(vcpu)?;
                vcpu_obj
                    .lock()
                    .set_sregs(&sregs, &seg_regs, &dt_regs)
                    .map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_set_cpuids",
        |mut caller: Caller<'_, ThreadHostState>,
         vcpu: u32,
         cpuids_ptr: u32,
         cpuids_len: u32|
         -> i32 {
            let res = (|| -> Result<(), String> {
                let raw_cpuids =
                    read_vec::<RawCpuid>(&caller.data().memory, cpuids_ptr, cpuids_len)?;
                let cpuids = raw_cpuids.into_iter().map(Into::into).collect();
                let vcpu_obj = caller.data().shared.vcpus.get(vcpu)?;
                vcpu_obj
                    .lock()
                    .set_cpuids(cpuids)
                    .map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_dump",
        |mut caller: Caller<'_, ThreadHostState>, vcpu: u32| -> i32 {
            let res = (|| -> Result<(), String> {
                let vcpu_obj = caller.data().shared.vcpus.get(vcpu)?;
                vcpu_obj.lock().dump().map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vcpu_close",
        |caller: Caller<'_, ThreadHostState>, vcpu: u32| {
            caller.data().shared.vcpus.remove(vcpu);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_mem_map",
        |mut caller: Caller<'_, ThreadHostState>,
         mem: u32,
         slot: u32,
         gpa: u64,
         size: u64,
         hva: u64,
         flags: u32|
         -> i32 {
            let res = (|| -> Result<(), String> {
                let mem_obj = caller.data().shared.vm_memories.get(mem)?;
                mem_obj
                    .mem_map(
                        slot,
                        gpa,
                        size as usize,
                        hva,
                        mem_map_option_from_u32(flags),
                    )
                    .map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_unmap",
        |mut caller: Caller<'_, ThreadHostState>,
         mem: u32,
         slot: u32,
         gpa: u64,
         size: u64|
         -> i32 {
            let res = (|| -> Result<(), String> {
                let mem_obj = caller.data().shared.vm_memories.get(mem)?;
                mem_obj
                    .unmap(slot, gpa, size as usize)
                    .map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_max_mem_slots",
        |mut caller: Caller<'_, ThreadHostState>, mem: u32, out_ptr: u32| -> i32 {
            let res = (|| -> Result<(), String> {
                let mem_obj = caller.data().shared.vm_memories.get(mem)?;
                let slots = mem_obj.max_mem_slots().map_err(|e| e.to_string())?;
                write_struct(&caller.data().memory, out_ptr, &slots)
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_register_encrypted_range",
        |mut caller: Caller<'_, ThreadHostState>, mem: u32, addr: u64, size: u64| -> i32 {
            let res = (|| -> Result<(), String> {
                let mem_obj = caller.data().shared.vm_memories.get(mem)?;
                mem_obj
                    .register_encrypted_range(addr, size as usize)
                    .map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_deregister_encrypted_range",
        |mut caller: Caller<'_, ThreadHostState>, mem: u32, addr: u64, size: u64| -> i32 {
            let res = (|| -> Result<(), String> {
                let mem_obj = caller.data().shared.vm_memories.get(mem)?;
                mem_obj
                    .deregister_encrypted_range(addr, size as usize)
                    .map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_alloc_anon_mem",
        |mut caller: Caller<'_, ThreadHostState>,
         mem: u32,
         size: u64,
         addr_out_ptr: u32,
         size_out_ptr: u32|
         -> i32 {
            let mem_obj = match caller.data().shared.vm_memories.get(mem) {
                Ok(m) => m,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let pages = match mem_obj.alloc_anon_mem(size as usize) {
                Ok(p) => p,
                Err(e) => return caller.data_mut().set_io_err(e),
            };
            let addr = pages.addr();
            let actual_size = pages.size() as u64;
            if let Err(e) = write_struct(&caller.data().memory, addr_out_ptr, &addr)
                .and_then(|_| write_struct(&caller.data().memory, size_out_ptr, &actual_size))
            {
                return caller.data_mut().set_err(e);
            }
            caller.data().shared.mem_pages.insert_arc(pages) as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_memory_close",
        |caller: Caller<'_, ThreadHostState>, mem: u32| {
            caller.data().shared.vm_memories.remove(mem);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_pages_sync",
        |mut caller: Caller<'_, ThreadHostState>, pages: u32| -> i32 {
            let pages_obj = match caller.data().shared.mem_pages.get(pages) {
                Ok(p) => p,
                Err(e) => return caller.data_mut().set_err(e),
            };
            match pages_obj.sync() {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_pages_read",
        |mut caller: Caller<'_, ThreadHostState>,
         pages: u32,
         offset: u64,
         dst_ptr: u32,
         len: u32|
         -> i32 {
            let pages_obj = match caller.data().shared.mem_pages.get(pages) {
                Ok(p) => p,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let start = match check_bounds(&caller.data().memory, dst_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    caller.data().memory.data().as_ptr().add(start) as *mut u8,
                    len as usize,
                )
            };
            match pages_obj.read(offset as usize, dst) {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_pages_write",
        |mut caller: Caller<'_, ThreadHostState>,
         pages: u32,
         offset: u64,
         src_ptr: u32,
         len: u32|
         -> i32 {
            let pages_obj = match caller.data().shared.mem_pages.get(pages) {
                Ok(p) => p,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let start = match check_bounds(&caller.data().memory, src_ptr, len as usize) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let src = unsafe {
                std::slice::from_raw_parts(
                    caller.data().memory.data().as_ptr().add(start) as *const u8,
                    len as usize,
                )
            };
            match pages_obj.write(offset as usize, src) {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "mem_pages_close",
        |caller: Caller<'_, ThreadHostState>, pages: u32| {
            caller.data().shared.mem_pages.remove(pages);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "intx_sender_send",
        |mut caller: Caller<'_, ThreadHostState>, sender: u32| -> i32 {
            let res = (|| -> Result<(), String> {
                let s = caller.data().shared.intx_senders.get(sender)?;
                s.send().map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "intx_sender_close",
        |caller: Caller<'_, ThreadHostState>, sender: u32| {
            caller.data().shared.intx_senders.remove(sender);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "msi_sender_send",
        |mut caller: Caller<'_, ThreadHostState>, sender: u32, addr: u64, data: u32| -> i32 {
            let res = (|| -> Result<(), String> {
                let s = caller.data().shared.msi_senders.get(sender)?;
                s.send(addr, data).map_err(|e| e.to_string())
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "msi_sender_close",
        |caller: Caller<'_, ThreadHostState>, sender: u32| {
            caller.data().shared.msi_senders.remove(sender);
        },
    )?;

    // --- Cross-Split Core <-> IO Bridge Imports ---
    linker.func_wrap(
        "vmm",
        "core_get_boot_info",
        |mut caller: Caller<'_, ThreadHostState>,
         boot_info_out_ptr: u32,
         devs_out_ptr: u32,
         max_devs: u32|
         -> i32 {
            let bridge = caller.data().shared.bridge.clone();
            if let Err(e) = bridge.ensure_mapped() {
                return caller.data_mut().set_err(e.to_string());
            }
            let shm = unsafe { &*bridge.shm };
            if let Err(e) = write_struct(&caller.data().memory, boot_info_out_ptr, &shm.boot_info) {
                return caller.data_mut().set_err(e);
            }
            let count = (shm.boot_info.num_virtio_devs as usize)
                .min(max_devs as usize)
                .min(MAX_VIRTIO_DEVS);
            let elem_size = std::mem::size_of::<vmm_core::host::abi::ShmVirtioDeviceSpec>();
            for i in 0..count {
                if let Err(e) = write_struct(
                    &caller.data().memory,
                    devs_out_ptr + (i * elem_size) as u32,
                    &shm.virtio_devs[i],
                ) {
                    return caller.data_mut().set_err(e);
                }
            }
            count as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_read_payload",
        |mut caller: Caller<'_, ThreadHostState>,
         kind: u32,
         offset: u64,
         dst_ptr: u32,
         len: u32|
         -> i32 {
            let bridge = caller.data().shared.bridge.clone();
            if let Err(e) = bridge.ensure_mapped() {
                return caller.data_mut().set_err(e.to_string());
            }
            let pkind = if kind == 0 {
                PayloadKind::Kernel
            } else {
                PayloadKind::Initramfs
            };
            let shm = unsafe { &*bridge.shm };
            let kernel_size = shm.boot_info.kernel_size;
            let initramfs_size = shm.boot_info.initramfs_size;
            let (base_off, total_size) = match pkind {
                PayloadKind::Kernel => (0u64, kernel_size),
                PayloadKind::Initramfs => (kernel_size, initramfs_size),
            };
            if offset >= total_size || len == 0 {
                return 0;
            }
            let avail = (total_size - offset) as usize;
            let to_read = (len as usize).min(avail);
            let pbase = bridge.payload_base.load(Ordering::Acquire) as usize;
            let plen = bridge.payload_len.load(Ordering::Acquire) as usize;
            let start = (base_off + offset) as usize;
            if pbase == 0 || start.checked_add(to_read).map_or(true, |end| end > plen) {
                return caller.data_mut().set_err("payload read out of bounds");
            }
            let src = unsafe { std::slice::from_raw_parts((pbase + start) as *const u8, to_read) };
            if let Err(e) = write_bytes(&caller.data().memory, dst_ptr, src) {
                return caller.data_mut().set_err(e);
            }
            to_read as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_virtio_start",
        |mut caller: Caller<'_, ThreadHostState>,
         dev: Handle,
         driver_features: u64,
         queues_ptr: u32,
         num_queues: u32|
         -> i32 {
            let raw_queues = match read_vec::<ShmVirtioQueueConfig>(
                &caller.data().memory,
                queues_ptr,
                num_queues,
            ) {
                Ok(q) => q,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let dev_idx = dev as usize;
            if dev_idx >= MAX_VIRTIO_DEVS {
                return caller
                    .data_mut()
                    .set_err(format!("invalid virtio dev handle {dev}"));
            }
            let bridge = caller.data().shared.bridge.clone();
            let shm = bridge.shm;
            let nq = raw_queues.len().min(MAX_QUEUES_PER_DEV);
            unsafe {
                for (i, q) in raw_queues.into_iter().enumerate().take(nq) {
                    (*shm).device_queues[dev_idx][i] = q;
                }
            }
            let entry = vmm_core::host::abi::CoreToIoEntry {
                msg_type: vmm_core::host::abi::CORE_MSG_VIRTIO_START,
                aux_u16: nq as u16,
                _pad: 0,
                dev,
                features: driver_features,
                data: [0; 40],
            };
            if unsafe { vmm_core::host::abi::BridgeShm::push_core_to_io(shm, entry) } {
                bridge.wake_io();
            }
            let _ = VirtioQueueConfig::default();
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_virtio_notify",
        |caller: Caller<'_, ThreadHostState>, dev: Handle, queue_index: u32| -> i32 {
            let bridge = &caller.data().shared.bridge;
            let shm = bridge.shm;
            let entry = vmm_core::host::abi::CoreToIoEntry {
                msg_type: vmm_core::host::abi::CORE_MSG_VIRTIO_NOTIFY,
                aux_u16: queue_index as u16,
                _pad: 0,
                dev,
                features: 0,
                data: [0; 40],
            };
            if unsafe { vmm_core::host::abi::BridgeShm::push_core_to_io(shm, entry) } {
                bridge.wake_io();
            }
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_virtio_reset",
        |caller: Caller<'_, ThreadHostState>, dev: Handle| -> i32 {
            let bridge = &caller.data().shared.bridge;
            let shm = bridge.shm;
            let entry = vmm_core::host::abi::CoreToIoEntry {
                msg_type: vmm_core::host::abi::CORE_MSG_VIRTIO_RESET,
                aux_u16: 0,
                _pad: 0,
                dev,
                features: 0,
                data: [0; 40],
            };
            if unsafe { vmm_core::host::abi::BridgeShm::push_core_to_io(shm, entry) } {
                bridge.wake_io();
            }
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_virtio_update_irq",
        |mut caller: Caller<'_, ThreadHostState>, dev: Handle, routing_ptr: u32| -> i32 {
            let routing = match read_struct::<ShmDeviceMsixRouting>(&caller.data().memory, routing_ptr)
            {
                Ok(r) => r,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let dev_idx = dev as usize;
            if dev_idx >= MAX_VIRTIO_DEVS {
                return caller
                    .data_mut()
                    .set_err(format!("invalid virtio dev handle {dev}"));
            }
            let shm = caller.data().shared.bridge.shm;
            let lock = unsafe { &(*shm).msix_lock };
            spin_lock(lock);
            unsafe {
                (*shm).msix_routing[dev_idx] = routing;
            }
            spin_unlock(lock);
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_serial_tx",
        |caller: Caller<'_, ThreadHostState>, byte: u32| -> i32 {
            let bridge = &caller.data().shared.bridge;
            let shm = bridge.shm;
            let mut data = [0u8; 40];
            data[0] = byte as u8;
            let entry = vmm_core::host::abi::CoreToIoEntry {
                msg_type: vmm_core::host::abi::CORE_MSG_SERIAL_TX,
                aux_u16: 1,
                _pad: 0,
                dev: 0,
                features: 0,
                data,
            };
            if unsafe { vmm_core::host::abi::BridgeShm::push_core_to_io(shm, entry) } {
                bridge.wake_io();
            }
            0
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_serial_rx",
        |mut caller: Caller<'_, ThreadHostState>, dst_ptr: u32, max_len: u32| -> i32 {
            let bridge = caller.data().shared.bridge.clone();
            let shm = bridge.shm;
            let mut rx = bridge.serial_rx.lock();
            while rx.is_empty() {
                if unsafe { (*shm).shutdown_requested.load(Ordering::Acquire) != 0 } {
                    return 0;
                }
                bridge.serial_rx_cv.wait(&mut rx);
            }
            let count = (max_len as usize).min(rx.len());
            let mut bytes = Vec::with_capacity(count);
            for _ in 0..count {
                bytes.push(rx.pop_front().unwrap());
            }
            drop(rx);
            if let Err(e) = write_bytes(&caller.data().memory, dst_ptr, &bytes) {
                return caller.data_mut().set_err(e);
            }
            count as i32
        },
    )?;

    linker.func_wrap(
        "vmm",
        "core_notify_shutdown",
        |caller: Caller<'_, ThreadHostState>| -> i32 {
            let bridge = &caller.data().shared.bridge;
            let shm = bridge.shm;
            unsafe {
                (*shm).shutdown_requested.store(1, Ordering::Release);
            }
            bridge.serial_rx_cv.notify_all();
            let entry = vmm_core::host::abi::CoreToIoEntry {
                msg_type: vmm_core::host::abi::CORE_MSG_SHUTDOWN,
                aux_u16: 0,
                _pad: 0,
                dev: 0,
                features: 0,
                data: [0; 40],
            };
            let _ = unsafe { vmm_core::host::abi::BridgeShm::push_core_to_io(shm, entry) };
            bridge.wake_io();
            0
        },
    )?;

    Ok(())
}

pub fn run_wasm_core(
    module_path: &Path,
    fds: CoreBridgeFds,
) -> Result<(), Box<dyn std::error::Error>> {
    let bridge = SharedCoreBridge::from_fds(fds)?;

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
    let shared_resources = Arc::new(SharedCoreHostResources::new(bridge));

    let mut store = Store::new(
        &engine,
        ThreadHostState {
            wasi: build_core_wasi()?,
            shared: shared_resources,
            memory: shared_memory.clone(),
            last_error: String::new(),
        },
    );

    let mut linker = Linker::<ThreadHostState>::new(&engine);
    linker.define(&store, "env", "memory", shared_memory)?;
    p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;
    register_core_imports(&mut linker)?;

    let next_tid = Arc::new(AtomicI32::new(1));
    let spawn_engine = engine.clone();
    let spawn_module = module.clone();

    let spawn_linker_slot: Arc<RwLock<Option<Linker<ThreadHostState>>>> =
        Arc::new(RwLock::new(None));
    let spawn_linker_ref = spawn_linker_slot.clone();

    linker.func_wrap(
        "wasi",
        "thread-spawn",
        move |caller: Caller<'_, ThreadHostState>, start_arg: i32| -> i32 {
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
            let shared = caller.data().shared.clone();
            let memory = caller.data().memory.clone();

            let spawn_res = std::thread::Builder::new()
                .name(format!("core_wasm_thread_{tid}"))
                .spawn(move || {
                    let mut child_store = Store::new(
                        &engine,
                        ThreadHostState {
                            wasi: wasi_ctx,
                            shared,
                            memory,
                            last_error: String::new(),
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
