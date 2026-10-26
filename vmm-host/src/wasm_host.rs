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

use std::collections::{HashMap, VecDeque};
use std::io::{IoSlice, IoSliceMut};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use parking_lot::{Mutex, RwLock};
use vmm_runner::host::abi::{
    ERR_EOF, ERR_GENERIC, ERR_INTERRUPTED, ERR_WOULD_BLOCK, EXIT_INTERRUPTED, EXIT_IO, EXIT_MMIO,
    EXIT_REBOOT, EXIT_SHUTDOWN, EXIT_UNKNOWN, RawCpuid, RawDtRegEntry, RawDtRegVal, RawIoEvent,
    RawRegVal, RawSegRegEntry, RawSegRegVal, RawVmExit, decode_vm_entry, dt_reg_from_u32,
    mem_map_option_from_u32, reg_from_u32, seg_reg_from_u32, sreg_from_u32,
};
use vmm_runner::host::{
    DtRegVal, Hypervisor, Interest, IntxSender, MemPages, MsiSender, SegRegVal, SerialConsole, Tap,
    Token, Vcpu, Vm, VmExit, VmMemory,
};
use vmm_runner::virtio::dev::net::NetFeature;
use wasmtime::{
    Caller, Config, Engine, ExternType, Linker, MemoryType, Module, SharedMemory, Store,
};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{FsPerms, I32Exit, WasiCtxBuilder};
use zerocopy::{AsBytes, FromBytes};

use crate::kvm::Kvm;

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

#[derive(Default)]
struct SharedHostResources {
    hypervisors: ResourceTable<Kvm>,
    vms: ResourceTable<RwLock<Box<dyn Vm>>>,
    vcpus: ResourceTable<Mutex<Box<dyn Vcpu>>>,
    vm_memories: ResourceTable<Box<dyn VmMemory>>,
    mem_pages: ResourceTable<dyn MemPages>,
    intx_senders: ResourceTable<Box<dyn IntxSender>>,
    msi_senders: ResourceTable<Box<dyn MsiSender>>,
    serials: ResourceTable<Box<dyn SerialConsole>>,
    taps: ResourceTable<Mutex<Box<dyn Tap>>>,
}

#[derive(Clone)]
struct WasiThreadConfig {
    config_filename: String,
    preopen_dirs: Vec<(PathBuf, String)>,
}

impl WasiThreadConfig {
    fn new(config_filename: &str) -> Self {
        let mut dirs: Vec<(PathBuf, String)> = Vec::new();

        let mut add_dir = |p: &Path| {
            if p.is_dir()
                && let Some(s) = p.to_str()
                && !dirs.iter().any(|(_, guest)| guest == s)
            {
                dirs.push((p.to_path_buf(), s.to_string()));
            }
        };

        if let Ok(cwd) = std::env::current_dir() {
            add_dir(&cwd);
        }

        if let Some(parent) = Path::new(config_filename)
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
        {
            add_dir(parent);
        }

        if let Ok(config_contents) = std::fs::read_to_string(config_filename) {
            for token in config_contents.split('"') {
                if token.starts_with('/')
                    && let Some(parent) = Path::new(token).parent()
                    && parent != Path::new("/")
                {
                    add_dir(parent);
                }
            }
        }

        add_dir(Path::new("/tmp"));
        add_dir(Path::new("/"));

        Self {
            config_filename: config_filename.to_string(),
            preopen_dirs: dirs,
        }
    }

    fn build_p1(&self) -> wasmtime::Result<WasiP1Ctx> {
        let mut builder = WasiCtxBuilder::new();
        builder
            .allow_blocking_current_thread(true)
            .inherit_stdio()
            .args(&["vmm-runner", "-c", &self.config_filename])
            .inherit_env();
        for (host_path, guest_path) in &self.preopen_dirs {
            let _ = builder.preopened_dir(host_path, guest_path, FsPerms::ReadWrite);
        }
        let _ = builder.preopened_dir(".", ".", FsPerms::ReadWrite);
        Ok(builder.build_p1())
    }
}

pub struct ThreadHostState {
    wasi: WasiP1Ctx,
    shared: Arc<SharedHostResources>,
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

fn read_bytes(mem: &SharedMemory, ptr: u32, dst: &mut [u8]) -> Result<(), String> {
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
    let total = (count as usize)
        .checked_mul(elem_size)
        .ok_or_else(|| "slice byte length overflow".to_string())?;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count as usize {
        let item_ptr = (ptr as usize + i * elem_size) as u32;
        out.push(read_struct::<T>(mem, item_ptr)?);
    }
    let _ = total;
    Ok(out)
}

fn register_vmm_imports(linker: &mut Linker<ThreadHostState>) -> wasmtime::Result<()> {
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
            match Kvm::new() {
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
        "vm_next_io_event",
        |mut caller: Caller<'_, ThreadHostState>, vm: u32, event_out_ptr: u32| -> i32 {
            let res = (|| -> Result<(), String> {
                let vm_obj = caller.data().shared.vms.get(vm)?;
                let ev = vm_obj.read().next_io_event().map_err(|e| e.to_string())?;
                let raw = RawIoEvent::from(ev);
                write_struct(&caller.data().memory, event_out_ptr, &raw)
            })();
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_stop_io_poll",
        |mut caller: Caller<'_, ThreadHostState>, vm: u32| -> i32 {
            let res = (|| -> Result<(), String> {
                let vm_obj = caller.data().shared.vms.get(vm)?;
                vm_obj.read().stop_io_poll().map_err(|e| e.to_string())
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
        "vm_create_serial_console",
        |mut caller: Caller<'_, ThreadHostState>, vm: u32| -> i32 {
            let vm_obj = match caller.data().shared.vms.get(vm) {
                Ok(v) => v,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let res = vm_obj.read().create_serial_console();
            match res {
                Ok(serial) => caller.data().shared.serials.insert(serial) as i32,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "vm_create_tap",
        |mut caller: Caller<'_, ThreadHostState>,
         vm: u32,
         has_name: u32,
         name_ptr: u32,
         name_len: u32|
         -> i32 {
            let if_name = if has_name != 0 {
                let mut buf = vec![0u8; name_len as usize];
                if let Err(e) = read_bytes(&caller.data().memory, name_ptr, &mut buf) {
                    return caller.data_mut().set_err(e);
                }
                match String::from_utf8(buf) {
                    Ok(s) => Some(s),
                    Err(e) => return caller.data_mut().set_err(e.to_string()),
                }
            } else {
                None
            };
            let vm_obj = match caller.data().shared.vms.get(vm) {
                Ok(v) => v,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let res = vm_obj.read().create_tap(if_name.as_deref());
            match res {
                Ok(tap) => caller.data().shared.taps.insert(Mutex::new(tap)) as i32,
                Err(e) => caller.data_mut().set_io_err(e),
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

    linker.func_wrap(
        "vmm",
        "serial_write_byte",
        |mut caller: Caller<'_, ThreadHostState>, serial: u32, byte: u32| -> i32 {
            let s = match caller.data().shared.serials.get(serial) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            match s.write_byte(byte as u8) {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_read_input",
        |mut caller: Caller<'_, ThreadHostState>,
         serial: u32,
         dst_ptr: u32,
         max_len: u32|
         -> i32 {
            let s = match caller.data().shared.serials.get(serial) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let mut deque = VecDeque::new();
            match s.read_input(&mut deque) {
                Ok(None) => ERR_EOF,
                Ok(Some(_)) => {
                    let bytes: Vec<u8> = deque.into_iter().take(max_len as usize).collect();
                    if let Err(e) = write_bytes(&caller.data().memory, dst_ptr, &bytes) {
                        return caller.data_mut().set_err(e);
                    }
                    bytes.len() as i32
                }
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_shutdown",
        |mut caller: Caller<'_, ThreadHostState>, serial: u32| -> i32 {
            let s = match caller.data().shared.serials.get(serial) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            match s.shutdown() {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "serial_close",
        |caller: Caller<'_, ThreadHostState>, serial: u32| {
            caller.data().shared.serials.remove(serial);
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_detected_offload",
        |caller: Caller<'_, ThreadHostState>, tap: u32| -> u64 {
            match caller.data().shared.taps.get(tap) {
                Ok(t) => t.lock().detected_offload().bits(),
                Err(_) => 0,
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_enable_offload",
        |mut caller: Caller<'_, ThreadHostState>, tap: u32, feature: u64| -> i32 {
            let t = match caller.data().shared.taps.get(tap) {
                Ok(t) => t,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let res = t
                .lock()
                .enable_offload(NetFeature::from_bits_retain(feature));
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_register",
        |mut caller: Caller<'_, ThreadHostState>, tap: u32, token: u64, interests: u32| -> i32 {
            let t = match caller.data().shared.taps.get(tap) {
                Ok(t) => t,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let res = t
                .lock()
                .register(Token(token), Interest::from_bits_retain(interests as u8));
            match res {
                Ok(()) => 0,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_deregister",
        |caller: Caller<'_, ThreadHostState>, tap: u32| {
            if let Ok(t) = caller.data().shared.taps.get(tap) {
                t.lock().deregister();
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_read",
        |mut caller: Caller<'_, ThreadHostState>, tap: u32, dst_ptr: u32, max_len: u32| -> i32 {
            let t = match caller.data().shared.taps.get(tap) {
                Ok(t) => t,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let start = match check_bounds(&caller.data().memory, dst_ptr, max_len as usize) {
                Ok(s) => s,
                Err(e) => return caller.data_mut().set_err(e),
            };
            let dst = unsafe {
                std::slice::from_raw_parts_mut(
                    caller.data().memory.data().as_ptr().add(start) as *mut u8,
                    max_len as usize,
                )
            };
            let res = t.lock().read_vectored(&mut [IoSliceMut::new(dst)]);
            match res {
                Ok(n) => n as i32,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_write",
        |mut caller: Caller<'_, ThreadHostState>, tap: u32, src_ptr: u32, len: u32| -> i32 {
            let t = match caller.data().shared.taps.get(tap) {
                Ok(t) => t,
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
            let res = t.lock().write_vectored(&[IoSlice::new(src)]);
            match res {
                Ok(n) => n as i32,
                Err(e) => caller.data_mut().set_io_err(e),
            }
        },
    )?;

    linker.func_wrap(
        "vmm",
        "tap_close",
        |caller: Caller<'_, ThreadHostState>, tap: u32| {
            caller.data().shared.taps.remove(tap);
        },
    )?;

    Ok(())
}

pub fn run_wasm_vmm(
    module_path: &Path,
    config_filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = Config::new();
    config.wasm_threads(true);
    config.shared_memory(true);
    config.wasm_simd(false);
    config.wasm_relaxed_simd(false);
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
    let shared_resources = Arc::new(SharedHostResources::default());
    let wasi_config = Arc::new(WasiThreadConfig::new(config_filename));

    let mut store = Store::new(
        &engine,
        ThreadHostState {
            wasi: wasi_config.build_p1()?,
            shared: shared_resources,
            memory: shared_memory.clone(),
            last_error: String::new(),
        },
    );

    let mut linker = Linker::<ThreadHostState>::new(&engine);
    linker.define(&store, "env", "memory", shared_memory)?;
    p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)?;
    register_vmm_imports(&mut linker)?;

    let next_tid = Arc::new(AtomicI32::new(1));
    let spawn_engine = engine.clone();
    let spawn_module = module.clone();
    let spawn_wasi_config = wasi_config.clone();

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
            let wasi_ctx = match spawn_wasi_config.build_p1() {
                Ok(c) => c,
                Err(_) => return -1,
            };
            let shared = caller.data().shared.clone();
            let memory = caller.data().memory.clone();

            let spawn_res = std::thread::Builder::new()
                .name(format!("wasm_thread_{tid}"))
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
                            log::error!("failed to instantiate module on thread {tid}: {e}");
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
