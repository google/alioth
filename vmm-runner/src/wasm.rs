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

use std::collections::VecDeque;
use std::io::{IoSlice, IoSliceMut};
use std::sync::Arc;

use crate::host::abi::{
    ERR_EOF, ERR_INTERRUPTED, ERR_WOULD_BLOCK, EXIT_INTERRUPTED, EXIT_IO, EXIT_MMIO, EXIT_REBOOT,
    EXIT_SHUTDOWN, RawCpuid, RawDtRegEntry, RawDtRegVal, RawIoEvent, RawRegVal, RawSegRegEntry,
    RawSegRegVal, RawVmExit, dt_reg_to_u32, encode_vm_entry, mem_map_option_to_u32, reg_to_u32,
    seg_reg_to_u32, sreg_to_u32,
};
use crate::host::{
    Cpuid, DtReg, DtRegVal, Error, Hypervisor, Interest, IntxSender, IoEvent, MemMapOption,
    MemPages, MsiSender, Reg, Result, SReg, SegReg, SegRegVal, SerialConsole, Tap, Token, Vcpu,
    Vm, VmEntry, VmExit, VmMemory,
};
use crate::virtio::dev::net::NetFeature;

#[link(wasm_import_module = "vmm")]
unsafe extern "C" {
    fn vmm_last_error_len() -> u32;
    fn vmm_last_error_read(dst_ptr: u32, dst_len: u32) -> i32;

    fn hv_new() -> i32;
    fn hv_get_supported_cpuids(hv: u32, dst_ptr: u32, max_entries: u32) -> i32;
    fn hv_create_vm(hv: u32) -> i32;
    fn hv_close(hv: u32);

    fn vm_create_vcpu(vm: u32, id: u32) -> i32;
    fn vm_stop_vcpu(vm: u32, id: u32) -> i32;
    fn vm_next_io_event(vm: u32, event_out_ptr: u32) -> i32;
    fn vm_stop_io_poll(vm: u32) -> i32;
    fn vm_create_vm_memory(vm: u32) -> i32;
    fn vm_create_intx_sender(vm: u32, pin: u32) -> i32;
    fn vm_create_msi_sender(vm: u32) -> i32;
    fn vm_create_serial_console(vm: u32) -> i32;
    fn vm_create_tap(vm: u32, has_name: u32, name_ptr: u32, name_len: u32) -> i32;
    fn vm_close(vm: u32);

    fn vcpu_run(vcpu: u32, entry_kind: u32, entry_data: u64, exit_out_ptr: u32) -> i32;
    fn vcpu_get_reg(vcpu: u32, reg: u32, val_out_ptr: u32) -> i32;
    fn vcpu_set_regs(vcpu: u32, vals_ptr: u32, vals_len: u32) -> i32;
    fn vcpu_get_seg_reg(vcpu: u32, reg: u32, val_out_ptr: u32) -> i32;
    fn vcpu_get_dt_reg(vcpu: u32, reg: u32, val_out_ptr: u32) -> i32;
    fn vcpu_get_sreg(vcpu: u32, reg: u32, val_out_ptr: u32) -> i32;
    fn vcpu_set_sregs(
        vcpu: u32,
        sregs_ptr: u32,
        sregs_len: u32,
        seg_regs_ptr: u32,
        seg_regs_len: u32,
        dt_regs_ptr: u32,
        dt_regs_len: u32,
    ) -> i32;
    fn vcpu_set_cpuids(vcpu: u32, cpuids_ptr: u32, cpuids_len: u32) -> i32;
    fn vcpu_dump(vcpu: u32) -> i32;
    fn vcpu_close(vcpu: u32);

    fn vm_memory_mem_map(mem: u32, slot: u32, gpa: u64, size: u64, hva: u64, flags: u32) -> i32;
    fn vm_memory_unmap(mem: u32, slot: u32, gpa: u64, size: u64) -> i32;
    fn vm_memory_max_mem_slots(mem: u32, out_ptr: u32) -> i32;
    fn vm_memory_register_encrypted_range(mem: u32, addr: u64, size: u64) -> i32;
    fn vm_memory_deregister_encrypted_range(mem: u32, addr: u64, size: u64) -> i32;
    fn vm_memory_alloc_anon_mem(
        mem: u32,
        size: u64,
        addr_out_ptr: u32,
        size_out_ptr: u32,
    ) -> i32;
    fn vm_memory_close(mem: u32);

    fn mem_pages_sync(pages: u32) -> i32;
    fn mem_pages_read(pages: u32, offset: u64, dst_ptr: u32, len: u32) -> i32;
    fn mem_pages_write(pages: u32, offset: u64, src_ptr: u32, len: u32) -> i32;
    fn mem_pages_close(pages: u32);

    fn intx_sender_send(sender: u32) -> i32;
    fn intx_sender_close(sender: u32);

    fn msi_sender_send(sender: u32, addr: u64, data: u32) -> i32;
    fn msi_sender_close(sender: u32);

    fn serial_write_byte(serial: u32, byte: u32) -> i32;
    fn serial_read_input(serial: u32, dst_ptr: u32, max_len: u32) -> i32;
    fn serial_shutdown(serial: u32) -> i32;
    fn serial_close(serial: u32);

    fn tap_detected_offload(tap: u32) -> u64;
    fn tap_enable_offload(tap: u32, feature: u64) -> i32;
    fn tap_register(tap: u32, token: u64, interests: u32) -> i32;
    fn tap_deregister(tap: u32);
    fn tap_read(tap: u32, dst_ptr: u32, max_len: u32) -> i32;
    fn tap_write(tap: u32, src_ptr: u32, len: u32) -> i32;
    fn tap_close(tap: u32);
}

fn fetch_last_error() -> String {
    let len = unsafe { vmm_last_error_len() } as usize;
    if len == 0 {
        return "unknown host error".to_string();
    }
    let mut buf = vec![0u8; len];
    unsafe { vmm_last_error_read(buf.as_mut_ptr() as u32, len as u32) };
    String::from_utf8_lossy(&buf).into_owned()
}

fn check_hv(rc: i32) -> Result<u32, Error> {
    if rc < 0 {
        Err(Error::Unexpected {
            msg: fetch_last_error(),
        })
    } else {
        Ok(rc as u32)
    }
}

fn check_hv_unit(rc: i32) -> Result<(), Error> {
    check_hv(rc).map(|_| ())
}

fn check_io(rc: i32) -> std::io::Result<u32> {
    if rc >= 0 {
        Ok(rc as u32)
    } else if rc == ERR_WOULD_BLOCK {
        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    } else if rc == ERR_INTERRUPTED {
        Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
    } else {
        Err(std::io::Error::other(fetch_last_error()))
    }
}

fn check_io_unit(rc: i32) -> std::io::Result<()> {
    check_io(rc).map(|_| ())
}

#[derive(Debug)]
pub struct WasmMemPages {
    handle: u32,
    addr: u64,
    size: usize,
}

impl Drop for WasmMemPages {
    fn drop(&mut self) {
        unsafe { mem_pages_close(self.handle) };
    }
}

impl MemPages for WasmMemPages {
    fn addr(&self) -> u64 {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }

    fn sync(&self) -> std::io::Result<()> {
        check_io_unit(unsafe { mem_pages_sync(self.handle) })
    }

    fn read(&self, offset: usize, dst: &mut [u8]) -> std::io::Result<()> {
        check_io_unit(unsafe {
            mem_pages_read(
                self.handle,
                offset as u64,
                dst.as_mut_ptr() as u32,
                dst.len() as u32,
            )
        })
    }

    fn write(&self, offset: usize, src: &[u8]) -> std::io::Result<()> {
        check_io_unit(unsafe {
            mem_pages_write(
                self.handle,
                offset as u64,
                src.as_ptr() as u32,
                src.len() as u32,
            )
        })
    }
}

#[derive(Debug)]
pub struct WasmVmMemory {
    handle: u32,
}

impl Drop for WasmVmMemory {
    fn drop(&mut self) {
        unsafe { vm_memory_close(self.handle) };
    }
}

impl VmMemory for WasmVmMemory {
    fn mem_map(
        &self,
        slot: u32,
        gpa: u64,
        size: usize,
        hva: u64,
        option: MemMapOption,
    ) -> Result<(), Error> {
        check_hv_unit(unsafe {
            vm_memory_mem_map(
                self.handle,
                slot,
                gpa,
                size as u64,
                hva,
                mem_map_option_to_u32(option),
            )
        })
    }

    fn unmap(&self, slot: u32, gpa: u64, size: usize) -> Result<(), Error> {
        check_hv_unit(unsafe { vm_memory_unmap(self.handle, slot, gpa, size as u64) })
    }

    fn max_mem_slots(&self) -> Result<u32, Error> {
        let mut out = 0u32;
        check_hv_unit(unsafe { vm_memory_max_mem_slots(self.handle, &mut out as *mut u32 as u32) })?;
        Ok(out)
    }

    fn register_encrypted_range(&self, addr: u64, size: usize) -> Result<()> {
        check_hv_unit(unsafe {
            vm_memory_register_encrypted_range(self.handle, addr, size as u64)
        })
    }

    fn deregister_encrypted_range(&self, addr: u64, size: usize) -> Result<()> {
        check_hv_unit(unsafe {
            vm_memory_deregister_encrypted_range(self.handle, addr, size as u64)
        })
    }

    fn alloc_anon_mem(&self, size: usize) -> std::io::Result<Arc<dyn MemPages>> {
        let mut addr = 0u64;
        let mut actual_size = 0u64;
        let handle = check_io(unsafe {
            vm_memory_alloc_anon_mem(
                self.handle,
                size as u64,
                &mut addr as *mut u64 as u32,
                &mut actual_size as *mut u64 as u32,
            )
        })?;
        Ok(Arc::new(WasmMemPages {
            handle,
            addr,
            size: actual_size as usize,
        }))
    }
}

#[derive(Debug)]
pub struct WasmIntxSender {
    handle: u32,
}

impl Drop for WasmIntxSender {
    fn drop(&mut self) {
        unsafe { intx_sender_close(self.handle) };
    }
}

impl IntxSender for WasmIntxSender {
    fn send(&self) -> Result<(), Error> {
        check_hv_unit(unsafe { intx_sender_send(self.handle) })
    }
}

#[derive(Debug)]
pub struct WasmMsiSender {
    handle: u32,
}

impl Drop for WasmMsiSender {
    fn drop(&mut self) {
        unsafe { msi_sender_close(self.handle) };
    }
}

impl MsiSender for WasmMsiSender {
    fn send(&self, addr: u64, data: u32) -> Result<()> {
        check_hv_unit(unsafe { msi_sender_send(self.handle, addr, data) })
    }
}

#[derive(Debug)]
pub struct WasmSerialConsole {
    handle: u32,
}

impl Drop for WasmSerialConsole {
    fn drop(&mut self) {
        unsafe { serial_close(self.handle) };
    }
}

impl SerialConsole for WasmSerialConsole {
    fn write_byte(&self, byte: u8) -> std::io::Result<()> {
        check_io_unit(unsafe { serial_write_byte(self.handle, byte as u32) })
    }

    fn read_input(&self, data: &mut VecDeque<u8>) -> std::io::Result<Option<usize>> {
        let mut buf = [0u8; 256];
        let rc = unsafe {
            serial_read_input(self.handle, buf.as_mut_ptr() as u32, buf.len() as u32)
        };
        if rc == ERR_EOF {
            return Ok(None);
        }
        let n = check_io(rc)? as usize;
        data.extend(&buf[..n]);
        Ok(Some(n))
    }

    fn shutdown(&self) -> std::io::Result<()> {
        check_io_unit(unsafe { serial_shutdown(self.handle) })
    }
}

#[derive(Debug)]
pub struct WasmTap {
    handle: u32,
}

impl Drop for WasmTap {
    fn drop(&mut self) {
        unsafe { tap_close(self.handle) };
    }
}

impl Tap for WasmTap {
    fn detected_offload(&self) -> NetFeature {
        NetFeature::from_bits_retain(unsafe { tap_detected_offload(self.handle) })
    }

    fn enable_offload(&mut self, feature: NetFeature) -> std::io::Result<()> {
        check_io_unit(unsafe { tap_enable_offload(self.handle, feature.bits()) })
    }

    fn register(&self, token: Token, interests: Interest) -> std::io::Result<()> {
        check_io_unit(unsafe { tap_register(self.handle, token.0, interests.bits() as u32) })
    }

    fn deregister(&self) {
        unsafe { tap_deregister(self.handle) };
    }

    fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        let total_len: usize = bufs.iter().map(|b| b.len()).sum();
        let mut data = vec![0u8; total_len];
        let n = check_io(unsafe {
            tap_read(self.handle, data.as_mut_ptr() as u32, total_len as u32)
        })? as usize;
        let mut offset = 0;
        for buf in bufs.iter_mut() {
            let rest = n.saturating_sub(offset);
            if rest == 0 {
                break;
            }
            let copy_len = buf.len().min(rest);
            buf[..copy_len].copy_from_slice(&data[offset..offset + copy_len]);
            offset += copy_len;
        }
        Ok(offset)
    }

    fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        let total_len: usize = bufs.iter().map(|b| b.len()).sum();
        let mut data = Vec::with_capacity(total_len);
        for buf in bufs {
            data.extend_from_slice(buf);
        }
        let n = check_io(unsafe {
            tap_write(self.handle, data.as_ptr() as u32, data.len() as u32)
        })? as usize;
        Ok(n)
    }
}

#[derive(Debug)]
pub struct WasmVcpu {
    handle: u32,
}

impl Drop for WasmVcpu {
    fn drop(&mut self) {
        unsafe { vcpu_close(self.handle) };
    }
}

impl Vcpu for WasmVcpu {
    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error> {
        let (entry_kind, entry_data) = encode_vm_entry(entry);
        let mut raw_exit = RawVmExit::default();
        check_hv_unit(unsafe {
            vcpu_run(
                self.handle,
                entry_kind,
                entry_data,
                &mut raw_exit as *mut RawVmExit as u32,
            )
        })?;
        match raw_exit.kind {
            EXIT_IO => Ok(VmExit::Io {
                port: raw_exit.addr_or_port as u16,
                write: if raw_exit.is_write != 0 {
                    Some(raw_exit.data as u32)
                } else {
                    None
                },
                size: raw_exit.size,
            }),
            EXIT_MMIO => Ok(VmExit::Mmio {
                addr: raw_exit.addr_or_port,
                write: if raw_exit.is_write != 0 {
                    Some(raw_exit.data)
                } else {
                    None
                },
                size: raw_exit.size,
            }),
            EXIT_SHUTDOWN => Ok(VmExit::Shutdown),
            EXIT_REBOOT => Ok(VmExit::Reboot),
            EXIT_INTERRUPTED => Ok(VmExit::Interrupted),
            _ => Ok(VmExit::Unknown(fetch_last_error())),
        }
    }

    fn get_reg(&self, reg: Reg) -> Result<u64, Error> {
        let mut val = 0u64;
        check_hv_unit(unsafe {
            vcpu_get_reg(self.handle, reg_to_u32(reg), &mut val as *mut u64 as u32)
        })?;
        Ok(val)
    }

    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error> {
        let raw_vals: Vec<RawRegVal> = vals
            .iter()
            .map(|&(r, val)| RawRegVal {
                reg: reg_to_u32(r),
                _pad: 0,
                val,
            })
            .collect();
        check_hv_unit(unsafe {
            vcpu_set_regs(self.handle, raw_vals.as_ptr() as u32, raw_vals.len() as u32)
        })
    }

    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error> {
        let mut raw = RawSegRegVal::default();
        check_hv_unit(unsafe {
            vcpu_get_seg_reg(
                self.handle,
                seg_reg_to_u32(reg),
                &mut raw as *mut RawSegRegVal as u32,
            )
        })?;
        Ok(raw.into())
    }

    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error> {
        let mut raw = RawDtRegVal::default();
        check_hv_unit(unsafe {
            vcpu_get_dt_reg(
                self.handle,
                dt_reg_to_u32(reg),
                &mut raw as *mut RawDtRegVal as u32,
            )
        })?;
        Ok(raw.into())
    }

    fn get_sreg(&self, reg: SReg) -> Result<u64, Error> {
        let mut val = 0u64;
        check_hv_unit(unsafe {
            vcpu_get_sreg(self.handle, sreg_to_u32(reg), &mut val as *mut u64 as u32)
        })?;
        Ok(val)
    }

    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        let raw_sregs: Vec<RawRegVal> = sregs
            .iter()
            .map(|&(r, val)| RawRegVal {
                reg: sreg_to_u32(r),
                _pad: 0,
                val,
            })
            .collect();
        let raw_seg_regs: Vec<RawSegRegEntry> = seg_regs
            .iter()
            .map(|&(r, val)| RawSegRegEntry {
                reg: seg_reg_to_u32(r),
                _pad: 0,
                val: val.into(),
            })
            .collect();
        let raw_dt_regs: Vec<RawDtRegEntry> = dt_regs
            .iter()
            .map(|&(r, val)| RawDtRegEntry {
                reg: dt_reg_to_u32(r),
                _pad: 0,
                val: val.into(),
            })
            .collect();
        check_hv_unit(unsafe {
            vcpu_set_sregs(
                self.handle,
                raw_sregs.as_ptr() as u32,
                raw_sregs.len() as u32,
                raw_seg_regs.as_ptr() as u32,
                raw_seg_regs.len() as u32,
                raw_dt_regs.as_ptr() as u32,
                raw_dt_regs.len() as u32,
            )
        })
    }

    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error> {
        let raw_cpuids: Vec<RawCpuid> = cpuids.into_iter().map(RawCpuid::from).collect();
        check_hv_unit(unsafe {
            vcpu_set_cpuids(
                self.handle,
                raw_cpuids.as_ptr() as u32,
                raw_cpuids.len() as u32,
            )
        })
    }

    fn dump(&self) -> Result<(), Error> {
        check_hv_unit(unsafe { vcpu_dump(self.handle) })
    }
}

#[derive(Debug)]
pub struct WasmVm {
    handle: u32,
}

impl Drop for WasmVm {
    fn drop(&mut self) {
        unsafe { vm_close(self.handle) };
    }
}

impl Vm for WasmVm {
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>, Error> {
        let handle = check_hv(unsafe { vm_create_vcpu(self.handle, id) })?;
        Ok(Box::new(WasmVcpu { handle }))
    }

    fn stop_vcpu(&self, id: u32) -> Result<(), Error> {
        check_hv_unit(unsafe { vm_stop_vcpu(self.handle, id) })
    }

    fn next_io_event(&self) -> Result<IoEvent, Error> {
        let mut raw = RawIoEvent::default();
        check_hv_unit(unsafe { vm_next_io_event(self.handle, &mut raw as *mut RawIoEvent as u32) })?;
        Ok(raw.into())
    }

    fn stop_io_poll(&self) -> Result<(), Error> {
        check_hv_unit(unsafe { vm_stop_io_poll(self.handle) })
    }

    fn create_vm_memory(&mut self) -> Result<Box<dyn VmMemory>, Error> {
        let handle = check_hv(unsafe { vm_create_vm_memory(self.handle) })?;
        Ok(Box::new(WasmVmMemory { handle }))
    }

    fn create_intx_sender(&self, pin: u8) -> Result<Box<dyn IntxSender>, Error> {
        let handle = check_hv(unsafe { vm_create_intx_sender(self.handle, pin as u32) })?;
        Ok(Box::new(WasmIntxSender { handle }))
    }

    fn create_msi_sender(&self) -> Result<Box<dyn MsiSender>, Error> {
        let handle = check_hv(unsafe { vm_create_msi_sender(self.handle) })?;
        Ok(Box::new(WasmMsiSender { handle }))
    }

    fn create_serial_console(&self) -> std::io::Result<Box<dyn SerialConsole>> {
        let handle = check_io(unsafe { vm_create_serial_console(self.handle) })?;
        Ok(Box::new(WasmSerialConsole { handle }))
    }

    fn create_tap(&self, if_name: Option<&str>) -> std::io::Result<Box<dyn Tap>> {
        let (has_name, ptr, len) = match if_name {
            Some(name) => (1u32, name.as_ptr() as u32, name.len() as u32),
            None => (0u32, 0u32, 0u32),
        };
        let handle = check_io(unsafe { vm_create_tap(self.handle, has_name, ptr, len) })?;
        Ok(Box::new(WasmTap { handle }))
    }
}

#[derive(Debug)]
pub struct WasmHypervisor {
    handle: u32,
}

impl Drop for WasmHypervisor {
    fn drop(&mut self) {
        unsafe { hv_close(self.handle) };
    }
}

impl WasmHypervisor {
    pub fn new() -> Result<Self, String> {
        let handle = check_hv(unsafe { hv_new() }).map_err(|e| e.to_string())?;
        Ok(Self { handle })
    }
}

impl Hypervisor for WasmHypervisor {
    fn create_vm(&self) -> Result<Box<dyn Vm>, Error> {
        let handle = check_hv(unsafe { hv_create_vm(self.handle) })?;
        Ok(Box::new(WasmVm { handle }))
    }

    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error> {
        let mut raw = vec![RawCpuid::default(); 256];
        let count = check_hv(unsafe {
            hv_get_supported_cpuids(self.handle, raw.as_mut_ptr() as u32, raw.len() as u32)
        })? as usize;
        raw.truncate(count);
        Ok(raw.into_iter().map(Cpuid::from).collect())
    }
}
