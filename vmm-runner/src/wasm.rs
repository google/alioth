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

use crate::host::{
    Cpuid, DtReg, DtRegVal, Error, Hypervisor, Interest, IntxSender, MemMapOption, MemPages,
    MsiSender, PollEvent, Reg, Result, SReg, SegReg, SegRegVal, SerialConsole, Tap, Token, Vcpu,
    Vm, VmEntry, VmEvent, VmExit, VmMemory,
};
use crate::hw::reg::SegAccess;
use crate::virtio::dev::net::NetFeature;

wit_bindgen::generate!({
    world: "vmm-world",
    path: "../wit",
    pub_export_macro: true,
});

use vmm::host::api;

fn map_err(msg: String) -> Error {
    Error::Unexpected { msg }
}

fn map_io_err(e: api::IoError) -> std::io::Error {
    match e {
        api::IoError::WouldBlock => std::io::Error::from(std::io::ErrorKind::WouldBlock),
        api::IoError::Interrupted => std::io::Error::from(std::io::ErrorKind::Interrupted),
        api::IoError::Other(msg) => std::io::Error::other(msg),
    }
}

fn to_wit_reg(r: Reg) -> api::Reg {
    match r {
        Reg::Rax => api::Reg::Rax,
        Reg::Rbx => api::Reg::Rbx,
        Reg::Rcx => api::Reg::Rcx,
        Reg::Rdx => api::Reg::Rdx,
        Reg::Rsi => api::Reg::Rsi,
        Reg::Rdi => api::Reg::Rdi,
        Reg::Rsp => api::Reg::Rsp,
        Reg::Rbp => api::Reg::Rbp,
        Reg::R8 => api::Reg::R8,
        Reg::R9 => api::Reg::R9,
        Reg::R10 => api::Reg::R10,
        Reg::R11 => api::Reg::R11,
        Reg::R12 => api::Reg::R12,
        Reg::R13 => api::Reg::R13,
        Reg::R14 => api::Reg::R14,
        Reg::R15 => api::Reg::R15,
        Reg::Rip => api::Reg::Rip,
        Reg::Rflags => api::Reg::Rflags,
    }
}

fn to_wit_sreg(r: SReg) -> api::SReg {
    match r {
        SReg::Cr0 => api::SReg::Cr0,
        SReg::Cr2 => api::SReg::Cr2,
        SReg::Cr3 => api::SReg::Cr3,
        SReg::Cr4 => api::SReg::Cr4,
        SReg::Cr8 => api::SReg::Cr8,
        SReg::Efer => api::SReg::Efer,
        SReg::ApicBase => api::SReg::ApicBase,
    }
}

fn to_wit_seg_reg(r: SegReg) -> api::SegReg {
    match r {
        SegReg::Cs => api::SegReg::Cs,
        SegReg::Ds => api::SegReg::Ds,
        SegReg::Es => api::SegReg::Es,
        SegReg::Fs => api::SegReg::Fs,
        SegReg::Gs => api::SegReg::Gs,
        SegReg::Ss => api::SegReg::Ss,
        SegReg::Tr => api::SegReg::Tr,
        SegReg::Ldtr => api::SegReg::Ldtr,
    }
}

fn to_wit_dt_reg(r: DtReg) -> api::DtReg {
    match r {
        DtReg::Gdtr => api::DtReg::Gdtr,
        DtReg::Idtr => api::DtReg::Idtr,
    }
}

fn to_wit_seg_reg_val(v: SegRegVal) -> api::SegRegVal {
    api::SegRegVal {
        selector: v.selector,
        base: v.base,
        limit: v.limit,
        access: v.access.0,
    }
}

fn from_wit_seg_reg_val(v: api::SegRegVal) -> SegRegVal {
    SegRegVal {
        selector: v.selector,
        base: v.base,
        limit: v.limit,
        access: SegAccess(v.access),
    }
}

fn to_wit_dt_reg_val(v: DtRegVal) -> api::DtRegVal {
    api::DtRegVal {
        base: v.base,
        limit: v.limit,
    }
}

fn from_wit_dt_reg_val(v: api::DtRegVal) -> DtRegVal {
    DtRegVal {
        base: v.base,
        limit: v.limit,
    }
}

fn to_wit_cpuid(c: Cpuid) -> api::Cpuid {
    api::Cpuid {
        func_val: c.func,
        index: c.index,
        eax: c.eax,
        ebx: c.ebx,
        ecx: c.ecx,
        edx: c.edx,
    }
}

fn from_wit_cpuid(c: api::Cpuid) -> Cpuid {
    Cpuid {
        func: c.func_val,
        index: c.index,
        eax: c.eax,
        ebx: c.ebx,
        ecx: c.ecx,
        edx: c.edx,
    }
}

fn to_wit_mem_map_option(o: MemMapOption) -> api::MemMapOption {
    api::MemMapOption {
        read: o.read,
        write: o.write,
        exec: o.exec,
        log_dirty: o.log_dirty,
    }
}

fn to_wit_vm_entry(e: VmEntry) -> api::VmEntry {
    match e {
        VmEntry::None => api::VmEntry::None,
        VmEntry::Shutdown => api::VmEntry::Shutdown,
        VmEntry::Reboot => api::VmEntry::Reboot,
        VmEntry::Io { data } => api::VmEntry::Io(data),
        VmEntry::Mmio { data } => api::VmEntry::Mmio(data),
    }
}

fn from_wit_vm_exit(e: api::VmExit) -> VmExit {
    match e {
        api::VmExit::Io(io) => VmExit::Io {
            port: io.port,
            write: io.write,
            size: io.size,
        },
        api::VmExit::Mmio(mmio) => VmExit::Mmio {
            addr: mmio.addr,
            write: mmio.write,
            size: mmio.size,
        },
        api::VmExit::Shutdown => VmExit::Shutdown,
        api::VmExit::Reboot => VmExit::Reboot,
        api::VmExit::Unknown(s) => VmExit::Unknown(s),
        api::VmExit::Interrupted => VmExit::Interrupted,
    }
}

fn from_wit_vm_event(e: api::VmEvent) -> VmEvent {
    match e {
        api::VmEvent::VcpuExit(v) => VmEvent::VcpuExit {
            id: v.id,
            exit: from_wit_vm_exit(v.exit),
        },
        api::VmEvent::SerialInput => VmEvent::SerialInput,
        api::VmEvent::Poll(p) => VmEvent::Poll(PollEvent {
            token: Token(p.token),
            is_readable: p.is_readable,
            is_writable: p.is_writable,
        }),
    }
}

#[derive(Debug)]
pub struct WasmMemPages {
    inner: api::MemPages,
    addr: u64,
    size: usize,
}

impl MemPages for WasmMemPages {
    fn addr(&self) -> u64 {
        self.addr
    }

    fn size(&self) -> usize {
        self.size
    }

    fn sync(&self) -> std::io::Result<()> {
        self.inner.sync().map_err(std::io::Error::other)
    }

    fn read(&self, offset: usize, dst: &mut [u8]) -> std::io::Result<()> {
        let data = self
            .inner
            .read(offset as u64, dst.len() as u64)
            .map_err(std::io::Error::other)?;
        dst.copy_from_slice(&data);
        Ok(())
    }

    fn write(&self, offset: usize, src: &[u8]) -> std::io::Result<()> {
        self.inner
            .write(offset as u64, src)
            .map_err(std::io::Error::other)
    }
}

#[derive(Debug)]
pub struct WasmVmMemory {
    inner: api::VmMemory,
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
        self.inner
            .mem_map(slot, gpa, size as u64, hva, to_wit_mem_map_option(option))
            .map_err(map_err)
    }

    fn unmap(&self, slot: u32, gpa: u64, size: usize) -> Result<(), Error> {
        self.inner.unmap(slot, gpa, size as u64).map_err(map_err)
    }

    fn max_mem_slots(&self) -> Result<u32, Error> {
        self.inner.max_mem_slots().map_err(map_err)
    }

    fn register_encrypted_range(&self, addr: u64, size: usize) -> Result<()> {
        self.inner
            .register_encrypted_range(addr, size as u64)
            .map_err(map_err)
    }

    fn deregister_encrypted_range(&self, addr: u64, size: usize) -> Result<()> {
        self.inner
            .deregister_encrypted_range(addr, size as u64)
            .map_err(map_err)
    }

    fn alloc_anon_mem(&self, size: usize) -> std::io::Result<Arc<dyn MemPages>> {
        let inner = self
            .inner
            .alloc_anon_mem(size as u64)
            .map_err(std::io::Error::other)?;
        let addr = inner.addr();
        let actual_size = inner.size() as usize;
        Ok(Arc::new(WasmMemPages {
            inner,
            addr,
            size: actual_size,
        }))
    }
}

#[derive(Debug)]
pub struct WasmIntxSender {
    inner: api::IntxSender,
}

impl IntxSender for WasmIntxSender {
    fn send(&self) -> Result<(), Error> {
        self.inner.send().map_err(map_err)
    }
}

#[derive(Debug)]
pub struct WasmMsiSender {
    inner: api::MsiSender,
}

impl MsiSender for WasmMsiSender {
    fn send(&self, addr: u64, data: u32) -> Result<()> {
        self.inner.send(addr, data).map_err(map_err)
    }
}

#[derive(Debug)]
pub struct WasmSerialConsole {
    inner: api::SerialConsole,
}

impl SerialConsole for WasmSerialConsole {
    fn write_byte(&self, byte: u8) -> std::io::Result<()> {
        self.inner.write_byte(byte).map_err(std::io::Error::other)
    }

    fn read_input(&self, data: &mut VecDeque<u8>) -> std::io::Result<Option<usize>> {
        match self.inner.read_input().map_err(std::io::Error::other)? {
            None => Ok(None),
            Some(bytes) => {
                let count = bytes.len();
                data.extend(bytes);
                Ok(Some(count))
            }
        }
    }

    fn shutdown(&self) -> std::io::Result<()> {
        self.inner.shutdown().map_err(std::io::Error::other)
    }
}

#[derive(Debug)]
pub struct WasmTap {
    inner: api::Tap,
}

impl Tap for WasmTap {
    fn detected_offload(&self) -> NetFeature {
        NetFeature::from_bits_retain(self.inner.detected_offload())
    }

    fn enable_offload(&mut self, feature: NetFeature) -> std::io::Result<()> {
        self.inner
            .enable_offload(feature.bits())
            .map_err(std::io::Error::other)
    }

    fn register(&self, token: Token, interests: Interest) -> std::io::Result<()> {
        self.inner
            .register(token.0, interests.bits())
            .map_err(std::io::Error::other)
    }

    fn deregister(&self) {
        self.inner.deregister();
    }

    fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        let total_len: usize = bufs.iter().map(|b| b.len()).sum();
        let data = self.inner.read(total_len as u64).map_err(map_io_err)?;
        let mut offset = 0;
        for buf in bufs.iter_mut() {
            let rest = data.len() - offset;
            if rest == 0 {
                break;
            }
            let n = buf.len().min(rest);
            buf[..n].copy_from_slice(&data[offset..offset + n]);
            offset += n;
        }
        Ok(offset)
    }

    fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        let total_len: usize = bufs.iter().map(|b| b.len()).sum();
        let mut data = Vec::with_capacity(total_len);
        for buf in bufs {
            data.extend_from_slice(buf);
        }
        let n = self.inner.write(&data).map_err(map_io_err)?;
        Ok(n as usize)
    }
}

#[derive(Debug)]
pub struct WasmVcpu {
    inner: api::Vcpu,
}

impl Vcpu for WasmVcpu {
    fn get_reg(&self, reg: Reg) -> Result<u64, Error> {
        self.inner.get_reg(to_wit_reg(reg)).map_err(map_err)
    }

    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error> {
        let wit_vals: Vec<_> = vals.iter().map(|&(r, v)| (to_wit_reg(r), v)).collect();
        self.inner.set_regs(&wit_vals).map_err(map_err)
    }

    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error> {
        self.inner
            .get_seg_reg(to_wit_seg_reg(reg))
            .map(from_wit_seg_reg_val)
            .map_err(map_err)
    }

    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error> {
        self.inner
            .get_dt_reg(to_wit_dt_reg(reg))
            .map(from_wit_dt_reg_val)
            .map_err(map_err)
    }

    fn get_sreg(&self, reg: SReg) -> Result<u64, Error> {
        self.inner.get_sreg(to_wit_sreg(reg)).map_err(map_err)
    }

    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        let wit_sregs: Vec<_> = sregs.iter().map(|&(r, v)| (to_wit_sreg(r), v)).collect();
        let wit_seg_regs: Vec<_> = seg_regs
            .iter()
            .map(|&(r, v)| (to_wit_seg_reg(r), to_wit_seg_reg_val(v)))
            .collect();
        let wit_dt_regs: Vec<_> = dt_regs
            .iter()
            .map(|&(r, v)| (to_wit_dt_reg(r), to_wit_dt_reg_val(v)))
            .collect();
        self.inner
            .set_sregs(&wit_sregs, &wit_seg_regs, &wit_dt_regs)
            .map_err(map_err)
    }

    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error> {
        let wit_cpuids: Vec<_> = cpuids.into_iter().map(to_wit_cpuid).collect();
        self.inner.set_cpuids(&wit_cpuids).map_err(map_err)
    }

    fn dump(&self) -> Result<(), Error> {
        self.inner.dump().map_err(map_err)
    }
}

#[derive(Debug)]
pub struct WasmVm {
    inner: api::Vm,
}

impl Vm for WasmVm {
    fn create_vcpu(&self, id: u32) -> Result<Box<dyn Vcpu>, Error> {
        let inner = self.inner.create_vcpu(id).map_err(map_err)?;
        Ok(Box::new(WasmVcpu { inner }))
    }

    fn stop_vcpu(&self, id: u32) -> Result<(), Error> {
        self.inner.stop_vcpu(id).map_err(map_err)
    }

    fn resume_vcpu(&self, id: u32, entry: VmEntry) -> Result<(), Error> {
        self.inner
            .resume_vcpu(id, to_wit_vm_entry(entry))
            .map_err(map_err)
    }

    fn next_event(&self) -> Result<VmEvent, Error> {
        self.inner
            .next_event()
            .map(from_wit_vm_event)
            .map_err(map_err)
    }

    fn create_vm_memory(&mut self) -> Result<Box<dyn VmMemory>, Error> {
        let inner = self.inner.create_vm_memory().map_err(map_err)?;
        Ok(Box::new(WasmVmMemory { inner }))
    }

    fn create_intx_sender(&self, pin: u8) -> Result<Box<dyn IntxSender>, Error> {
        let inner = self.inner.create_intx_sender(pin).map_err(map_err)?;
        Ok(Box::new(WasmIntxSender { inner }))
    }

    fn create_msi_sender(&self) -> Result<Box<dyn MsiSender>, Error> {
        let inner = self.inner.create_msi_sender().map_err(map_err)?;
        Ok(Box::new(WasmMsiSender { inner }))
    }

    fn create_serial_console(&self) -> std::io::Result<Box<dyn SerialConsole>> {
        let inner = self
            .inner
            .create_serial_console()
            .map_err(std::io::Error::other)?;
        Ok(Box::new(WasmSerialConsole { inner }))
    }

    fn create_tap(&self, if_name: Option<&str>) -> std::io::Result<Box<dyn Tap>> {
        let inner = self
            .inner
            .create_tap(if_name)
            .map_err(std::io::Error::other)?;
        Ok(Box::new(WasmTap { inner }))
    }
}

#[derive(Debug)]
pub struct WasmHypervisor {
    inner: api::Hypervisor,
}

impl WasmHypervisor {
    pub fn new() -> Result<Self, String> {
        let inner = api::get_hypervisor()?;
        Ok(Self { inner })
    }
}

impl Hypervisor for WasmHypervisor {
    fn create_vm(&self) -> Result<Box<dyn Vm>, Error> {
        let inner = self.inner.create_vm().map_err(map_err)?;
        Ok(Box::new(WasmVm { inner }))
    }

    fn get_supported_cpuids(&self) -> Result<Vec<Cpuid>, Error> {
        let cpuids = self.inner.get_supported_cpuids().map_err(map_err)?;
        Ok(cpuids.into_iter().map(from_wit_cpuid).collect())
    }
}

pub struct WasmGuest;

impl Guest for WasmGuest {
    fn run(config_path: String) -> Result<(), String> {
        let hv = WasmHypervisor::new()?;
        crate::run(&config_path, Box::new(hv)).map_err(|e| e.to_string())
    }
}
