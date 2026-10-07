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
use std::path::Path;
use std::sync::Arc;

use vmm_runner::host::{
    Cpuid, DtReg, DtRegVal, Hypervisor, Interest, IntxSender, MemMapOption, MemPages, MsiSender,
    Reg, SReg, SegReg, SegRegVal, SerialConsole, Tap, Token, Vcpu, Vm, VmEntry, VmEvent, VmExit,
    VmMemory,
};
use vmm_runner::hw::reg::SegAccess;
use vmm_runner::virtio::dev::net::NetFeature;
use wasmtime::component::{Component, HasSelf, Linker, Resource, ResourceTable};
use wasmtime::{Engine, Store};
use wasmtime_wasi::{FsPerms, WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

use crate::kvm::Kvm;

wasmtime::component::bindgen!({
    world: "vmm-world",
    path: "../wit",
    with: {
        "vmm:host/api.hypervisor": HostHypervisorRes,
        "vmm:host/api.vm": HostVmRes,
        "vmm:host/api.vcpu": HostVcpuRes,
        "vmm:host/api.vm-memory": HostVmMemoryRes,
        "vmm:host/api.mem-pages": HostMemPagesRes,
        "vmm:host/api.intx-sender": HostIntxSenderRes,
        "vmm:host/api.msi-sender": HostMsiSenderRes,
        "vmm:host/api.serial-console": HostSerialConsoleRes,
        "vmm:host/api.tap": HostTapRes,
    },
});

use vmm::host::api;

pub type HostHypervisorRes = Kvm;
pub type HostVmRes = Box<dyn Vm>;
pub type HostVcpuRes = Box<dyn Vcpu>;
pub type HostVmMemoryRes = Box<dyn VmMemory>;
pub type HostMemPagesRes = Arc<dyn MemPages>;
pub type HostIntxSenderRes = Box<dyn IntxSender>;
pub type HostMsiSenderRes = Box<dyn MsiSender>;
pub type HostSerialConsoleRes = Box<dyn SerialConsole>;
pub type HostTapRes = Box<dyn Tap>;

pub struct HostState {
    wasi: WasiCtx,
    table: ResourceTable,
}

impl WasiView for HostState {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

fn to_wit_io_err(e: std::io::Error) -> api::IoError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock => api::IoError::WouldBlock,
        std::io::ErrorKind::Interrupted => api::IoError::Interrupted,
        _ => api::IoError::Other(e.to_string()),
    }
}

fn from_wit_reg(r: api::Reg) -> Reg {
    match r {
        api::Reg::Rax => Reg::Rax,
        api::Reg::Rbx => Reg::Rbx,
        api::Reg::Rcx => Reg::Rcx,
        api::Reg::Rdx => Reg::Rdx,
        api::Reg::Rsi => Reg::Rsi,
        api::Reg::Rdi => Reg::Rdi,
        api::Reg::Rsp => Reg::Rsp,
        api::Reg::Rbp => Reg::Rbp,
        api::Reg::R8 => Reg::R8,
        api::Reg::R9 => Reg::R9,
        api::Reg::R10 => Reg::R10,
        api::Reg::R11 => Reg::R11,
        api::Reg::R12 => Reg::R12,
        api::Reg::R13 => Reg::R13,
        api::Reg::R14 => Reg::R14,
        api::Reg::R15 => Reg::R15,
        api::Reg::Rip => Reg::Rip,
        api::Reg::Rflags => Reg::Rflags,
    }
}

fn from_wit_sreg(r: api::SReg) -> SReg {
    match r {
        api::SReg::Cr0 => SReg::Cr0,
        api::SReg::Cr2 => SReg::Cr2,
        api::SReg::Cr3 => SReg::Cr3,
        api::SReg::Cr4 => SReg::Cr4,
        api::SReg::Cr8 => SReg::Cr8,
        api::SReg::Efer => SReg::Efer,
        api::SReg::ApicBase => SReg::ApicBase,
    }
}

fn from_wit_seg_reg(r: api::SegReg) -> SegReg {
    match r {
        api::SegReg::Cs => SegReg::Cs,
        api::SegReg::Ds => SegReg::Ds,
        api::SegReg::Es => SegReg::Es,
        api::SegReg::Fs => SegReg::Fs,
        api::SegReg::Gs => SegReg::Gs,
        api::SegReg::Ss => SegReg::Ss,
        api::SegReg::Tr => SegReg::Tr,
        api::SegReg::Ldtr => SegReg::Ldtr,
    }
}

fn from_wit_dt_reg(r: api::DtReg) -> DtReg {
    match r {
        api::DtReg::Gdtr => DtReg::Gdtr,
        api::DtReg::Idtr => DtReg::Idtr,
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

fn from_wit_mem_map_option(o: api::MemMapOption) -> MemMapOption {
    MemMapOption {
        read: o.read,
        write: o.write,
        exec: o.exec,
        log_dirty: o.log_dirty,
    }
}

fn from_wit_vm_entry(e: api::VmEntry) -> VmEntry {
    match e {
        api::VmEntry::None => VmEntry::None,
        api::VmEntry::Shutdown => VmEntry::Shutdown,
        api::VmEntry::Reboot => VmEntry::Reboot,
        api::VmEntry::Io(data) => VmEntry::Io { data },
        api::VmEntry::Mmio(data) => VmEntry::Mmio { data },
    }
}

fn to_wit_vm_exit(e: VmExit) -> api::VmExit {
    match e {
        VmExit::Io { port, write, size } => api::VmExit::Io(api::IoExit { port, write, size }),
        VmExit::Mmio { addr, write, size } => {
            api::VmExit::Mmio(api::MmioExit { addr, write, size })
        }
        VmExit::Shutdown => api::VmExit::Shutdown,
        VmExit::Reboot => api::VmExit::Reboot,
        VmExit::Unknown(s) => api::VmExit::Unknown(s),
        VmExit::Interrupted => api::VmExit::Interrupted,
    }
}

fn to_wit_vm_event(e: VmEvent) -> api::VmEvent {
    match e {
        VmEvent::VcpuExit { id, exit } => api::VmEvent::VcpuExit(api::VcpuExit {
            id,
            exit: to_wit_vm_exit(exit),
        }),
        VmEvent::SerialInput => api::VmEvent::SerialInput,
        VmEvent::Poll(p) => api::VmEvent::Poll(api::PollEvent {
            token: p.token.0,
            is_readable: p.is_readable,
            is_writable: p.is_writable,
        }),
    }
}

impl api::HostMemPages for HostState {
    fn addr(&mut self, self_: Resource<HostMemPagesRes>) -> u64 {
        let pages = self.table.get(&self_).unwrap();
        pages.addr()
    }

    fn size(&mut self, self_: Resource<HostMemPagesRes>) -> u64 {
        let pages = self.table.get(&self_).unwrap();
        pages.size() as u64
    }

    fn sync(&mut self, self_: Resource<HostMemPagesRes>) -> Result<(), String> {
        let pages = self.table.get(&self_).map_err(|e| e.to_string())?;
        pages.sync().map_err(|e| e.to_string())
    }

    fn read(
        &mut self,
        self_: Resource<HostMemPagesRes>,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>, String> {
        let pages = self.table.get(&self_).map_err(|e| e.to_string())?;
        let mut dst = vec![0u8; len as usize];
        pages
            .read(offset as usize, &mut dst)
            .map_err(|e| e.to_string())?;
        Ok(dst)
    }

    fn write(
        &mut self,
        self_: Resource<HostMemPagesRes>,
        offset: u64,
        src: Vec<u8>,
    ) -> Result<(), String> {
        let pages = self.table.get(&self_).map_err(|e| e.to_string())?;
        pages
            .write(offset as usize, &src)
            .map_err(|e| e.to_string())
    }

    fn drop(&mut self, rep: Resource<HostMemPagesRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl api::HostVmMemory for HostState {
    fn mem_map(
        &mut self,
        self_: Resource<HostVmMemoryRes>,
        slot: u32,
        gpa: u64,
        size: u64,
        hva: u64,
        opt: api::MemMapOption,
    ) -> Result<(), String> {
        let mem = self.table.get(&self_).map_err(|e| e.to_string())?;
        mem.mem_map(
            slot,
            gpa,
            size as usize,
            hva,
            from_wit_mem_map_option(opt),
        )
        .map_err(|e| e.to_string())
    }

    fn unmap(
        &mut self,
        self_: Resource<HostVmMemoryRes>,
        slot: u32,
        gpa: u64,
        size: u64,
    ) -> Result<(), String> {
        let mem = self.table.get(&self_).map_err(|e| e.to_string())?;
        mem.unmap(slot, gpa, size as usize)
            .map_err(|e| e.to_string())
    }

    fn max_mem_slots(&mut self, self_: Resource<HostVmMemoryRes>) -> Result<u32, String> {
        let mem = self.table.get(&self_).map_err(|e| e.to_string())?;
        mem.max_mem_slots().map_err(|e| e.to_string())
    }

    fn register_encrypted_range(
        &mut self,
        self_: Resource<HostVmMemoryRes>,
        addr: u64,
        size: u64,
    ) -> Result<(), String> {
        let mem = self.table.get(&self_).map_err(|e| e.to_string())?;
        mem.register_encrypted_range(addr, size as usize)
            .map_err(|e| e.to_string())
    }

    fn deregister_encrypted_range(
        &mut self,
        self_: Resource<HostVmMemoryRes>,
        addr: u64,
        size: u64,
    ) -> Result<(), String> {
        let mem = self.table.get(&self_).map_err(|e| e.to_string())?;
        mem.deregister_encrypted_range(addr, size as usize)
            .map_err(|e| e.to_string())
    }

    fn alloc_anon_mem(
        &mut self,
        self_: Resource<HostVmMemoryRes>,
        size: u64,
    ) -> Result<Resource<HostMemPagesRes>, String> {
        let pages = {
            let mem = self.table.get(&self_).map_err(|e| e.to_string())?;
            mem.alloc_anon_mem(size as usize)
                .map_err(|e| e.to_string())?
        };
        self.table.push(pages).map_err(|e| e.to_string())
    }

    fn drop(&mut self, rep: Resource<HostVmMemoryRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl api::HostIntxSender for HostState {
    fn send(&mut self, self_: Resource<HostIntxSenderRes>) -> Result<(), String> {
        let sender = self.table.get(&self_).map_err(|e| e.to_string())?;
        sender.send().map_err(|e| e.to_string())
    }

    fn drop(&mut self, rep: Resource<HostIntxSenderRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl api::HostMsiSender for HostState {
    fn send(
        &mut self,
        self_: Resource<HostMsiSenderRes>,
        addr: u64,
        data: u32,
    ) -> Result<(), String> {
        let sender = self.table.get(&self_).map_err(|e| e.to_string())?;
        sender.send(addr, data).map_err(|e| e.to_string())
    }

    fn drop(&mut self, rep: Resource<HostMsiSenderRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl api::HostSerialConsole for HostState {
    fn write_byte(
        &mut self,
        self_: Resource<HostSerialConsoleRes>,
        byte: u8,
    ) -> Result<(), String> {
        let serial = self.table.get(&self_).map_err(|e| e.to_string())?;
        serial.write_byte(byte).map_err(|e| e.to_string())
    }

    fn read_input(
        &mut self,
        self_: Resource<HostSerialConsoleRes>,
    ) -> Result<Option<Vec<u8>>, String> {
        let serial = self.table.get(&self_).map_err(|e| e.to_string())?;
        let mut buf = VecDeque::new();
        match serial.read_input(&mut buf).map_err(|e| e.to_string())? {
            None => Ok(None),
            Some(_) => Ok(Some(buf.into_iter().collect())),
        }
    }

    fn shutdown(&mut self, self_: Resource<HostSerialConsoleRes>) -> Result<(), String> {
        let serial = self.table.get(&self_).map_err(|e| e.to_string())?;
        serial.shutdown().map_err(|e| e.to_string())
    }

    fn drop(&mut self, rep: Resource<HostSerialConsoleRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl api::HostTap for HostState {
    fn detected_offload(&mut self, self_: Resource<HostTapRes>) -> u64 {
        let tap = self.table.get(&self_).unwrap();
        tap.detected_offload().bits()
    }

    fn enable_offload(&mut self, self_: Resource<HostTapRes>, feature: u64) -> Result<(), String> {
        let tap = self.table.get_mut(&self_).map_err(|e| e.to_string())?;
        tap.enable_offload(NetFeature::from_bits_retain(feature))
            .map_err(|e| e.to_string())
    }

    fn register(
        &mut self,
        self_: Resource<HostTapRes>,
        token: u64,
        interests: u8,
    ) -> Result<(), String> {
        let tap = self.table.get(&self_).map_err(|e| e.to_string())?;
        tap.register(Token(token), Interest::from_bits_retain(interests))
            .map_err(|e| e.to_string())
    }

    fn deregister(&mut self, self_: Resource<HostTapRes>) {
        if let Ok(tap) = self.table.get(&self_) {
            tap.deregister();
        }
    }

    fn read(
        &mut self,
        self_: Resource<HostTapRes>,
        max_len: u64,
    ) -> Result<Vec<u8>, api::IoError> {
        let tap = self
            .table
            .get(&self_)
            .map_err(|e| api::IoError::Other(e.to_string()))?;
        let mut buf = vec![0u8; max_len as usize];
        let n = tap
            .read_vectored(&mut [IoSliceMut::new(&mut buf)])
            .map_err(to_wit_io_err)?;
        buf.truncate(n);
        Ok(buf)
    }

    fn write(
        &mut self,
        self_: Resource<HostTapRes>,
        data: Vec<u8>,
    ) -> Result<u64, api::IoError> {
        let tap = self
            .table
            .get(&self_)
            .map_err(|e| api::IoError::Other(e.to_string()))?;
        let n = tap
            .write_vectored(&[IoSlice::new(&data)])
            .map_err(to_wit_io_err)?;
        Ok(n as u64)
    }

    fn drop(&mut self, rep: Resource<HostTapRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl api::HostVcpu for HostState {
    fn get_reg(&mut self, self_: Resource<HostVcpuRes>, r: api::Reg) -> Result<u64, String> {
        let vcpu = self.table.get(&self_).map_err(|e| e.to_string())?;
        vcpu.get_reg(from_wit_reg(r)).map_err(|e| e.to_string())
    }

    fn set_regs(
        &mut self,
        self_: Resource<HostVcpuRes>,
        vals: Vec<(api::Reg, u64)>,
    ) -> Result<(), String> {
        let vcpu = self.table.get_mut(&self_).map_err(|e| e.to_string())?;
        let host_vals: Vec<_> = vals.into_iter().map(|(r, v)| (from_wit_reg(r), v)).collect();
        vcpu.set_regs(&host_vals).map_err(|e| e.to_string())
    }

    fn get_seg_reg(
        &mut self,
        self_: Resource<HostVcpuRes>,
        r: api::SegReg,
    ) -> Result<api::SegRegVal, String> {
        let vcpu = self.table.get(&self_).map_err(|e| e.to_string())?;
        vcpu.get_seg_reg(from_wit_seg_reg(r))
            .map(to_wit_seg_reg_val)
            .map_err(|e| e.to_string())
    }

    fn get_dt_reg(
        &mut self,
        self_: Resource<HostVcpuRes>,
        r: api::DtReg,
    ) -> Result<api::DtRegVal, String> {
        let vcpu = self.table.get(&self_).map_err(|e| e.to_string())?;
        vcpu.get_dt_reg(from_wit_dt_reg(r))
            .map(to_wit_dt_reg_val)
            .map_err(|e| e.to_string())
    }

    fn get_sreg(&mut self, self_: Resource<HostVcpuRes>, r: api::SReg) -> Result<u64, String> {
        let vcpu = self.table.get(&self_).map_err(|e| e.to_string())?;
        vcpu.get_sreg(from_wit_sreg(r)).map_err(|e| e.to_string())
    }

    fn set_sregs(
        &mut self,
        self_: Resource<HostVcpuRes>,
        sregs: Vec<(api::SReg, u64)>,
        seg_regs: Vec<(api::SegReg, api::SegRegVal)>,
        dt_regs: Vec<(api::DtReg, api::DtRegVal)>,
    ) -> Result<(), String> {
        let vcpu = self.table.get_mut(&self_).map_err(|e| e.to_string())?;
        let host_sregs: Vec<_> = sregs
            .into_iter()
            .map(|(r, v)| (from_wit_sreg(r), v))
            .collect();
        let host_seg_regs: Vec<_> = seg_regs
            .into_iter()
            .map(|(r, v)| (from_wit_seg_reg(r), from_wit_seg_reg_val(v)))
            .collect();
        let host_dt_regs: Vec<_> = dt_regs
            .into_iter()
            .map(|(r, v)| (from_wit_dt_reg(r), from_wit_dt_reg_val(v)))
            .collect();
        vcpu.set_sregs(&host_sregs, &host_seg_regs, &host_dt_regs)
            .map_err(|e| e.to_string())
    }

    fn set_cpuids(
        &mut self,
        self_: Resource<HostVcpuRes>,
        cpuids: Vec<api::Cpuid>,
    ) -> Result<(), String> {
        let vcpu = self.table.get_mut(&self_).map_err(|e| e.to_string())?;
        let host_cpuids: Vec<_> = cpuids.into_iter().map(from_wit_cpuid).collect();
        vcpu.set_cpuids(host_cpuids).map_err(|e| e.to_string())
    }

    fn dump(&mut self, self_: Resource<HostVcpuRes>) -> Result<(), String> {
        let vcpu = self.table.get(&self_).map_err(|e| e.to_string())?;
        vcpu.dump().map_err(|e| e.to_string())
    }

    fn drop(&mut self, rep: Resource<HostVcpuRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl api::HostVm for HostState {
    fn create_vcpu(
        &mut self,
        self_: Resource<HostVmRes>,
        id: u32,
    ) -> Result<Resource<HostVcpuRes>, String> {
        let vcpu = {
            let vm = self.table.get(&self_).map_err(|e| e.to_string())?;
            vm.create_vcpu(id).map_err(|e| e.to_string())?
        };
        self.table.push(vcpu).map_err(|e| e.to_string())
    }

    fn stop_vcpu(&mut self, self_: Resource<HostVmRes>, id: u32) -> Result<(), String> {
        let vm = self.table.get(&self_).map_err(|e| e.to_string())?;
        vm.stop_vcpu(id).map_err(|e| e.to_string())
    }

    fn resume_vcpu(
        &mut self,
        self_: Resource<HostVmRes>,
        id: u32,
        entry: api::VmEntry,
    ) -> Result<(), String> {
        let vm = self.table.get(&self_).map_err(|e| e.to_string())?;
        vm.resume_vcpu(id, from_wit_vm_entry(entry))
            .map_err(|e| e.to_string())
    }

    fn next_event(&mut self, self_: Resource<HostVmRes>) -> Result<api::VmEvent, String> {
        let vm = self.table.get(&self_).map_err(|e| e.to_string())?;
        vm.next_event()
            .map(to_wit_vm_event)
            .map_err(|e| e.to_string())
    }

    fn create_vm_memory(
        &mut self,
        self_: Resource<HostVmRes>,
    ) -> Result<Resource<HostVmMemoryRes>, String> {
        let mem = {
            let vm = self.table.get_mut(&self_).map_err(|e| e.to_string())?;
            vm.create_vm_memory().map_err(|e| e.to_string())?
        };
        self.table.push(mem).map_err(|e| e.to_string())
    }

    fn create_intx_sender(
        &mut self,
        self_: Resource<HostVmRes>,
        pin: u8,
    ) -> Result<Resource<HostIntxSenderRes>, String> {
        let sender = {
            let vm = self.table.get(&self_).map_err(|e| e.to_string())?;
            vm.create_intx_sender(pin).map_err(|e| e.to_string())?
        };
        self.table.push(sender).map_err(|e| e.to_string())
    }

    fn create_msi_sender(
        &mut self,
        self_: Resource<HostVmRes>,
    ) -> Result<Resource<HostMsiSenderRes>, String> {
        let sender = {
            let vm = self.table.get(&self_).map_err(|e| e.to_string())?;
            vm.create_msi_sender().map_err(|e| e.to_string())?
        };
        self.table.push(sender).map_err(|e| e.to_string())
    }

    fn create_serial_console(
        &mut self,
        self_: Resource<HostVmRes>,
    ) -> Result<Resource<HostSerialConsoleRes>, String> {
        let serial = {
            let vm = self.table.get(&self_).map_err(|e| e.to_string())?;
            vm.create_serial_console().map_err(|e| e.to_string())?
        };
        self.table.push(serial).map_err(|e| e.to_string())
    }

    fn create_tap(
        &mut self,
        self_: Resource<HostVmRes>,
        if_name: Option<String>,
    ) -> Result<Resource<HostTapRes>, String> {
        let tap = {
            let vm = self.table.get(&self_).map_err(|e| e.to_string())?;
            vm.create_tap(if_name.as_deref())
                .map_err(|e| e.to_string())?
        };
        self.table.push(tap).map_err(|e| e.to_string())
    }

    fn drop(&mut self, rep: Resource<HostVmRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl api::HostHypervisor for HostState {
    fn create_vm(
        &mut self,
        self_: Resource<HostHypervisorRes>,
    ) -> Result<Resource<HostVmRes>, String> {
        let vm = {
            let hv = self.table.get(&self_).map_err(|e| e.to_string())?;
            hv.create_vm().map_err(|e| e.to_string())?
        };
        self.table.push(vm).map_err(|e| e.to_string())
    }

    fn get_supported_cpuids(
        &mut self,
        self_: Resource<HostHypervisorRes>,
    ) -> Result<Vec<api::Cpuid>, String> {
        let hv = self.table.get(&self_).map_err(|e| e.to_string())?;
        let cpuids = hv.get_supported_cpuids().map_err(|e| e.to_string())?;
        Ok(cpuids.into_iter().map(to_wit_cpuid).collect())
    }

    fn drop(&mut self, rep: Resource<HostHypervisorRes>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

impl api::Host for HostState {
    fn get_hypervisor(&mut self) -> Result<Resource<HostHypervisorRes>, String> {
        let kvm = Kvm::new().map_err(|e| e.to_string())?;
        self.table.push(kvm).map_err(|e| e.to_string())
    }
}

fn add_wasi_without_sockets_to_linker(linker: &mut Linker<HostState>) -> wasmtime::Result<()> {
    use wasmtime_wasi::cli::{WasiCli, WasiCliView as _};
    use wasmtime_wasi::clocks::{WasiClocks, WasiClocksView as _};
    use wasmtime_wasi::filesystem::{WasiFilesystem, WasiFilesystemView as _};
    use wasmtime_wasi::p2::bindings::{cli, clocks, filesystem, random, sync};
    use wasmtime_wasi::random::{WasiRandom, WasiRandomView as _};

    struct HasIo;
    impl wasmtime::component::HasData for HasIo {
        type Data<'a> = &'a mut ResourceTable;
    }

    clocks::wall_clock::add_to_linker::<HostState, WasiClocks>(linker, HostState::clocks)?;
    clocks::monotonic_clock::add_to_linker::<HostState, WasiClocks>(linker, HostState::clocks)?;
    filesystem::preopens::add_to_linker::<HostState, WasiFilesystem>(
        linker,
        HostState::filesystem,
    )?;
    sync::filesystem::types::add_to_linker::<HostState, WasiFilesystem>(
        linker,
        HostState::filesystem,
    )?;
    random::random::add_to_linker::<HostState, WasiRandom>(linker, HostState::random)?;
    random::insecure::add_to_linker::<HostState, WasiRandom>(linker, HostState::random)?;
    random::insecure_seed::add_to_linker::<HostState, WasiRandom>(linker, HostState::random)?;
    cli::exit::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    cli::environment::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    cli::stdin::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    cli::stdout::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    cli::stderr::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    cli::terminal_input::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    cli::terminal_output::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    cli::terminal_stdin::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    cli::terminal_stdout::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    cli::terminal_stderr::add_to_linker::<HostState, WasiCli>(linker, HostState::cli)?;
    wasmtime_wasi_io::bindings::wasi::io::error::add_to_linker::<HostState, HasIo>(linker, |t| {
        t.ctx().table
    })?;
    sync::io::poll::add_to_linker::<HostState, HasIo>(linker, |t| t.ctx().table)?;
    sync::io::streams::add_to_linker::<HostState, HasIo>(linker, |t| t.ctx().table)?;
    Ok(())
}

pub fn run_wasm_vmm(
    component_path: &Path,
    config_filename: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let engine = Engine::default();
    #[cfg(feature = "compiler")]
    let component = Component::from_file(&engine, component_path)?;
    #[cfg(not(feature = "compiler"))]
    let component = unsafe { Component::deserialize_file(&engine, component_path)? };

    let mut linker = Linker::<HostState>::new(&engine);
    add_wasi_without_sockets_to_linker(&mut linker)?;
    VmmWorld::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)?;

    let mut wasi_builder = WasiCtxBuilder::new();
    wasi_builder
        .allow_blocking_current_thread(true)
        .inherit_stdio()
        .inherit_args()
        .inherit_env()
        .preopened_dir("/", "/", FsPerms::ReadWrite)?
        .preopened_dir("/tmp", "/tmp", FsPerms::ReadWrite)?;

    let cwd = std::env::current_dir().ok();

    if let Some(parent) = Path::new(config_filename)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        && cwd.as_deref() != Some(parent)
        && let Some(parent_str) = parent.to_str()
    {
        let _ = wasi_builder.preopened_dir(parent, parent_str, FsPerms::ReadWrite);
    }

    if let Ok(config_contents) = std::fs::read_to_string(config_filename) {
        for token in config_contents.split('"') {
            if token.starts_with('/')
                && let Some(parent) = Path::new(token).parent()
                && parent != Path::new("/")
                && cwd.as_deref() != Some(parent)
                && parent.is_dir()
                && let Some(parent_str) = parent.to_str()
            {
                let _ = wasi_builder.preopened_dir(parent, parent_str, FsPerms::ReadWrite);
            }
        }
    }

    wasi_builder.preopened_dir(".", ".", FsPerms::ReadWrite)?;

    let state = HostState {
        wasi: wasi_builder.build(),
        table: ResourceTable::new(),
    };
    let mut store = Store::new(&engine, state);

    let instance = VmmWorld::instantiate(&mut store, &component, &linker)?;
    instance
        .call_run(&mut store, config_filename)?
        .map_err(|e| format!("vmm-runner wasm error: {e}"))?;

    Ok(())
}
