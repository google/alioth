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

use std::io::ErrorKind;
use std::ops::{Deref, DerefMut};
use std::os::fd::{OwnedFd, RawFd};
use std::ptr::null_mut;

use libc::{MAP_FAILED, MAP_SHARED, PROT_READ, PROT_WRITE, mmap, munmap};
use vmm_core::host::abi::{
    GPR_R8, GPR_R9, GPR_R10, GPR_R11, GPR_R12, GPR_R13, GPR_R14, GPR_R15, GPR_RAX, GPR_RBP,
    GPR_RBX, GPR_RCX, GPR_RDI, GPR_RDX, GPR_RSI, GPR_RSP, RawCpuid, RawSegReg, RawVmEntry,
    RawVmExit, SYNC_REG_GPRS, SYNC_REG_RIP_RFLAGS, SYNC_REG_SREGS, VcpuCommPage,
};
use vmm_core::host::arch::{DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use vmm_core::host::{HvError, HvResult, MpState, RegId, RegVal, VmEntry, VmExit};
use vmm_core::hw::layout::IOAPIC_START;
use vmm_core::hw::reg::SegAccess;

use crate::ffi;
use crate::kvm::bindings::{
    KVM_EXIT_CPUID, KVM_EXIT_INTERNAL_ERROR, KVM_EXIT_IO, KVM_EXIT_IO_IN, KVM_EXIT_IO_OUT,
    KVM_EXIT_IOAPIC_EOI, KVM_EXIT_MMIO, KVM_EXIT_SHUTDOWN, KVM_EXIT_SYSTEM_EVENT,
    KVM_EXIT_X86_RDMSR, KVM_EXIT_X86_WRMSR, KVM_INTERNAL_ERROR_EMULATION,
    KVM_INTERNAL_ERROR_EMULATION_FLAG_INSTRUCTION_BYTES, KVM_MAX_CPUID_ENTRIES,
    KVM_SYNC_X86_EVENTS, KVM_SYNC_X86_REGS, KVM_SYNC_X86_SREGS, KVM_SYSTEM_EVENT_RESET,
    KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KvmMpState, KvmMsrEntry, KvmMsrs, KvmRegs, KvmRun,
    KvmSregs, kvm_get_mp_state, kvm_get_msrs, kvm_get_regs, kvm_get_sregs, kvm_run,
    kvm_set_cpuid2, kvm_set_mp_state, kvm_set_msrs, kvm_set_regs, kvm_set_sregs,
};

pub(crate) fn io_to_hv_err(e: std::io::Error) -> HvError {
    match e.kind() {
        ErrorKind::WouldBlock => HvError::WouldBlock,
        ErrorKind::Interrupted => HvError::Interrupted,
        ErrorKind::InvalidInput => HvError::InvalidParam,
        ErrorKind::OutOfMemory => HvError::NoMemory,
        ErrorKind::Unsupported => HvError::Unsupported,
        _ => HvError::HardwareFault,
    }
}

pub(crate) struct KvmRunBlock {
    addr: usize,
    size: usize,
}

impl KvmRunBlock {
    pub unsafe fn new(fd: RawFd, mmap_size: usize) -> HvResult<KvmRunBlock> {
        let prot = PROT_READ | PROT_WRITE;
        let addr = ffi!(
            unsafe { mmap(null_mut(), mmap_size, prot, MAP_SHARED, fd, 0) },
            MAP_FAILED
        )
        .map_err(io_to_hv_err)?;
        Ok(KvmRunBlock {
            addr: addr as usize,
            size: mmap_size,
        })
    }

    pub(super) unsafe fn data_slice<T>(&self, offset: usize, count: usize) -> &[T] {
        unsafe { std::slice::from_raw_parts((self.addr + offset) as *const T, count) }
    }

    pub(super) unsafe fn data_slice_mut<T>(&mut self, offset: usize, count: usize) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut((self.addr + offset) as *mut T, count) }
    }
}

impl Deref for KvmRunBlock {
    type Target = KvmRun;

    fn deref(&self) -> &Self::Target {
        unsafe { &*(self.addr as *const Self::Target) }
    }
}

impl DerefMut for KvmRunBlock {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *(self.addr as *mut Self::Target) }
    }
}

impl Drop for KvmRunBlock {
    fn drop(&mut self) {
        if let Err(e) = ffi!(unsafe { munmap(self.addr as _, self.size) }) {
            log::error!("unmap kvm_run: {e}")
        }
    }
}

pub struct KvmVcpu {
    pub(crate) kvm_run: KvmRunBlock,
    pub(crate) fd: OwnedFd,
    pub(crate) sync_regs_cap: u64,
    pub(crate) sync_regs_valid: bool,
}

macro_rules! set_kvm_sreg {
    ($kvm_sregs:ident, $sreg:ident, $val:expr) => {{
        match $sreg {
            SReg::Cr0 => $kvm_sregs.cr0 = $val,
            SReg::Cr2 => $kvm_sregs.cr2 = $val,
            SReg::Cr3 => $kvm_sregs.cr3 = $val,
            SReg::Cr4 => $kvm_sregs.cr4 = $val,
            SReg::Cr8 => $kvm_sregs.cr8 = $val,
            SReg::Efer => $kvm_sregs.efer = $val,
            SReg::ApicBase => $kvm_sregs.apic_base = $val,
        }
    }};
}

macro_rules! set_kvm_dt_reg {
    ($kvm_sregs:ident, $dt_reg:ident, $val:expr) => {{
        let target = match $dt_reg {
            DtReg::Idtr => &mut $kvm_sregs.idt,
            DtReg::Gdtr => &mut $kvm_sregs.gdt,
        };
        target.limit = $val.limit;
        target.base = $val.base;
    }};
}

macro_rules! set_kvm_seg_reg {
    ($kvm_sregs:ident, $seg_reg:ident, $val:expr) => {{
        let target = match $seg_reg {
            SegReg::Cs => &mut $kvm_sregs.cs,
            SegReg::Ds => &mut $kvm_sregs.ds,
            SegReg::Es => &mut $kvm_sregs.es,
            SegReg::Fs => &mut $kvm_sregs.fs,
            SegReg::Gs => &mut $kvm_sregs.gs,
            SegReg::Ss => &mut $kvm_sregs.ss,
            SegReg::Tr => &mut $kvm_sregs.tr,
            SegReg::Ldtr => &mut $kvm_sregs.ldt,
        };
        target.selector = $val.selector;
        target.base = $val.base;
        target.limit = $val.limit;
        target.type_ = $val.access.seg_type() as u8;
        target.s = $val.access.s_code_data() as u8;
        target.dpl = $val.access.priv_level() as u8;
        target.present = $val.access.present() as u8;
        target.avl = $val.access.available() as u8;
        target.db = $val.access.db_size_32() as u8;
        target.g = $val.access.granularity() as u8;
        target.l = $val.access.l_64bit() as u8;
        target.unusable = $val.access.unusable() as u8;
    }};
}

macro_rules! get_kvm_sreg {
    ($kvm_sregs:ident, $sreg:ident) => {
        match $sreg {
            SReg::Cr0 => $kvm_sregs.cr0,
            SReg::Cr2 => $kvm_sregs.cr2,
            SReg::Cr3 => $kvm_sregs.cr3,
            SReg::Cr4 => $kvm_sregs.cr4,
            SReg::Cr8 => $kvm_sregs.cr8,
            SReg::Efer => $kvm_sregs.efer,
            SReg::ApicBase => $kvm_sregs.apic_base,
        }
    };
}

macro_rules! get_kvm_dt_reg {
    ($kvm_sregs:ident, $dt_reg:ident) => {{
        let target = match $dt_reg {
            DtReg::Idtr => $kvm_sregs.idt,
            DtReg::Gdtr => $kvm_sregs.gdt,
        };
        DtRegVal {
            limit: target.limit,
            base: target.base,
        }
    }};
}

macro_rules! get_kvm_seg_reg {
    ($kvm_sregs:ident, $seg_reg:ident) => {{
        let kvm_segment = match $seg_reg {
            SegReg::Cs => $kvm_sregs.cs,
            SegReg::Ds => $kvm_sregs.ds,
            SegReg::Es => $kvm_sregs.es,
            SegReg::Fs => $kvm_sregs.fs,
            SegReg::Gs => $kvm_sregs.gs,
            SegReg::Ss => $kvm_sregs.ss,
            SegReg::Tr => $kvm_sregs.tr,
            SegReg::Ldtr => $kvm_sregs.ldt,
        };
        let access = (kvm_segment.unusable as u32) << 16
            | (kvm_segment.g as u32) << 15
            | (kvm_segment.db as u32) << 14
            | (kvm_segment.l as u32) << 13
            | (kvm_segment.avl as u32) << 12
            | (kvm_segment.present as u32) << 7
            | (kvm_segment.dpl as u32) << 5
            | (kvm_segment.s as u32) << 4
            | (kvm_segment.type_ as u32);
        SegRegVal {
            selector: kvm_segment.selector,
            base: kvm_segment.base,
            limit: kvm_segment.limit,
            access: SegAccess(access),
        }
    }};
}

fn read_gpr(kvm_regs: &KvmRegs, reg: Reg) -> u64 {
    match reg {
        Reg::Rax => kvm_regs.rax,
        Reg::Rbx => kvm_regs.rbx,
        Reg::Rcx => kvm_regs.rcx,
        Reg::Rdx => kvm_regs.rdx,
        Reg::Rsi => kvm_regs.rsi,
        Reg::Rdi => kvm_regs.rdi,
        Reg::Rsp => kvm_regs.rsp,
        Reg::Rbp => kvm_regs.rbp,
        Reg::R8 => kvm_regs.r8,
        Reg::R9 => kvm_regs.r9,
        Reg::R10 => kvm_regs.r10,
        Reg::R11 => kvm_regs.r11,
        Reg::R12 => kvm_regs.r12,
        Reg::R13 => kvm_regs.r13,
        Reg::R14 => kvm_regs.r14,
        Reg::R15 => kvm_regs.r15,
        Reg::Rip => kvm_regs.rip,
        Reg::Rflags => kvm_regs.rflags,
    }
}

fn write_gpr(kvm_regs: &mut KvmRegs, reg: Reg, val: u64) {
    match reg {
        Reg::Rax => kvm_regs.rax = val,
        Reg::Rbx => kvm_regs.rbx = val,
        Reg::Rcx => kvm_regs.rcx = val,
        Reg::Rdx => kvm_regs.rdx = val,
        Reg::Rsi => kvm_regs.rsi = val,
        Reg::Rdi => kvm_regs.rdi = val,
        Reg::Rsp => kvm_regs.rsp = val,
        Reg::Rbp => kvm_regs.rbp = val,
        Reg::R8 => kvm_regs.r8 = val,
        Reg::R9 => kvm_regs.r9 = val,
        Reg::R10 => kvm_regs.r10 = val,
        Reg::R11 => kvm_regs.r11 = val,
        Reg::R12 => kvm_regs.r12 = val,
        Reg::R13 => kvm_regs.r13 = val,
        Reg::R14 => kvm_regs.r14 = val,
        Reg::R15 => kvm_regs.r15 = val,
        Reg::Rip => kvm_regs.rip = val,
        Reg::Rflags => kvm_regs.rflags = val,
    }
}

fn copy_kvm_regs_to_comm(regs: &KvmRegs, comm: &mut VcpuCommPage) {
    comm.gprs[GPR_RAX] = regs.rax;
    comm.gprs[GPR_RCX] = regs.rcx;
    comm.gprs[GPR_RDX] = regs.rdx;
    comm.gprs[GPR_RBX] = regs.rbx;
    comm.gprs[GPR_RSP] = regs.rsp;
    comm.gprs[GPR_RBP] = regs.rbp;
    comm.gprs[GPR_RSI] = regs.rsi;
    comm.gprs[GPR_RDI] = regs.rdi;
    comm.gprs[GPR_R8] = regs.r8;
    comm.gprs[GPR_R9] = regs.r9;
    comm.gprs[GPR_R10] = regs.r10;
    comm.gprs[GPR_R11] = regs.r11;
    comm.gprs[GPR_R12] = regs.r12;
    comm.gprs[GPR_R13] = regs.r13;
    comm.gprs[GPR_R14] = regs.r14;
    comm.gprs[GPR_R15] = regs.r15;
    comm.rip = regs.rip;
    comm.rflags = regs.rflags;
}

fn copy_comm_gprs_to_kvm(comm: &VcpuCommPage, regs: &mut KvmRegs) {
    regs.rax = comm.gprs[GPR_RAX];
    regs.rcx = comm.gprs[GPR_RCX];
    regs.rdx = comm.gprs[GPR_RDX];
    regs.rbx = comm.gprs[GPR_RBX];
    regs.rsp = comm.gprs[GPR_RSP];
    regs.rbp = comm.gprs[GPR_RBP];
    regs.rsi = comm.gprs[GPR_RSI];
    regs.rdi = comm.gprs[GPR_RDI];
    regs.r8 = comm.gprs[GPR_R8];
    regs.r9 = comm.gprs[GPR_R9];
    regs.r10 = comm.gprs[GPR_R10];
    regs.r11 = comm.gprs[GPR_R11];
    regs.r12 = comm.gprs[GPR_R12];
    regs.r13 = comm.gprs[GPR_R13];
    regs.r14 = comm.gprs[GPR_R14];
    regs.r15 = comm.gprs[GPR_R15];
}

fn copy_kvm_sregs_to_comm(sregs: &KvmSregs, comm: &mut VcpuCommPage) {
    comm.cr0 = sregs.cr0;
    comm.cr2 = sregs.cr2;
    comm.cr3 = sregs.cr3;
    comm.cr4 = sregs.cr4;
    comm.efer = sregs.efer;
    let cs_seg = SegReg::Cs;
    comm.cs = RawSegReg::from(get_kvm_seg_reg!(sregs, cs_seg));
    comm.ds_base = sregs.ds.base;
    comm.es_base = sregs.es.base;
    comm.fs_base = sregs.fs.base;
    comm.gs_base = sregs.gs.base;
    comm.ss_base = sregs.ss.base;
}

fn copy_comm_sregs_to_kvm(comm: &VcpuCommPage, sregs: &mut KvmSregs) {
    sregs.cr0 = comm.cr0;
    sregs.cr2 = comm.cr2;
    sregs.cr3 = comm.cr3;
    sregs.cr4 = comm.cr4;
    sregs.efer = comm.efer;
    let cs_seg = SegReg::Cs;
    let cs_val = SegRegVal::from(comm.cs);
    set_kvm_seg_reg!(sregs, cs_seg, cs_val);
}

impl KvmVcpu {
    fn flush_comm_dirty_regs(&mut self, comm: &mut VcpuCommPage) -> HvResult<()> {
        let dirty = comm.dirty_regs;
        if dirty == 0 {
            return Ok(());
        }
        let has_fast_sync = (self.sync_regs_cap & (KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS))
            == (KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS);

        if has_fast_sync {
            if !self.sync_regs_valid {
                let regs = unsafe { kvm_get_regs(&self.fd) }.map_err(io_to_hv_err)?;
                let sregs = unsafe { kvm_get_sregs(&self.fd) }.map_err(io_to_hv_err)?;
                let sync = unsafe { &mut self.kvm_run.s.regs };
                sync.regs = regs;
                sync.sregs = sregs;
                self.sync_regs_valid = true;
            }
            if (dirty & (SYNC_REG_GPRS | SYNC_REG_RIP_RFLAGS)) != 0 {
                let regs = unsafe { &mut self.kvm_run.s.regs.regs };
                if (dirty & SYNC_REG_GPRS) != 0 {
                    copy_comm_gprs_to_kvm(comm, regs);
                }
                if (dirty & SYNC_REG_RIP_RFLAGS) != 0 {
                    regs.rip = comm.rip;
                    regs.rflags = comm.rflags;
                }
                self.kvm_run.kvm_dirty_regs |= KVM_SYNC_X86_REGS;
            }
            if (dirty & SYNC_REG_SREGS) != 0 {
                let sregs = unsafe { &mut self.kvm_run.s.regs.sregs };
                copy_comm_sregs_to_kvm(comm, sregs);
                self.kvm_run.kvm_dirty_regs |= KVM_SYNC_X86_SREGS;
            }
        } else {
            if (dirty & (SYNC_REG_GPRS | SYNC_REG_RIP_RFLAGS)) != 0 {
                let mut regs = unsafe { kvm_get_regs(&self.fd) }.map_err(io_to_hv_err)?;
                if (dirty & SYNC_REG_GPRS) != 0 {
                    copy_comm_gprs_to_kvm(comm, &mut regs);
                }
                if (dirty & SYNC_REG_RIP_RFLAGS) != 0 {
                    regs.rip = comm.rip;
                    regs.rflags = comm.rflags;
                }
                unsafe { kvm_set_regs(&self.fd, &regs) }.map_err(io_to_hv_err)?;
            }
            if (dirty & SYNC_REG_SREGS) != 0 {
                let mut sregs = unsafe { kvm_get_sregs(&self.fd) }.map_err(io_to_hv_err)?;
                copy_comm_sregs_to_kvm(comm, &mut sregs);
                unsafe { kvm_set_sregs(&self.fd, &sregs) }.map_err(io_to_hv_err)?;
            }
        }
        comm.dirty_regs = 0;
        Ok(())
    }

    pub fn run(&mut self, comm: &mut VcpuCommPage) -> HvResult<()> {
        self.flush_comm_dirty_regs(comm)?;
        let entry = comm.entry.to_entry();
        match entry {
            VmEntry::None => {}
            VmEntry::Io { data } => self.entry_io(data),
            VmEntry::Mmio { data } => self.entry_mmio(data),
            VmEntry::Msr { data, error } => {
                let msr = unsafe { &mut self.kvm_run.exit.msr };
                msr.data = data;
                msr.error = error;
            }
            VmEntry::InjectFault { vector, error_code } => {
                if (self.sync_regs_cap & KVM_SYNC_X86_EVENTS) != 0 {
                    let ev = unsafe { &mut self.kvm_run.s.regs.events };
                    ev.exception.injected = 1;
                    ev.exception.nr = vector;
                    ev.exception.has_error_code = u8::from(error_code.is_some());
                    ev.exception.pending = 0;
                    ev.exception.error_code = error_code.unwrap_or(0);
                    self.kvm_run.kvm_dirty_regs |= KVM_SYNC_X86_EVENTS;
                }
            }
            VmEntry::Shutdown | VmEntry::Reboot => self.set_immediate_exit(true),
        };

        self.kvm_run.kvm_valid_regs =
            self.sync_regs_cap & (KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS | KVM_SYNC_X86_EVENTS);

        let ret = unsafe { kvm_run(&self.fd) };
        let vm_exit = match ret {
            Err(e) => match (e.kind(), entry) {
                (ErrorKind::WouldBlock, _) => VmExit::Interrupted,
                (ErrorKind::Interrupted, VmEntry::Shutdown) => {
                    self.set_immediate_exit(false);
                    VmExit::Shutdown
                }
                (ErrorKind::Interrupted, VmEntry::Reboot) => {
                    self.set_immediate_exit(false);
                    VmExit::Reboot
                }
                (ErrorKind::Interrupted, _) => {
                    self.set_immediate_exit(false);
                    VmExit::Interrupted
                }
                _ => return Err(io_to_hv_err(e)),
            },
            Ok(_) => {
                comm.synced_regs = 0;
                if (self.sync_regs_cap & KVM_SYNC_X86_REGS) != 0 {
                    let regs = unsafe { &self.kvm_run.s.regs.regs };
                    copy_kvm_regs_to_comm(regs, comm);
                    comm.synced_regs |= SYNC_REG_GPRS | SYNC_REG_RIP_RFLAGS;
                }
                if (self.sync_regs_cap & KVM_SYNC_X86_SREGS) != 0 {
                    let sregs = unsafe { &self.kvm_run.s.regs.sregs };
                    copy_kvm_sregs_to_comm(sregs, comm);
                    comm.synced_regs |= SYNC_REG_SREGS;
                }
                if (self.sync_regs_cap & (KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS))
                    == (KVM_SYNC_X86_REGS | KVM_SYNC_X86_SREGS)
                {
                    self.sync_regs_valid = true;
                }

                match self.kvm_run.exit_reason {
                    KVM_EXIT_IO => self.handle_io()?,
                    KVM_EXIT_MMIO => self.handle_mmio()?,
                    KVM_EXIT_SHUTDOWN => VmExit::Shutdown,
                    KVM_EXIT_SYSTEM_EVENT => {
                        let ev_type = unsafe { self.kvm_run.exit.system_event.type_ };
                        if ev_type == KVM_SYSTEM_EVENT_RESET {
                            VmExit::Reboot
                        } else {
                            VmExit::Shutdown
                        }
                    }
                    KVM_EXIT_IOAPIC_EOI => {
                        let vector = unsafe { self.kvm_run.exit.eoi.vector };
                        VmExit::Mmio {
                            gpa: (IOAPIC_START + 0x40) as u64,
                            write: Some(vector as u64),
                            size: 4,
                        }
                    }
                    KVM_EXIT_INTERNAL_ERROR => {
                        let ef = unsafe { self.kvm_run.exit.emulation_failure };
                        if ef.suberror == KVM_INTERNAL_ERROR_EMULATION {
                            let (insn_len, insn_bytes) =
                                if (ef.flags & KVM_INTERNAL_ERROR_EMULATION_FLAG_INSTRUCTION_BYTES)
                                    != 0
                                {
                                    (ef.insn_size.min(15), ef.insn_bytes)
                                } else {
                                    (0, [0u8; 15])
                                };
                            VmExit::MmioFault {
                                gpa: 0,
                                gva: None,
                                is_write: false,
                                insn_len,
                                insn_bytes,
                            }
                        } else {
                            log::error!("kvm internal error suberror={:#x}", ef.suberror);
                            return Err(HvError::HardwareFault);
                        }
                    }
                    KVM_EXIT_X86_RDMSR => {
                        let msr = unsafe { self.kvm_run.exit.msr.index };
                        VmExit::MsrRead { msr }
                    }
                    KVM_EXIT_X86_WRMSR => {
                        let msr = unsafe { self.kvm_run.exit.msr };
                        VmExit::MsrWrite {
                            msr: msr.index,
                            val: msr.data,
                        }
                    }
                    KVM_EXIT_CPUID => VmExit::Cpuid {
                        func: comm.gprs[GPR_RAX] as u32,
                        index: comm.gprs[GPR_RCX] as u32,
                    },
                    reason => {
                        log::error!("unknown kvm exit: {reason:#x}");
                        return Err(HvError::HardwareFault);
                    }
                }
            }
        };

        comm.exit = RawVmExit::from_exit(vm_exit);
        comm.entry = RawVmEntry::default();
        comm.dirty_regs = 0;
        Ok(())
    }

    pub(crate) fn immediate_exit_ptr(&mut self) -> *mut std::sync::atomic::AtomicU8 {
        (&mut self.kvm_run.immediate_exit as *mut u8).cast()
    }

    #[cfg(target_endian = "little")]
    pub(super) fn entry_mmio(&mut self, data: u64) {
        assert_eq!(self.kvm_run.exit_reason, KVM_EXIT_MMIO);
        let kvm_mmio = unsafe { &mut self.kvm_run.exit.mmio };
        assert_eq!(kvm_mmio.is_write, 0);
        kvm_mmio.data = data.to_ne_bytes();
    }

    pub(super) fn set_immediate_exit(&mut self, enable: bool) {
        self.kvm_run.immediate_exit = enable as u8;
    }

    pub(super) fn entry_io(&mut self, data: u32) {
        assert_eq!(self.kvm_run.exit_reason, KVM_EXIT_IO);
        let kvm_io = unsafe { &self.kvm_run.exit.io };
        assert_eq!(kvm_io.direction, KVM_EXIT_IO_IN);
        let offset = kvm_io.data_offset as usize;
        let count = kvm_io.count as usize;
        match kvm_io.size {
            1 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[0] = data as u8;
            },
            2 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[0] = data as u16;
            },
            4 => unsafe {
                self.kvm_run.data_slice_mut(offset, count)[0] = data;
            },
            _ => unreachable!("kvm_io.size = {}", kvm_io.size),
        }
    }

    #[cfg(target_endian = "little")]
    pub(super) fn handle_mmio(&mut self) -> HvResult<VmExit> {
        let kvm_mmio = unsafe { &self.kvm_run.exit.mmio };
        let exit = VmExit::Mmio {
            gpa: kvm_mmio.phys_addr,
            write: if kvm_mmio.is_write > 0 {
                Some(u64::from_ne_bytes(kvm_mmio.data))
            } else {
                None
            },
            size: kvm_mmio.len as u8,
        };
        Ok(exit)
    }

    pub(super) fn handle_io(&mut self) -> HvResult<VmExit> {
        let kvm_io = unsafe { &self.kvm_run.exit.io };
        let offset = kvm_io.data_offset as usize;
        let count = kvm_io.count as usize;
        assert_eq!(count, 1);
        let write = match (kvm_io.direction, kvm_io.size) {
            (KVM_EXIT_IO_IN, _) => None,
            (KVM_EXIT_IO_OUT, 1) => {
                Some(unsafe { self.kvm_run.data_slice::<u8>(offset, count) }[0] as u32)
            }
            (KVM_EXIT_IO_OUT, 2) => {
                Some(unsafe { self.kvm_run.data_slice::<u16>(offset, count) }[0] as u32)
            }
            (KVM_EXIT_IO_OUT, 4) => {
                Some(unsafe { self.kvm_run.data_slice::<u32>(offset, count) }[0])
            }
            _ => unreachable!(
                "kvm_io.direction = {}, kvm_io.size = {}",
                kvm_io.direction, kvm_io.size
            ),
        };
        Ok(VmExit::Io {
            port: kvm_io.port,
            write,
            size: kvm_io.size,
        })
    }

    pub fn configure_cpuids(&mut self, cpuids: &[RawCpuid]) -> HvResult<()> {
        if cpuids.len() > KVM_MAX_CPUID_ENTRIES {
            return Err(HvError::InvalidParam);
        }
        let mut kvm_cpuid2 = KvmCpuid2 {
            nent: cpuids.len() as u32,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
        };
        for (cpuid, entry) in cpuids.iter().zip(kvm_cpuid2.entries.iter_mut()) {
            entry.eax = cpuid.eax;
            entry.ebx = cpuid.ebx;
            entry.ecx = cpuid.ecx;
            entry.edx = cpuid.edx;
            entry.function = cpuid.func;
            if cpuid.has_index != 0 {
                entry.index = cpuid.index;
                entry.flags = KvmCpuid2Flag::SIGNIFCANT_INDEX;
            } else {
                entry.flags = KvmCpuid2Flag::empty();
            }
        }
        unsafe { kvm_set_cpuid2(&self.fd, &kvm_cpuid2) }.map_err(io_to_hv_err)?;
        Ok(())
    }

    pub fn get_regs_batch(&self, ids: &[RegId], out: &mut [RegVal]) -> HvResult<()> {
        if ids.len() != out.len() {
            return Err(HvError::InvalidParam);
        }
        let mut cached_regs: Option<KvmRegs> = None;
        let mut cached_sregs: Option<KvmSregs> = None;

        for (id, dst) in ids.iter().copied().zip(out.iter_mut()) {
            match id {
                RegId::Gpr(reg) => {
                    let kvm_regs = match &cached_regs {
                        Some(r) => r,
                        None => {
                            let r = unsafe { kvm_get_regs(&self.fd) }.map_err(io_to_hv_err)?;
                            cached_regs.insert(r)
                        }
                    };
                    *dst = RegVal::Scalar(read_gpr(kvm_regs, reg));
                }
                RegId::SReg(sreg) => {
                    let kvm_sregs = match &cached_sregs {
                        Some(s) => s,
                        None => {
                            let s = unsafe { kvm_get_sregs(&self.fd) }.map_err(io_to_hv_err)?;
                            cached_sregs.insert(s)
                        }
                    };
                    *dst = RegVal::Scalar(get_kvm_sreg!(kvm_sregs, sreg));
                }
                RegId::SegReg(seg_reg) => {
                    let kvm_sregs = match &cached_sregs {
                        Some(s) => s,
                        None => {
                            let s = unsafe { kvm_get_sregs(&self.fd) }.map_err(io_to_hv_err)?;
                            cached_sregs.insert(s)
                        }
                    };
                    *dst = RegVal::Seg(get_kvm_seg_reg!(kvm_sregs, seg_reg));
                }
                RegId::DtReg(dt_reg) => {
                    let kvm_sregs = match &cached_sregs {
                        Some(s) => s,
                        None => {
                            let s = unsafe { kvm_get_sregs(&self.fd) }.map_err(io_to_hv_err)?;
                            cached_sregs.insert(s)
                        }
                    };
                    *dst = RegVal::Dt(get_kvm_dt_reg!(kvm_sregs, dt_reg));
                }
                RegId::Msr(index) => {
                    let mut msrs = KvmMsrs::<1> {
                        nmsrs: 1,
                        pad: 0,
                        entries: [KvmMsrEntry {
                            index,
                            reserved: 0,
                            data: 0,
                        }],
                    };
                    let n = unsafe { kvm_get_msrs(&self.fd, &mut msrs) }.map_err(io_to_hv_err)?;
                    if n != 1 {
                        return Err(HvError::InvalidParam);
                    }
                    *dst = RegVal::Scalar(msrs.entries[0].data);
                }
                RegId::MpState => {
                    let st = unsafe { kvm_get_mp_state(&self.fd) }.map_err(io_to_hv_err)?;
                    *dst = RegVal::MpState(MpState::from_u32(st.mp_state)?);
                }
            }
        }
        Ok(())
    }

    pub fn set_regs_batch(&mut self, regs: &[(RegId, RegVal)]) -> HvResult<()> {
        self.kvm_run.kvm_dirty_regs = 0;
        self.sync_regs_valid = false;
        let mut has_sregs = false;
        let mut has_gprs = false;
        let mut msr_count = 0usize;
        let mut mp_state: Option<MpState> = None;

        for &(id, val) in regs {
            match (id, val) {
                (RegId::SReg(_), RegVal::Scalar(_))
                | (RegId::SegReg(_), RegVal::Seg(_))
                | (RegId::DtReg(_), RegVal::Dt(_)) => {
                    has_sregs = true;
                }
                (RegId::Gpr(_), RegVal::Scalar(_)) => {
                    has_gprs = true;
                }
                (RegId::Msr(_), RegVal::Scalar(_)) => {
                    msr_count += 1;
                }
                (RegId::MpState, RegVal::MpState(st)) => {
                    mp_state = Some(st);
                }
                _ => return Err(HvError::InvalidParam),
            }
        }

        if has_sregs {
            let mut kvm_sregs = unsafe { kvm_get_sregs(&self.fd) }.map_err(io_to_hv_err)?;
            for &(id, val) in regs {
                match (id, val) {
                    (RegId::SReg(sreg), RegVal::Scalar(v)) => set_kvm_sreg!(kvm_sregs, sreg, v),
                    (RegId::SegReg(seg_reg), RegVal::Seg(v)) => {
                        set_kvm_seg_reg!(kvm_sregs, seg_reg, v)
                    }
                    (RegId::DtReg(dt_reg), RegVal::Dt(v)) => set_kvm_dt_reg!(kvm_sregs, dt_reg, v),
                    _ => {}
                }
            }
            unsafe { kvm_set_sregs(&self.fd, &kvm_sregs) }.map_err(io_to_hv_err)?;
        }

        if has_gprs {
            let mut kvm_regs = unsafe { kvm_get_regs(&self.fd) }.map_err(io_to_hv_err)?;
            for &(id, val) in regs {
                if let (RegId::Gpr(reg), RegVal::Scalar(v)) = (id, val) {
                    write_gpr(&mut kvm_regs, reg, v);
                }
            }
            unsafe { kvm_set_regs(&self.fd, &kvm_regs) }.map_err(io_to_hv_err)?;
        }

        if msr_count > 0 {
            const MSR_CHUNK: usize = 32;
            let mut batch = KvmMsrs::<MSR_CHUNK> {
                nmsrs: 0,
                pad: 0,
                entries: [KvmMsrEntry::default(); MSR_CHUNK],
            };
            let mut idx = 0usize;
            for &(id, val) in regs {
                if let (RegId::Msr(msr), RegVal::Scalar(data)) = (id, val) {
                    batch.entries[idx] = KvmMsrEntry {
                        index: msr,
                        reserved: 0,
                        data,
                    };
                    idx += 1;
                    if idx == MSR_CHUNK {
                        batch.nmsrs = idx as u32;
                        let written =
                            unsafe { kvm_set_msrs(&self.fd, &batch) }.map_err(io_to_hv_err)?;
                        if written as usize != idx {
                            return Err(HvError::InvalidParam);
                        }
                        idx = 0;
                    }
                }
            }
            if idx > 0 {
                batch.nmsrs = idx as u32;
                let written = unsafe { kvm_set_msrs(&self.fd, &batch) }.map_err(io_to_hv_err)?;
                if written as usize != idx {
                    return Err(HvError::InvalidParam);
                }
            }
        }

        if let Some(st) = mp_state {
            let kvm_mp = KvmMpState {
                mp_state: st as u32,
            };
            unsafe { kvm_set_mp_state(&self.fd, &kvm_mp) }.map_err(io_to_hv_err)?;
        }

        Ok(())
    }
}
