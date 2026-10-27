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
use vmm_core::host::arch::{Cpuid, DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use vmm_core::host::{Error, Result, Vcpu, VmEntry, VmExit};
use vmm_core::hw::reg::SegAccess;

use crate::ffi;
use crate::kvm::bindings::{
    KVM_EXIT_IO, KVM_EXIT_IO_IN, KVM_EXIT_IO_OUT, KVM_EXIT_MMIO, KVM_EXIT_SHUTDOWN,
    KVM_MAX_CPUID_ENTRIES, KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KvmRegs, KvmRun,
    kvm_get_regs, kvm_get_sregs, kvm_get_sregs2, kvm_run, kvm_set_cpuid2, kvm_set_regs,
    kvm_set_sregs, kvm_set_sregs2,
};

pub(super) struct KvmRunBlock {
    addr: usize,
    size: usize,
}

impl KvmRunBlock {
    pub unsafe fn new(fd: RawFd, mmap_size: usize) -> Result<KvmRunBlock, Error> {
        let prot = PROT_READ | PROT_WRITE;
        let addr = ffi!(
            unsafe { mmap(null_mut(), mmap_size, prot, MAP_SHARED, fd, 0) },
            MAP_FAILED
        )?;
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
    pub(super) kvm_run: KvmRunBlock,
    pub(super) fd: OwnedFd,
}

macro_rules! set_kvm_sreg {
    ($kvm_sregs:ident, $sreg:ident, $val:expr) => {
        match $sreg {
            SReg::Cr0 => $kvm_sregs.cr0 = $val,
            SReg::Cr2 => $kvm_sregs.cr2 = $val,
            SReg::Cr3 => $kvm_sregs.cr3 = $val,
            SReg::Cr4 => $kvm_sregs.cr4 = $val,
            SReg::Cr8 => $kvm_sregs.cr8 = $val,
            SReg::Efer => $kvm_sregs.efer = $val,
            SReg::ApicBase => $kvm_sregs.apic_base = $val,
        }
    };
}

macro_rules! set_kvm_dt_reg {
    ($kvm_sregs:ident, $dt_reg:ident, $val:expr) => {
        let target = match $dt_reg {
            DtReg::Idtr => &mut $kvm_sregs.idt,
            DtReg::Gdtr => &mut $kvm_sregs.gdt,
        };
        target.limit = $val.limit;
        target.base = $val.base;
    };
}

macro_rules! set_kvm_seg_reg {
    ($kvm_sregs:ident, $seg_reg:ident, $val:expr) => {
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
    };
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

impl Vcpu for KvmVcpu {
    fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error> {
        KvmVcpu::run(self, entry)
    }

    fn get_reg(&self, reg: Reg) -> Result<u64, Error> {
        self.kvm_get_reg(reg)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal, Error> {
        self.kvm_get_dt_reg(reg)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal, Error> {
        self.kvm_get_seg_reg(reg)
    }

    #[cfg(target_arch = "x86_64")]
    fn get_sreg(&self, reg: SReg) -> Result<u64, Error> {
        self.kvm_get_sreg(reg)
    }

    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<(), Error> {
        self.kvm_set_regs(vals)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        self.kvm_set_sregs(sregs, seg_regs, dt_regs)
    }

    #[cfg(target_arch = "x86_64")]
    fn set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error> {
        self.kvm_set_cpuids(cpuids)
    }

    fn dump(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl KvmVcpu {
    pub fn run(&mut self, entry: VmEntry) -> Result<VmExit, Error> {
        match entry {
            VmEntry::None => {}
            VmEntry::Io { data } => self.entry_io(data),
            VmEntry::Mmio { data } => self.entry_mmio(data),
            VmEntry::Shutdown | VmEntry::Reboot => self.set_immediate_exit(true),
        };
        let ret = unsafe { kvm_run(&self.fd) };
        match ret {
            Err(e) => match (e.kind(), entry) {
                (ErrorKind::WouldBlock, _) => Ok(VmExit::Interrupted),
                (ErrorKind::Interrupted, VmEntry::Shutdown) => {
                    self.set_immediate_exit(false);
                    Ok(VmExit::Shutdown)
                }
                (ErrorKind::Interrupted, VmEntry::Reboot) => {
                    self.set_immediate_exit(false);
                    Ok(VmExit::Reboot)
                }
                (ErrorKind::Interrupted, _) => {
                    self.set_immediate_exit(false);
                    Ok(VmExit::Interrupted)
                }
                _ => Err(e.into()),
            },
            Ok(_) => match self.kvm_run.exit_reason {
                KVM_EXIT_IO => self.handle_io(),
                KVM_EXIT_MMIO => self.handle_mmio(),
                KVM_EXIT_SHUTDOWN => Ok(VmExit::Shutdown),
                reason => Ok(VmExit::Unknown(format!("unkown kvm exit: {reason:#x}"))),
            },
        }
    }

    pub(super) fn immediate_exit_ptr(&mut self) -> *mut std::sync::atomic::AtomicU8 {
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
    pub(super) fn handle_mmio(&mut self) -> Result<VmExit, Error> {
        let kvm_mmio = unsafe { &self.kvm_run.exit.mmio };
        let exit = VmExit::Mmio {
            addr: kvm_mmio.phys_addr,
            write: if kvm_mmio.is_write > 0 {
                Some(u64::from_ne_bytes(kvm_mmio.data))
            } else {
                None
            },
            size: kvm_mmio.len as u8,
        };
        Ok(exit)
    }

    pub(super) fn handle_io(&mut self) -> Result<VmExit, Error> {
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

    fn get_kvm_regs(&self) -> Result<KvmRegs> {
        let kvm_regs = unsafe { kvm_get_regs(&self.fd) }?;
        Ok(kvm_regs)
    }

    fn set_kvm_regs(&self, kvm_regs: &KvmRegs) -> Result<()> {
        unsafe { kvm_set_regs(&self.fd, kvm_regs) }?;
        Ok(())
    }

    pub fn kvm_set_regs(&self, vals: &[(Reg, u64)]) -> Result<()> {
        let mut kvm_regs = self.get_kvm_regs()?;
        for (reg, val) in vals {
            match reg {
                Reg::Rax => kvm_regs.rax = *val,
                Reg::Rbx => kvm_regs.rbx = *val,
                Reg::Rcx => kvm_regs.rcx = *val,
                Reg::Rdx => kvm_regs.rdx = *val,
                Reg::Rsi => kvm_regs.rsi = *val,
                Reg::Rdi => kvm_regs.rdi = *val,
                Reg::Rsp => kvm_regs.rsp = *val,
                Reg::Rbp => kvm_regs.rbp = *val,
                Reg::R8 => kvm_regs.r8 = *val,
                Reg::R9 => kvm_regs.r9 = *val,
                Reg::R10 => kvm_regs.r10 = *val,
                Reg::R11 => kvm_regs.r11 = *val,
                Reg::R12 => kvm_regs.r12 = *val,
                Reg::R13 => kvm_regs.r13 = *val,
                Reg::R14 => kvm_regs.r14 = *val,
                Reg::R15 => kvm_regs.r15 = *val,
                Reg::Rip => kvm_regs.rip = *val,
                Reg::Rflags => kvm_regs.rflags = *val,
            }
        }
        self.set_kvm_regs(&kvm_regs)
    }

    pub fn kvm_get_reg(&self, reg: Reg) -> Result<u64> {
        let kvm_regs = self.get_kvm_regs()?;
        let val = match reg {
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
        };
        Ok(val)
    }

    #[allow(dead_code)]
    pub fn kvm_set_sregs2(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        let mut kvm_sregs2 = unsafe { kvm_get_sregs2(&self.fd) }?;
        for (reg, val) in sregs {
            set_kvm_sreg!(kvm_sregs2, reg, *val)
        }
        for (reg, val) in dt_regs {
            set_kvm_dt_reg!(kvm_sregs2, reg, val);
        }
        for (reg, val) in seg_regs {
            set_kvm_seg_reg!(kvm_sregs2, reg, val);
        }
        unsafe { kvm_set_sregs2(&self.fd, &kvm_sregs2) }?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn kvm_get_dt_reg2(&self, reg: DtReg) -> Result<DtRegVal> {
        let kvm_sregs2 = unsafe { kvm_get_sregs2(&self.fd) }?;
        let val = get_kvm_dt_reg!(kvm_sregs2, reg);
        Ok(val)
    }

    #[allow(dead_code)]
    pub fn kvm_get_seg_reg2(&self, reg: SegReg) -> Result<SegRegVal> {
        let kvm_sregs2 = unsafe { kvm_get_sregs2(&self.fd) }?;
        let val = get_kvm_seg_reg!(kvm_sregs2, reg);
        Ok(val)
    }

    #[allow(dead_code)]
    pub fn kvm_get_sreg2(&self, reg: SReg) -> Result<u64> {
        let kvm_sregs2 = unsafe { kvm_get_sregs2(&self.fd) }?;
        let val = get_kvm_sreg!(kvm_sregs2, reg);
        Ok(val)
    }

    pub fn kvm_set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        let mut kvm_sregs = unsafe { kvm_get_sregs(&self.fd) }?;
        for (reg, val) in sregs {
            set_kvm_sreg!(kvm_sregs, reg, *val)
        }
        for (reg, val) in dt_regs {
            set_kvm_dt_reg!(kvm_sregs, reg, val);
        }
        for (reg, val) in seg_regs {
            set_kvm_seg_reg!(kvm_sregs, reg, val);
        }
        unsafe { kvm_set_sregs(&self.fd, &kvm_sregs) }?;
        Ok(())
    }

    pub fn kvm_get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal> {
        let kvm_sregs = unsafe { kvm_get_sregs(&self.fd) }?;
        let val = get_kvm_dt_reg!(kvm_sregs, reg);
        Ok(val)
    }

    pub fn kvm_get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal> {
        let kvm_sregs = unsafe { kvm_get_sregs(&self.fd) }?;
        let val = get_kvm_seg_reg!(kvm_sregs, reg);
        Ok(val)
    }

    pub fn kvm_get_sreg(&self, reg: SReg) -> Result<u64> {
        let kvm_sregs = unsafe { kvm_get_sregs(&self.fd) }?;
        let val = get_kvm_sreg!(kvm_sregs, reg);
        Ok(val)
    }

    pub fn kvm_set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error> {
        if cpuids.len() > KVM_MAX_CPUID_ENTRIES {
            Err(Error::Unexpected {
                msg: format!("exeeds kvm cpuid entry limit: {KVM_MAX_CPUID_ENTRIES}"),
            })?
        }
        let mut kvm_cpuid2 = KvmCpuid2 {
            nent: cpuids.len() as u32,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
        };
        for (cpuid, entry) in std::iter::zip(cpuids, kvm_cpuid2.entries.iter_mut()) {
            entry.eax = cpuid.eax;
            entry.ebx = cpuid.ebx;
            entry.ecx = cpuid.ecx;
            entry.edx = cpuid.edx;
            entry.function = cpuid.func;
            if let Some(index) = cpuid.index {
                entry.index = index;
                entry.flags = KvmCpuid2Flag::SIGNIFCANT_INDEX;
            } else {
                entry.flags = KvmCpuid2Flag::empty();
            }
        }
        unsafe { kvm_set_cpuid2(&self.fd, &kvm_cpuid2) }?;
        Ok(())
    }
}
