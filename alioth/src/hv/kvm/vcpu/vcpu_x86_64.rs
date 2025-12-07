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

use std::arch::x86_64::CpuidResult;
use std::collections::HashMap;
use std::iter::zip;

use snafu::ResultExt;

use crate::arch::cpuid::CpuidIn;
use crate::arch::reg::{DtReg, DtRegVal, Reg, SReg, SegAccess, SegReg, SegRegVal};
use crate::hv::kvm::kvm_error;
use crate::hv::kvm::vcpu::KvmVcpu;
use crate::hv::{Error, Result, error};
use crate::sys::kvm::{
    KVM_MAX_CPUID_ENTRIES, KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KvmMsrEntry, KvmMsrs, KvmRegs,
    MAX_IO_MSRS, kvm_get_regs, kvm_get_sregs, kvm_get_sregs2, kvm_set_cpuid2, kvm_set_msrs,
    kvm_set_regs, kvm_set_sregs, kvm_set_sregs2,
};

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

impl KvmVcpu {
    fn get_kvm_regs(&self) -> Result<KvmRegs> {
        let kvm_regs = unsafe { kvm_get_regs(&self.fd) }.context(error::VcpuReg)?;
        Ok(kvm_regs)
    }

    fn set_kvm_regs(&self, kvm_regs: &KvmRegs) -> Result<()> {
        unsafe { kvm_set_regs(&self.fd, kvm_regs) }.context(error::VcpuReg)?;
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

    pub fn kvm_set_sregs2(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        let mut kvm_sregs2 = unsafe { kvm_get_sregs2(&self.fd) }.context(error::VcpuReg)?;
        for (reg, val) in sregs {
            set_kvm_sreg!(kvm_sregs2, reg, *val)
        }
        for (reg, val) in dt_regs {
            set_kvm_dt_reg!(kvm_sregs2, reg, val);
        }
        for (reg, val) in seg_regs {
            set_kvm_seg_reg!(kvm_sregs2, reg, val);
        }
        unsafe { kvm_set_sregs2(&self.fd, &kvm_sregs2) }.context(error::VcpuReg)?;
        Ok(())
    }

    pub fn kvm_get_dt_reg2(&self, reg: DtReg) -> Result<DtRegVal> {
        let kvm_sregs2 = unsafe { kvm_get_sregs2(&self.fd) }.context(error::VcpuReg)?;
        let val = get_kvm_dt_reg!(kvm_sregs2, reg);
        Ok(val)
    }

    pub fn kvm_get_seg_reg2(&self, reg: SegReg) -> Result<SegRegVal> {
        let kvm_sregs2 = unsafe { kvm_get_sregs2(&self.fd) }.context(error::VcpuReg)?;
        let val = get_kvm_seg_reg!(kvm_sregs2, reg);
        Ok(val)
    }

    pub fn kvm_get_sreg2(&self, reg: SReg) -> Result<u64> {
        let kvm_sregs2 = unsafe { kvm_get_sregs2(&self.fd) }.context(error::VcpuReg)?;
        let val = get_kvm_sreg!(kvm_sregs2, reg);
        Ok(val)
    }

    pub fn kvm_set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        let mut kvm_sregs = unsafe { kvm_get_sregs(&self.fd) }.context(error::VcpuReg)?;
        for (reg, val) in sregs {
            set_kvm_sreg!(kvm_sregs, reg, *val)
        }
        for (reg, val) in dt_regs {
            set_kvm_dt_reg!(kvm_sregs, reg, val);
        }
        for (reg, val) in seg_regs {
            set_kvm_seg_reg!(kvm_sregs, reg, val);
        }
        unsafe { kvm_set_sregs(&self.fd, &kvm_sregs) }.context(error::VcpuReg)?;
        Ok(())
    }

    pub fn kvm_get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal> {
        let kvm_sregs = unsafe { kvm_get_sregs(&self.fd) }.context(error::VcpuReg)?;
        let val = get_kvm_dt_reg!(kvm_sregs, reg);
        Ok(val)
    }

    pub fn kvm_get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal> {
        let kvm_sregs = unsafe { kvm_get_sregs(&self.fd) }.context(error::VcpuReg)?;
        let val = get_kvm_seg_reg!(kvm_sregs, reg);
        Ok(val)
    }

    pub fn kvm_get_sreg(&self, reg: SReg) -> Result<u64> {
        let kvm_sregs = unsafe { kvm_get_sregs(&self.fd) }.context(error::VcpuReg)?;
        let val = get_kvm_sreg!(kvm_sregs, reg);
        Ok(val)
    }

    pub fn kvm_set_cpuids(&mut self, cpuids: &HashMap<CpuidIn, CpuidResult>) -> Result<(), Error> {
        if cpuids.len() > KVM_MAX_CPUID_ENTRIES {
            return kvm_error::CpuidTableTooLong.fail()?;
        }
        let mut kvm_cpuid2 = KvmCpuid2 {
            nent: cpuids.len() as u32,
            padding: 0,
            entries: [KvmCpuidEntry2::default(); KVM_MAX_CPUID_ENTRIES],
        };
        for ((in_, out), entry) in zip(cpuids, &mut kvm_cpuid2.entries) {
            entry.eax = out.eax;
            entry.ebx = out.ebx;
            entry.ecx = out.ecx;
            entry.edx = out.edx;
            entry.function = in_.func;
            if let Some(index) = in_.index {
                entry.index = index;
                entry.flags = KvmCpuid2Flag::SIGNIFCANT_INDEX;
            } else {
                entry.flags = KvmCpuid2Flag::empty();
            }
        }
        unsafe { kvm_set_cpuid2(&self.fd, &kvm_cpuid2) }.context(error::GuestCpuid)?;
        Ok(())
    }

    pub fn kvm_set_msrs(&mut self, msrs: &[(u32, u64)]) -> Result<()> {
        let mut kvm_msrs = KvmMsrs {
            nmsrs: msrs.len() as u32,
            _pad: 0,
            entries: [KvmMsrEntry::default(); MAX_IO_MSRS],
        };
        for (i, (index, data)) in msrs.iter().enumerate() {
            kvm_msrs.entries[i].index = *index;
            kvm_msrs.entries[i].data = *data;
        }
        unsafe { kvm_set_msrs(&self.fd, &kvm_msrs) }.context(error::GuestMsr)?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "vcpu_x86_64_test.rs"]
mod tests;
