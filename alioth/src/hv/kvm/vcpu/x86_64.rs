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

use crate::arch::reg::SegAccess;
use crate::hv::arch::{Cpuid, DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use crate::hv::kvm::bindings::{
    KvmCpuid2, KvmCpuid2Flag, KvmCpuidEntry2, KvmRegs, KvmSregs2, KVM_MAX_CPUID_ENTRIES,
};
use crate::hv::kvm::ioctls::{
    kvm_get_regs, kvm_get_sregs2, kvm_set_cpuid2, kvm_set_regs, kvm_set_sregs2,
};
use crate::hv::kvm::vcpu::KvmVcpu;
use crate::hv::{Error, Result};

impl KvmVcpu {
    fn get_kvm_sregs2(&self) -> Result<KvmSregs2> {
        let kvm_sregs2 = unsafe { kvm_get_sregs2(&self.fd) }?;
        Ok(kvm_sregs2)
    }

    fn set_kvm_sregs2(&self, kvm_sregs2: &KvmSregs2) -> Result<()> {
        unsafe { kvm_set_sregs2(&self.fd, kvm_sregs2) }?;
        Ok(())
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

    pub fn kvm_set_sregs(
        &mut self,
        sregs: &[(SReg, u64)],
        seg_regs: &[(SegReg, SegRegVal)],
        dt_regs: &[(DtReg, DtRegVal)],
    ) -> Result<(), Error> {
        let mut kvm_sregs2 = self.get_kvm_sregs2()?;
        for (reg, val) in sregs {
            match reg {
                SReg::Cr0 => kvm_sregs2.cr0 = *val,
                SReg::Cr2 => kvm_sregs2.cr2 = *val,
                SReg::Cr3 => kvm_sregs2.cr3 = *val,
                SReg::Cr4 => kvm_sregs2.cr4 = *val,
                SReg::Cr8 => kvm_sregs2.cr8 = *val,
                SReg::Efer => kvm_sregs2.efer = *val,
                SReg::ApicBase => kvm_sregs2.apic_base = *val,
            }
        }
        for (reg, val) in dt_regs {
            let target = match reg {
                DtReg::Idtr => &mut kvm_sregs2.idt,
                DtReg::Gdtr => &mut kvm_sregs2.gdt,
            };
            target.limit = val.limit;
            target.base = val.base;
        }
        for (reg, val) in seg_regs {
            let target = match reg {
                SegReg::Cs => &mut kvm_sregs2.cs,
                SegReg::Ds => &mut kvm_sregs2.ds,
                SegReg::Es => &mut kvm_sregs2.es,
                SegReg::Fs => &mut kvm_sregs2.fs,
                SegReg::Gs => &mut kvm_sregs2.gs,
                SegReg::Ss => &mut kvm_sregs2.ss,
                SegReg::Tr => &mut kvm_sregs2.tr,
                SegReg::Ldtr => &mut kvm_sregs2.ldt,
            };
            target.selector = val.selector;
            target.base = val.base;
            target.limit = val.limit;
            target.type_ = val.access.seg_type() as u8;
            target.s = val.access.s_code_data() as u8;
            target.dpl = val.access.priv_level() as u8;
            target.present = val.access.present() as u8;
            target.avl = val.access.available() as u8;
            target.db = val.access.db_size_32() as u8;
            target.g = val.access.granularity() as u8;
            target.l = val.access.l_64bit() as u8;
            target.unusable = val.access.unusable() as u8;
        }
        self.set_kvm_sregs2(&kvm_sregs2)?;
        Ok(())
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

    pub fn kvm_get_dt_reg(&self, reg: DtReg) -> Result<DtRegVal> {
        let kvm_sregs2 = self.get_kvm_sregs2()?;
        let target = match reg {
            DtReg::Idtr => &kvm_sregs2.idt,
            DtReg::Gdtr => &kvm_sregs2.gdt,
        };
        Ok(DtRegVal {
            limit: target.limit,
            base: target.base,
        })
    }

    pub fn kvm_get_seg_reg(&self, reg: SegReg) -> Result<SegRegVal> {
        let kvm_sregs2 = self.get_kvm_sregs2()?;
        let kvm_segment = match reg {
            SegReg::Cs => kvm_sregs2.cs,
            SegReg::Ds => kvm_sregs2.ds,
            SegReg::Es => kvm_sregs2.es,
            SegReg::Fs => kvm_sregs2.fs,
            SegReg::Gs => kvm_sregs2.gs,
            SegReg::Ss => kvm_sregs2.ss,
            SegReg::Tr => kvm_sregs2.tr,
            SegReg::Ldtr => kvm_sregs2.ldt,
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
        let val = SegRegVal {
            selector: kvm_segment.selector,
            base: kvm_segment.base,
            limit: kvm_segment.limit,
            access: SegAccess(access),
        };
        Ok(val)
    }

    pub fn kvm_get_sreg(&self, reg: SReg) -> Result<u64> {
        let kvm_sregs2 = self.get_kvm_sregs2()?;
        let val = match reg {
            SReg::Cr0 => kvm_sregs2.cr0,
            SReg::Cr2 => kvm_sregs2.cr2,
            SReg::Cr3 => kvm_sregs2.cr3,
            SReg::Cr4 => kvm_sregs2.cr4,
            SReg::Cr8 => kvm_sregs2.cr8,
            SReg::Efer => kvm_sregs2.efer,
            SReg::ApicBase => kvm_sregs2.apic_base,
        };
        Ok(val)
    }

    pub fn kvm_set_cpuids(&mut self, cpuids: Vec<Cpuid>) -> Result<(), Error> {
        if cpuids.len() > KVM_MAX_CPUID_ENTRIES {
            Err(Error::Unexpected {
                msg: format!("exeeds kvm cpuid entry limit: {}", KVM_MAX_CPUID_ENTRIES),
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
