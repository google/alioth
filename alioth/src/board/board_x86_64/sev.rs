// Copyright 2026 Google LLC
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

use std::arch::x86_64::{__cpuid, CpuidResult};
use std::collections::HashMap;
use std::iter::zip;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use zerocopy::FromZeros;

use crate::arch::cpuid::{
    Cpuid1Ecx, Cpuid7Index0Ebx, Cpuid7Index0Edx, CpuidExt1fEAx, CpuidExt1fEbx, CpuidExt8Ebx,
    CpuidExt21EAx, CpuidIn,
};
use crate::arch::layout::MEM_64_START;
use crate::arch::reg::{Reg, SegAccess, SegReg, SegRegVal};
use crate::arch::sev::{SevPolicy, SnpPageType, SnpPolicy};
use crate::board::{Board, Result, error};
use crate::firmware::ovmf::sev::{
    SevDescType, SevMetadataDesc, SnpCpuidFunc, SnpCpuidInfo, parse_desc, parse_sev_ap_eip,
};
use crate::hv::{Coco, Vcpu, Vm, VmMemory};
use crate::mem::mapped::ArcMemPages;
use crate::mem::{self, LayoutChanged, MarkPrivateMemory};

pub fn adjust_cpuid(coco: &Coco, cpuids: &mut HashMap<CpuidIn, CpuidResult>) -> Result<()> {
    // AMD Volume 3, section E.4.17.
    let in_ = CpuidIn {
        func: 0x8000_001f,
        index: None,
    };
    let Some(out) = cpuids.get_mut(&in_) else {
        return error::MissingCpuid { leaf: in_ }.fail();
    };
    let host_ebx = CpuidExt1fEbx(__cpuid(in_.func).ebx);
    out.ebx = CpuidExt1fEbx::new(host_ebx.cbit_pos(), 1, 0).0;
    out.ecx = 0;
    out.edx = 0;
    if let Coco::AmdSev { policy } = coco {
        out.eax = if policy.es() {
            (CpuidExt1fEAx::SEV | CpuidExt1fEAx::SEV_ES).bits()
        } else {
            CpuidExt1fEAx::SEV.bits()
        };
    } else if let Coco::AmdSnp { .. } = coco {
        out.eax = (CpuidExt1fEAx::SEV | CpuidExt1fEAx::SEV_ES | CpuidExt1fEAx::SEV_SNP).bits()
    }

    if let Coco::AmdSnp { .. } = coco {
        snp_adjust_cpuids(cpuids);
    }

    Ok(())
}

fn snp_adjust_cpuids(cpuids: &mut HashMap<CpuidIn, CpuidResult>) {
    let in_ = CpuidIn {
        func: 0x1,
        index: None,
    };
    if let Some(out) = cpuids.get_mut(&in_) {
        out.ecx &= !Cpuid1Ecx::TSC_DEADLINE.bits()
    };

    let in_ = CpuidIn {
        func: 0x7,
        index: Some(0),
    };
    if let Some(out) = cpuids.get_mut(&in_) {
        out.ebx &= !Cpuid7Index0Ebx::TSC_ADJUST.bits();
        out.edx &= !(Cpuid7Index0Edx::IBRS_IBPB
            | Cpuid7Index0Edx::SPEC_CTRL_ST_PREDICTORS
            | Cpuid7Index0Edx::L1D_FLUSH_INTERFACE
            | Cpuid7Index0Edx::ARCH_CAPABILITIES
            | Cpuid7Index0Edx::CORE_CAPABILITIES
            | Cpuid7Index0Edx::SPEC_CTRL_SSBD)
            .bits()
    }

    let in_ = CpuidIn {
        func: 0x8000_0008,
        index: None,
    };
    if let Some(out) = cpuids.get_mut(&in_) {
        out.ebx &= !CpuidExt8Ebx::SSBD_VIRT_SPEC_CTRL.bits();
    }

    let in_ = CpuidIn {
        func: 0x8000_0021,
        index: None,
    };
    if let Some(out) = cpuids.get_mut(&in_) {
        out.eax &= !CpuidExt21EAx::NO_SMM_CTL_MSR.bits();
    }

    for index in 0..=4 {
        cpuids.remove(&CpuidIn {
            func: 0x8000_0026,
            index: Some(index),
        });
    }
}

impl<V> Board<V>
where
    V: Vm,
{
    fn fill_snp_cpuid(&self, entries: &mut [SnpCpuidFunc]) {
        for ((in_, out), dst) in zip(self.arch.cpuids.iter(), entries.iter_mut()) {
            dst.eax_in = in_.func;
            dst.ecx_in = in_.index.unwrap_or(0);
            dst.eax = out.eax;
            dst.ebx = out.ebx;
            dst.ecx = out.ecx;
            dst.edx = out.edx;
            if dst.eax_in == 0xd && (dst.ecx_in == 0x0 || dst.ecx_in == 0x1) {
                dst.ebx = 0x240;
                dst.xcr0_in = 1;
                dst.xss_in = 0;
            }
        }
    }

    fn parse_sev_api_eip(&self, data: &[u8]) -> Result<()> {
        let ap_eip = parse_sev_ap_eip(data)?;
        self.arch.sev_ap_eip.store(ap_eip, Ordering::Release);
        Ok(())
    }

    fn update_snp_desc(&self, desc: &SevMetadataDesc) -> Result<()> {
        let mut cpuid_table = SnpCpuidInfo::new_zeroed();
        let ram_bus = self.memory.ram_bus();
        let ram = ram_bus.lock_layout();
        let page_type = match desc.type_ {
            SevDescType::SNP_DESC_MEM => SnpPageType::UNMEASURED,
            SevDescType::SNP_SECRETS => SnpPageType::SECRETS,
            SevDescType::CPUID => {
                assert!(desc.len as usize >= size_of::<SnpCpuidInfo>());
                assert!(cpuid_table.entries.len() >= self.arch.cpuids.len());
                cpuid_table.count = self.arch.cpuids.len() as u32;
                self.fill_snp_cpuid(&mut cpuid_table.entries);
                ram.write_t(desc.base as _, &cpuid_table)?;
                SnpPageType::CPUID
            }
            _ => unimplemented!(),
        };
        let range_ref = ram.get_slice::<u8>(desc.base as u64, desc.len as u64)?;
        let bytes =
            unsafe { std::slice::from_raw_parts_mut(range_ref.as_ptr() as _, range_ref.len()) };
        self.memory
            .mark_private_memory(desc.base as _, desc.len as _, true)?;
        let ret = self.vm.snp_launch_update(bytes, desc.base as _, page_type);
        if ret.is_err() && desc.type_ == SevDescType::CPUID {
            let updated_cpuid: SnpCpuidInfo = ram.read_t(desc.base as _)?;
            for (set, got) in zip(&cpuid_table.entries, &updated_cpuid.entries) {
                if set != got {
                    log::error!("set {set:#x?}, but firmware expects {got:#x?}");
                }
            }
        }
        ret?;
        Ok(())
    }

    pub(crate) fn setup_sev(&self, fw: &mut ArcMemPages, policy: SevPolicy) -> Result<()> {
        self.memory.register_encrypted_pages(fw)?;

        let data = fw.as_slice_mut();
        if policy.es() {
            self.parse_sev_api_eip(data)?;
        }
        self.vm.sev_launch_update_data(data)?;
        Ok(())
    }

    pub(crate) fn setup_snp(&self, fw: &mut ArcMemPages) -> Result<()> {
        self.memory.register_encrypted_pages(fw)?;

        let data = fw.as_slice_mut();
        self.parse_sev_api_eip(data)?;
        for desc in parse_desc(data)? {
            self.update_snp_desc(desc)?;
        }
        let fw_gpa = MEM_64_START - data.len() as u64;
        self.memory
            .mark_private_memory(fw_gpa, data.len() as _, true)?;
        self.vm
            .snp_launch_update(data, fw_gpa, SnpPageType::NORMAL)?;
        Ok(())
    }

    pub(crate) fn sev_finalize(&self, policy: SevPolicy) -> Result<()> {
        if policy.es() {
            self.vm.sev_launch_update_vmsa()?;
        }
        self.vm.sev_launch_measure()?;
        self.vm.sev_launch_finish()?;
        Ok(())
    }

    pub(crate) fn snp_finalize(&self) -> Result<()> {
        self.vm.snp_launch_finish()?;
        Ok(())
    }

    pub(crate) fn sev_init_ap(&self, vcpu: &mut V::Vcpu) -> Result<()> {
        let eip = self.arch.sev_ap_eip.load(Ordering::Acquire);
        vcpu.set_regs(&[(Reg::Rip, eip as u64 & 0xffff)])?;
        vcpu.set_sregs(
            &[],
            &[(
                SegReg::Cs,
                SegRegVal {
                    selector: 0xf000,
                    base: eip as u64 & 0xffff_0000,
                    limit: 0xffff,
                    access: SegAccess(0x9b),
                },
            )],
            &[],
        )?;
        Ok(())
    }

    pub(crate) fn sev_init(&self, policy: SevPolicy, memory: Arc<V::Memory>) -> Result<()> {
        self.vm.sev_launch_start(policy)?;
        let encrypt_pages = Box::new(EncryptPages { memory });
        self.memory.register_change_callback(encrypt_pages)?;
        Ok(())
    }

    pub(crate) fn snp_init(&self, policy: SnpPolicy, memory: Arc<V::Memory>) -> Result<()> {
        self.vm.snp_launch_start(policy)?;
        let encrypt_pages = Box::new(EncryptPages {
            memory: memory.clone(),
        });
        self.memory.register_change_callback(encrypt_pages)?;
        let mark_private_memory = Box::new(MarkPrivateMemory { memory });
        self.memory.register_change_callback(mark_private_memory)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct EncryptPages {
    memory: Arc<dyn VmMemory>,
}

impl LayoutChanged for EncryptPages {
    fn ram_added(&self, _: u64, pages: &ArcMemPages) -> mem::Result<()> {
        self.memory.register_encrypted_range(pages.as_slice())?;
        Ok(())
    }

    fn ram_removed(&self, _: u64, _: &ArcMemPages) -> mem::Result<()> {
        Ok(())
    }
}
