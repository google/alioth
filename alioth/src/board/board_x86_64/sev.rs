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
use std::sync::Arc;

use crate::arch::cpuid::{
    Cpuid1Ecx, Cpuid7Index0Ebx, Cpuid7Index0Edx, CpuidExt1fEAx, CpuidExt1fEbx, CpuidExt8Ebx,
    CpuidExt21EAx, CpuidIn,
};
use crate::arch::sev::{SevPolicy, SnpPolicy};
use crate::board::{Board, Result, error};
use crate::hv::{Coco, Vm, VmMemory};
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
