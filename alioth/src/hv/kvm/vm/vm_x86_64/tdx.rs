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

use std::arch::x86_64::CpuidResult;
use std::collections::HashMap;
use std::mem::MaybeUninit;

use crate::arch::cpuid::CpuidIn;
use crate::arch::tdx::TdAttr;
use crate::hv::Result;
use crate::hv::kvm::vm::KvmVm;
use crate::hv::kvm::x86_64::tdx::tdx_op;
use crate::sys::kvm::{KvmCap, KvmCpuid2Flag, KvmCpuidEntry2, KvmHypercall};
use crate::sys::tdx::{KvmTdxCapabilities, KvmTdxCmdId, KvmTdxInitVm};

impl KvmVm {
    pub fn tdx_init(&self) -> Result<()> {
        let map_gpa_range = 1 << KvmHypercall::MAP_GPA_RANGE.raw();
        self.vm.enable_cap(KvmCap::EXIT_HYPERCALL, map_gpa_range)?;
        self.vm.enable_cap(KvmCap::X86_APIC_BUS_CYCLES_NS, 40)?;
        Ok(())
    }

    fn tdx_get_capabilities(&self) -> Result<Box<KvmTdxCapabilities>> {
        let mut caps: Box<KvmTdxCapabilities> =
            Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
        caps.cpuid.nent = caps.cpuid.entries.len() as u32;
        tdx_op(&self.vm.fd, KvmTdxCmdId::CAPABILITIES, 0, Some(&mut *caps))?;
        Ok(caps)
    }

    pub fn tdx_init_vm(&self, attr: TdAttr, cpuids: &HashMap<CpuidIn, CpuidResult>) -> Result<()> {
        let mut init: Box<KvmTdxInitVm> = Box::new(unsafe { MaybeUninit::zeroed().assume_init() });
        init.attributes = attr;

        let caps = self.tdx_get_capabilities()?;
        let convert = |e: &KvmCpuidEntry2| {
            let (mut in_, out) = From::from(*e);
            if in_.index.is_none() {
                in_.index = Some(0)
            }
            (in_, out)
        };
        let caps_cpuid = caps.cpuid.entries.iter().take(caps.cpuid.nent as usize);
        let caps_cpuid: HashMap<_, _> = caps_cpuid.map(convert).collect();
        for (in_, out) in cpuids {
            let cap_cpuid_in = CpuidIn {
                func: in_.func,
                index: in_.index.or(Some(0)),
            };
            let Some(cap_out) = caps_cpuid.get(&cap_cpuid_in) else {
                continue;
            };

            let entry = &mut init.cpuid.entries[init.cpuid.nent as usize];
            entry.function = in_.func;
            entry.index = in_.index.unwrap_or(0);
            entry.flags = if in_.index.is_some() {
                KvmCpuid2Flag::SIGNIFCANT_INDEX
            } else {
                KvmCpuid2Flag::empty()
            };
            entry.eax = out.eax & cap_out.eax;
            entry.ebx = out.ebx & cap_out.ebx;
            entry.ecx = out.ecx & cap_out.ecx;
            entry.edx = out.edx & cap_out.edx;

            init.cpuid.nent += 1;
        }

        tdx_op(&self.vm.fd, KvmTdxCmdId::INIT_VM, 0, Some(&mut *init))?;
        Ok(())
    }

    pub fn tdx_finalize_vm(&self) -> Result<()> {
        tdx_op::<()>(&self.vm.fd, KvmTdxCmdId::FINALIZE_VM, 0, None)
    }
}
