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

use crate::board::{Board, Error, Result};
use crate::hv::arch::Cpuid;
use crate::hv::{Hypervisor, Vcpu, Vm};
use crate::loader::InitState;

pub struct ArchBoard {
    cpuids: Vec<Cpuid>,
}

impl ArchBoard {
    pub fn new<H: Hypervisor>(hv: &H) -> Result<Self> {
        let mut cpuids = hv.get_supported_cpuids()?;
        for cpuid in &mut cpuids {
            if cpuid.func == 0x1 {
                cpuid.ecx |= (1 << 24) | (1 << 31);
            }
        }
        Ok(Self { cpuids })
    }
}

impl<V> Board<V>
where
    V: Vm,
{
    pub fn init_vcpu(&self, id: u32, init_state: &InitState) -> Result<<V as Vm>::Vcpu, Error> {
        let mut vcpu = self.vm.create_vcpu(id)?;
        if id == 0 {
            vcpu.set_regs(&init_state.regs)?;
            vcpu.set_sregs(&init_state.sregs, &init_state.seg_regs, &init_state.dt_regs)?;
        }
        let mut cpuids = self.arch.cpuids.clone();
        for cpuid in &mut cpuids {
            if cpuid.func == 0x1 {
                cpuid.ebx &= 0x00ff_ffff;
                cpuid.ebx |= id << 24;
            } else if cpuid.func == 0xb {
                cpuid.edx = id;
            }
        }
        vcpu.set_cpuids(cpuids)?;
        Ok(vcpu)
    }
}
