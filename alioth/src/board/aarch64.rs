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

use crate::arch::layout::{GIC_V2_CPU_INTERFACE_START, GIC_V2_DIST_START};
use crate::board::{Board, BoardConfig, Result, VcpuGuard};
use crate::hv::{GicV2, Hypervisor, Vcpu, Vm};
use crate::loader::InitState;
use crate::mem::mapped::ArcMemPages;

pub struct ArchBoard<V>
where
    V: Vm,
{
    gic_v2: V::GicV2,
}

impl<V: Vm> ArchBoard<V> {
    pub fn new<H>(_hv: &H, vm: &V, _config: &BoardConfig) -> Result<Self>
    where
        H: Hypervisor<Vm = V>,
    {
        let gic_v2 = vm.create_gic_v2(GIC_V2_DIST_START, GIC_V2_CPU_INTERFACE_START)?;
        Ok(ArchBoard { gic_v2 })
    }
}

impl<V> Board<V>
where
    V: Vm,
{
    pub fn setup_firmware(&self, _fw: &mut ArcMemPages) -> Result<()> {
        unimplemented!()
    }

    pub fn init_ap(&self, _id: u32, _vcpu: &mut V::Vcpu, _vcpus: &VcpuGuard) -> Result<()> {
        Ok(())
    }

    pub fn init_boot_vcpu(&self, vcpu: &mut V::Vcpu, init_state: &InitState) -> Result<()> {
        vcpu.set_regs(&init_state.regs)?;
        vcpu.set_sregs(&init_state.sregs)?;
        Ok(())
    }

    pub fn init_vcpu(&self, id: u32, vcpu: &mut V::Vcpu) -> Result<()> {
        vcpu.reset(id == 0)?;
        Ok(())
    }

    pub fn create_ram(&self) -> Result<()> {
        unimplemented!()
    }

    pub fn coco_init(&self, _id: u32) -> Result<()> {
        unimplemented!()
    }

    pub fn coco_finalize(&self, _id: u32, _vcpus: &VcpuGuard) -> Result<()> {
        unimplemented!()
    }

    pub fn create_firmware_data(&self, _init_state: &InitState) -> Result<()> {
        unimplemented!()
    }

    pub fn arch_init(&self) -> Result<()> {
        self.arch.gic_v2.init()?;
        Ok(())
    }
}
