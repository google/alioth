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

use crate::hv::kvm::bindings::{
    KvmDevArmVgicCtrl, KvmDevArmVgicGrp, KvmDevType, KvmVgicV2AddrType,
};
use crate::hv::kvm::device::KvmDevice;
use crate::hv::kvm::vm::KvmVm;
use crate::hv::kvm::Result;
use crate::hv::GicV2;

#[derive(Debug)]
pub struct KvmGicV2 {
    dev: KvmDevice,
}

impl GicV2 for KvmGicV2 {
    fn init(&self) -> Result<()> {
        self.dev.set_attr(
            KvmDevArmVgicGrp::CTL.raw(),
            KvmDevArmVgicCtrl::INIT.raw(),
            &(),
        )?;
        Ok(())
    }

    fn get_dist_reg(&self, cpu_index: u32, offset: u16) -> Result<u32> {
        let attr = (cpu_index as u64) << 32 | (offset as u64);
        let v = self.dev.get_attr(KvmDevArmVgicGrp::DIST_REGS.raw(), attr)?;
        Ok(v)
    }

    fn set_dist_reg(&self, cpu_index: u32, offset: u16, val: u32) -> Result<()> {
        let attr = (cpu_index as u64) << 32 | (offset as u64);
        self.dev
            .set_attr(KvmDevArmVgicGrp::DIST_REGS.raw(), attr, &val)?;
        Ok(())
    }

    fn get_cpu_reg(&self, cpu_index: u32, offset: u16) -> Result<u32> {
        let attr = (cpu_index as u64) << 32 | (offset as u64);
        let v = self.dev.get_attr(KvmDevArmVgicGrp::CPU_REGS.raw(), attr)?;
        Ok(v)
    }

    fn set_cpu_reg(&self, cpu_index: u32, offset: u16, val: u32) -> Result<()> {
        let attr = (cpu_index as u64) << 32 | (offset as u64);
        self.dev
            .set_attr(KvmDevArmVgicGrp::CPU_REGS.raw(), attr, &val)?;
        Ok(())
    }

    fn get_num_irqs(&self) -> Result<u32> {
        let n = self.dev.get_attr(KvmDevArmVgicGrp::NR_IRQS.raw(), 0)?;
        Ok(n)
    }

    fn set_num_irqs(&self, val: u32) -> Result<()> {
        self.dev
            .set_attr(KvmDevArmVgicGrp::NR_IRQS.raw(), 0, &val)?;
        Ok(())
    }
}

impl KvmVm {
    pub fn kvm_create_gic_v2(
        &self,
        distributor_base: u64,
        cpu_interface_base: u64,
    ) -> Result<KvmGicV2> {
        let dev = KvmDevice::new(&self.vm, KvmDevType::ARM_VGIC_V2)?;
        let gic = KvmGicV2 { dev };
        gic.dev.set_attr(
            KvmDevArmVgicGrp::ADDR.raw(),
            KvmVgicV2AddrType::DIST.raw(),
            &distributor_base,
        )?;
        gic.dev.set_attr(
            KvmDevArmVgicGrp::ADDR.raw(),
            KvmVgicV2AddrType::CPU.raw(),
            &cpu_interface_base,
        )?;
        Ok(gic)
    }
}
