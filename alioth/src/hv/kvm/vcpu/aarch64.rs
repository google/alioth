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

use snafu::ResultExt;

use crate::arch::reg::{Reg, SReg};
use crate::hv::kvm::vcpu::KvmVcpu;
use crate::hv::{Result, error};
use crate::sys::kvm::{
    KvmArmVcpuFeature, KvmCap, KvmOneReg, kvm_arm_preferred_target, kvm_arm_vcpu_init,
    kvm_get_one_reg, kvm_set_one_reg,
};

const fn encode_reg(reg: Reg) -> u64 {
    0x6030_0000_0010_0000 | ((reg as u64) << 1)
}

const fn encode_system_reg(reg: SReg) -> u64 {
    0x6030_0000_0013_0000 | reg.raw() as u64
}

impl KvmVcpu {
    pub fn kvm_vcpu_init(&self, is_bsp: bool) -> Result<()> {
        let mut arm_cpu_init =
            unsafe { kvm_arm_preferred_target(&self.vm.fd) }.context(error::CreateVcpu)?;
        if self.vm.check_extension(KvmCap::ARM_PSCI_0_2)? == 1 {
            arm_cpu_init.features[0] |= KvmArmVcpuFeature::PSCI_0_2.bits();
        }
        if !is_bsp {
            arm_cpu_init.features[0] |= KvmArmVcpuFeature::POWER_OFF.bits();
        }
        unsafe { kvm_arm_vcpu_init(&self.fd, &arm_cpu_init) }.context(error::CreateVcpu)?;
        Ok(())
    }

    fn get_one_reg(&self, reg: u64) -> Result<u64> {
        let mut val = 0;
        let one_reg = KvmOneReg {
            id: reg,
            addr: &mut val as *mut _ as _,
        };
        unsafe { kvm_get_one_reg(&self.fd, &one_reg) }.context(error::VcpuReg)?;
        Ok(val)
    }

    fn set_one_reg(&self, reg: u64, val: u64) -> Result<()> {
        let one_reg = KvmOneReg {
            id: reg,
            addr: &val as *const _ as _,
        };
        unsafe { kvm_set_one_reg(&self.fd, &one_reg) }.context(error::VcpuReg)?;
        Ok(())
    }

    pub fn kvm_set_regs(&self, vals: &[(Reg, u64)]) -> Result<()> {
        for (reg, val) in vals {
            self.set_one_reg(encode_reg(*reg), *val)?;
        }
        Ok(())
    }

    pub fn kvm_get_reg(&self, reg: Reg) -> Result<u64> {
        self.get_one_reg(encode_reg(reg))
    }

    pub fn kvm_set_sregs(&self, vals: &[(SReg, u64)]) -> Result<()> {
        for (reg, val) in vals {
            self.set_one_reg(encode_system_reg(*reg), *val)?;
        }
        Ok(())
    }

    pub fn kvm_get_sreg(&self, reg: SReg) -> Result<u64> {
        self.get_one_reg(encode_system_reg(reg))
    }
}
