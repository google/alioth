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
use crate::hv::hvf::bindings::{
    hv_vcpu_destroy, hv_vcpu_get_reg, hv_vcpu_get_sys_reg, hv_vcpu_set_reg, hv_vcpu_set_sys_reg,
    HvReg, HvVcpuExit,
};
use crate::hv::hvf::check_ret;
use crate::hv::{error, Result, Vcpu, VmEntry, VmExit};

#[derive(Debug)]
pub struct HvfVcpu {
    pub exit: *mut HvVcpuExit,
    pub vcpu_id: u64,
}

impl Drop for HvfVcpu {
    fn drop(&mut self) {
        let ret = unsafe { hv_vcpu_destroy(self.vcpu_id) };
        if let Err(e) = check_ret(ret) {
            log::error!("hv_vcpu_destroy: {e:?}");
        }
    }
}

enum HvfReg {
    Reg(HvReg),
    SReg(SReg),
}

impl Reg {
    fn to_hvf_reg(&self) -> HvfReg {
        match *self {
            Reg::X0 => HvfReg::Reg(HvReg::X0),
            Reg::X1 => HvfReg::Reg(HvReg::X1),
            Reg::X2 => HvfReg::Reg(HvReg::X2),
            Reg::X3 => HvfReg::Reg(HvReg::X3),
            Reg::X4 => HvfReg::Reg(HvReg::X4),
            Reg::X5 => HvfReg::Reg(HvReg::X5),
            Reg::X6 => HvfReg::Reg(HvReg::X6),
            Reg::X7 => HvfReg::Reg(HvReg::X7),
            Reg::X8 => HvfReg::Reg(HvReg::X8),
            Reg::X9 => HvfReg::Reg(HvReg::X9),
            Reg::X10 => HvfReg::Reg(HvReg::X10),
            Reg::X11 => HvfReg::Reg(HvReg::X11),
            Reg::X12 => HvfReg::Reg(HvReg::X12),
            Reg::X13 => HvfReg::Reg(HvReg::X13),
            Reg::X14 => HvfReg::Reg(HvReg::X14),
            Reg::X15 => HvfReg::Reg(HvReg::X15),
            Reg::X16 => HvfReg::Reg(HvReg::X16),
            Reg::X17 => HvfReg::Reg(HvReg::X17),
            Reg::X18 => HvfReg::Reg(HvReg::X18),
            Reg::X19 => HvfReg::Reg(HvReg::X19),
            Reg::X20 => HvfReg::Reg(HvReg::X20),
            Reg::X21 => HvfReg::Reg(HvReg::X21),
            Reg::X22 => HvfReg::Reg(HvReg::X22),
            Reg::X23 => HvfReg::Reg(HvReg::X23),
            Reg::X24 => HvfReg::Reg(HvReg::X24),
            Reg::X25 => HvfReg::Reg(HvReg::X25),
            Reg::X26 => HvfReg::Reg(HvReg::X26),
            Reg::X27 => HvfReg::Reg(HvReg::X27),
            Reg::X28 => HvfReg::Reg(HvReg::X28),
            Reg::X29 => HvfReg::Reg(HvReg::X29),
            Reg::X30 => HvfReg::Reg(HvReg::X30),
            Reg::Sp => HvfReg::SReg(SReg::SP_EL0),
            Reg::Pc => HvfReg::Reg(HvReg::PC),
            Reg::Pstate => HvfReg::Reg(HvReg::CPSR),
        }
    }
}

impl Vcpu for HvfVcpu {
    fn reset(&self, _is_bsp: bool) -> Result<()> {
        unimplemented!()
    }

    fn dump(&self) -> Result<()> {
        unimplemented!()
    }

    fn run(&mut self, _entry: VmEntry) -> Result<VmExit> {
        unimplemented!()
    }

    fn get_reg(&self, reg: Reg) -> Result<u64> {
        let hvf_reg = reg.to_hvf_reg();
        let mut val = 0;
        let ret = match hvf_reg {
            HvfReg::Reg(r) => unsafe { hv_vcpu_get_reg(self.vcpu_id, r, &mut val) },
            HvfReg::SReg(r) => unsafe { hv_vcpu_get_sys_reg(self.vcpu_id, r, &mut val) },
        };
        check_ret(ret).context(error::VcpuReg)?;
        Ok(val)
    }

    fn set_regs(&mut self, vals: &[(Reg, u64)]) -> Result<()> {
        for (reg, val) in vals {
            let hvf_reg = reg.to_hvf_reg();
            let ret = match hvf_reg {
                HvfReg::Reg(r) => unsafe { hv_vcpu_set_reg(self.vcpu_id, r, *val) },
                HvfReg::SReg(r) => unsafe { hv_vcpu_set_sys_reg(self.vcpu_id, r, *val) },
            };
            check_ret(ret).context(error::VcpuReg)?;
        }
        Ok(())
    }

    fn get_sreg(&self, reg: SReg) -> Result<u64> {
        let mut val = 0;
        let ret = unsafe { hv_vcpu_get_sys_reg(self.vcpu_id, reg, &mut val) };
        check_ret(ret).context(error::VcpuReg)?;
        Ok(val)
    }

    fn set_sregs(&mut self, sregs: &[(SReg, u64)]) -> Result<()> {
        for (reg, val) in sregs {
            let ret = unsafe { hv_vcpu_set_sys_reg(self.vcpu_id, *reg, *val) };
            check_ret(ret).context(error::VcpuReg)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::arch::reg::Reg;
    use crate::hv::{Hvf, Hypervisor, Vcpu, Vm, VmConfig};

    #[test]
    fn test_vcpu_regs() {
        let hvf = Hvf {};
        let config = VmConfig { coco: None };
        let vm = hvf.create_vm(&config).unwrap();
        let mut vcpu = vm.create_vcpu(0).unwrap();
        let regs = [
            (Reg::X0, 0),
            (Reg::X1, 1),
            (Reg::X2, 2),
            (Reg::X3, 3),
            (Reg::X4, 4),
            (Reg::X5, 5),
            (Reg::X6, 6),
            (Reg::X7, 7),
            (Reg::X8, 8),
            (Reg::X9, 9),
            (Reg::X10, 10),
            (Reg::X11, 11),
            (Reg::X12, 12),
            (Reg::X13, 13),
            (Reg::X14, 14),
            (Reg::X15, 15),
            (Reg::X16, 16),
            (Reg::X17, 17),
            (Reg::X18, 18),
            (Reg::X19, 19),
            (Reg::X20, 20),
            (Reg::X21, 21),
            (Reg::X22, 22),
            (Reg::X23, 23),
            (Reg::X24, 24),
            (Reg::X25, 25),
            (Reg::X26, 26),
            (Reg::X27, 27),
            (Reg::X28, 28),
            (Reg::X29, 29),
            (Reg::X30, 30),
            (Reg::Sp, 0x1000),
            (Reg::Pc, 0x2000),
            (Reg::Pstate, 0xf << 28),
        ];
        vcpu.set_regs(&regs).unwrap();
        for (reg, val) in regs {
            assert_eq!(vcpu.get_reg(reg).unwrap(), val);
        }
    }
}
