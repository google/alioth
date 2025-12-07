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

mod vmentry;
mod vmexit;

use std::collections::HashMap;
use std::io::ErrorKind;
use std::ptr::null_mut;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, mpsc};

use parking_lot::Mutex;
use snafu::ResultExt;

use crate::arch::reg::{MpidrEl1, Reg, SReg};
use crate::hv::hvf::check_ret;
use crate::hv::hvf::vm::{HvfVm, VcpuEvent};
use crate::hv::{Result, Vcpu, VmEntry, VmExit, error};
use crate::sys::hvf::{
    HvExitReason, HvReg, HvVcpuExit, hv_vcpu_create, hv_vcpu_destroy, hv_vcpu_get_reg,
    hv_vcpu_get_sys_reg, hv_vcpu_run, hv_vcpu_set_reg, hv_vcpu_set_sys_reg,
};

pub fn encode_mpidr(id: u32) -> MpidrEl1 {
    let mut mpidr = MpidrEl1(0);
    mpidr.set_aff1(id as u64 >> 3);
    mpidr.set_aff0(id as u64 & 0x7);
    mpidr
}

#[derive(Debug)]
pub struct HvfVcpu {
    exit: *mut HvVcpuExit,
    vcpu_id: u64,
    vmexit: Option<VmExit>,
    exit_reg: Option<HvReg>,
    senders: Arc<Mutex<HashMap<MpidrEl1, Sender<VcpuEvent>>>>,
    receiver: Receiver<VcpuEvent>,
    power_on: bool,
}

impl HvfVcpu {
    fn handle_event(&mut self, event: &VcpuEvent) -> Result<()> {
        match event {
            VcpuEvent::PowerOn { pc, context } => {
                self.set_regs(&[(Reg::Pc, *pc), (Reg::X0, *context), (Reg::Pstate, 5)])?;
                self.power_on = true;
            }
            VcpuEvent::PowerOff => self.power_on = false,
        }
        Ok(())
    }

    pub fn new(vm: &HvfVm, id: u32) -> Result<Self> {
        let mut exit = null_mut();
        let mut vcpu_id = 0;
        let ret = unsafe { hv_vcpu_create(&mut vcpu_id, &mut exit, null_mut()) };
        check_ret(ret).context(error::CreateVcpu)?;

        let mpidr = encode_mpidr(id);
        let ret = unsafe { hv_vcpu_set_sys_reg(vcpu_id, SReg::MPIDR_EL1, mpidr.0) };
        check_ret(ret).context(error::VcpuReg)?;

        let (sender, receiver) = mpsc::channel();
        vm.senders.lock().insert(mpidr, sender);

        vm.vcpus.lock().insert(id, vcpu_id);

        Ok(HvfVcpu {
            exit,
            vcpu_id,
            vmexit: None,
            exit_reg: None,
            senders: vm.senders.clone(),
            receiver,
            power_on: false,
        })
    }
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
    fn to_hvf_reg(self) -> HvfReg {
        match self {
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
    fn reset(&mut self, is_bsp: bool) -> Result<()> {
        self.power_on = is_bsp;
        self.set_sregs(&[(SReg::SCTLR_EL1, 0)])
    }

    fn dump(&self) -> Result<()> {
        unimplemented!()
    }

    fn run(&mut self, entry: VmEntry) -> Result<VmExit> {
        match entry {
            VmEntry::None => {}
            VmEntry::Mmio { data } => self.entry_mmio(data)?,
            VmEntry::Shutdown => return Ok(VmExit::Shutdown),
            _ => unimplemented!("{entry:?}"),
        }
        if !self.power_on {
            let Ok(event) = self.receiver.recv() else {
                return Err(ErrorKind::BrokenPipe.into()).context(error::RunVcpu);
            };
            self.handle_event(&event)?;
            if !self.power_on {
                return Ok(VmExit::Shutdown);
            }
        }
        loop {
            let ret = unsafe { hv_vcpu_run(self.vcpu_id) };
            check_ret(ret).context(error::RunVcpu)?;

            while let Ok(event) = self.receiver.try_recv() {
                self.handle_event(&event)?;
                if !self.power_on {
                    return Ok(VmExit::Shutdown);
                }
            }

            let exit = unsafe { &*self.exit };
            match exit.reason {
                HvExitReason::EXCEPTION => {
                    self.handle_exception(&exit.exception)?;
                }
                _ => {
                    break error::VmExit {
                        msg: format!("{exit:x?}"),
                    }
                    .fail();
                }
            }
            if let Some(exit) = self.vmexit.take() {
                break Ok(exit);
            }
        }
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
#[path = "vcpu_test.rs"]
mod tests;
