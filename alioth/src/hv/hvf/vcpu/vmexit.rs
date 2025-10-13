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

use crate::arch::psci::{PSCI_VERSION_1_1, PsciFunc, PsciMigrateInfo};
use crate::arch::reg::{EsrEl2DataAbort, EsrEl2Ec, EsrEl2SysReg, MpidrEl1, Reg, SReg, encode};
use crate::hv::hvf::check_ret;
use crate::hv::hvf::vcpu::HvfVcpu;
use crate::hv::hvf::vm::VcpuEvent;
use crate::hv::{Result, Vcpu, VmExit, error};
use crate::sys::hvf::{HvReg, HvVcpuExitException, hv_vcpu_get_reg};

impl HvfVcpu {
    // https://esr.arm64.dev/
    pub fn handle_exception(&mut self, exception: &HvVcpuExitException) -> Result<()> {
        let esr = exception.syndrome;
        match esr.ec() {
            EsrEl2Ec::DATA_ABORT_LOWER => {
                self.decode_data_abort(EsrEl2DataAbort(esr.iss()), exception.physical_address)
            }
            EsrEl2Ec::HVC_64 => self.handle_hvc(),
            EsrEl2Ec::SYS_REG_64 => self.handle_sys_reg(EsrEl2SysReg(esr.iss())),
            _ => error::VmExit {
                msg: format!("Unhandled ESR: {esr:x?}"),
            }
            .fail(),
        }
    }

    pub fn decode_data_abort(&mut self, iss: EsrEl2DataAbort, gpa: u64) -> Result<()> {
        if !iss.isv() {
            return error::VmExit {
                msg: format!("Unhandled iss: {iss:x?}"),
            }
            .fail();
        }
        let reg = HvReg::from(iss.srt());
        let write = if iss.wnr() {
            let mut value = 0;
            let ret = unsafe { hv_vcpu_get_reg(self.vcpu_id, reg, &mut value) };
            check_ret(ret).context(error::VcpuReg)?;
            Some(value)
        } else {
            self.exit_reg = Some(reg);
            None
        };
        self.vmexit = Some(VmExit::Mmio {
            addr: gpa as _,
            write,
            size: 1 << iss.sas(),
        });
        self.advance_pc()
    }

    pub fn handle_hvc(&mut self) -> Result<()> {
        let func = self.get_reg(Reg::X0)?;
        let ret = match PsciFunc::from(func as u32) {
            PsciFunc::PSCI_VERSION => PSCI_VERSION_1_1 as u64,
            PsciFunc::MIGRATE_INFO_TYPE => PsciMigrateInfo::NOT_REQUIRED.raw() as u64,
            PsciFunc::PSCI_FEATURES => {
                let f = self.get_reg(Reg::X1)?;
                match PsciFunc::from(f as u32) {
                    PsciFunc::PSCI_VERSION
                    | PsciFunc::MIGRATE_INFO_TYPE
                    | PsciFunc::PSCI_FEATURES
                    | PsciFunc::SYSTEM_OFF
                    | PsciFunc::SYSTEM_OFF2_32
                    | PsciFunc::SYSTEM_OFF2_64
                    | PsciFunc::CPU_ON_32
                    | PsciFunc::CPU_ON_64
                    | PsciFunc::SYSTEM_RESET
                    | PsciFunc::SYSTEM_RESET2_32
                    | PsciFunc::SYSTEM_RESET2_64 => 0,
                    _ => u64::MAX,
                }
            }
            PsciFunc::SYSTEM_OFF | PsciFunc::SYSTEM_OFF2_32 | PsciFunc::SYSTEM_OFF2_64 => {
                self.vmexit = Some(VmExit::Shutdown);
                return Ok(());
            }
            PsciFunc::CPU_ON_32 | PsciFunc::CPU_ON_64 => {
                let mpidr = self.get_reg(Reg::X1)?;
                let pc = self.get_reg(Reg::X2)?;
                let context = self.get_reg(Reg::X3)?;
                if let Some(sender) = self.senders.lock().get(&MpidrEl1(mpidr)) {
                    sender.send(VcpuEvent::PowerOn { pc, context }).unwrap();
                    0
                } else {
                    log::error!("Failed to find CPU with mpidr {mpidr:#x}");
                    u64::MAX
                }
            }
            PsciFunc::SYSTEM_RESET | PsciFunc::SYSTEM_RESET2_32 | PsciFunc::SYSTEM_RESET2_64 => {
                self.vmexit = Some(VmExit::Reboot);
                return Ok(());
            }
            f => {
                return error::VmExit {
                    msg: format!("HVC: {f:x?}"),
                }
                .fail();
            }
        };
        self.set_regs(&[(Reg::X0, ret)])
    }

    pub fn handle_sys_reg(&mut self, iss: EsrEl2SysReg) -> Result<()> {
        if iss.is_read() {
            return error::VmExit {
                msg: format!("Unhandled iss: {iss:x?}"),
            }
            .fail();
        }
        let rt = HvReg::from(iss.rt());
        let mut val = 0;
        let ret = unsafe { hv_vcpu_get_reg(self.vcpu_id, rt, &mut val) };
        check_ret(ret).context(error::VcpuReg)?;
        let sreg = SReg::from(encode(
            iss.op0(),
            iss.op1(),
            iss.crn(),
            iss.crm(),
            iss.op2(),
        ));
        if sreg == SReg::OSDLR_EL1 || sreg == SReg::OSLAR_EL1 {
            log::warn!("vCPU-{} wrote {val:#x} to {sreg:?}", self.vcpu_id);
            self.advance_pc()?;
            return Ok(());
        }
        error::VmExit {
            msg: format!("Unhandled iss: {iss:x?}, sreg: {sreg:?}"),
        }
        .fail()
    }
}
