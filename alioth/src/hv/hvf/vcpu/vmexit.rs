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
use crate::arch::reg::{EsrEl2DataAbort, EsrEl2Ec, MpidrEl1, Reg};
use crate::hv::hvf::bindings::{HvReg, HvVcpuExitException, hv_vcpu_get_reg};
use crate::hv::hvf::check_ret;
use crate::hv::hvf::vcpu::HvfVcpu;
use crate::hv::hvf::vm::VcpuEvent;
use crate::hv::{Result, Vcpu, VmExit, error};

impl HvfVcpu {
    // https://esr.arm64.dev/
    pub fn handle_exception(&mut self, exception: &HvVcpuExitException) -> Result<()> {
        let esr = exception.syndrome;
        match esr.ec() {
            EsrEl2Ec::DATA_ABORT_LOWER => {
                self.decode_data_abort(EsrEl2DataAbort(esr.iss()), exception.physical_address)
            }
            EsrEl2Ec::HVC_64 => self.handle_hvc(),
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
        let pc = self.get_reg(Reg::Pc)?;
        self.set_regs(&[(Reg::Pc, pc + 4)])
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
                    | PsciFunc::CPU_ON_64 => 0,
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
            f => {
                return error::VmExit {
                    msg: format!("HVC: {f:x?}"),
                }
                .fail();
            }
        };
        self.set_regs(&[(Reg::X0, ret)])
    }
}
