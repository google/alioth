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

use crate::arch::reg::{EsrEl2DataAbort, EsrEl2Ec, Reg};
use crate::hv::hvf::bindings::{HvReg, HvVcpuExitException, hv_vcpu_get_reg};
use crate::hv::hvf::check_ret;
use crate::hv::hvf::vcpu::HvfVcpu;
use crate::hv::{Result, Vcpu, VmExit, error};

impl HvfVcpu {
    // https://esr.arm64.dev/
    pub fn handle_exception(&mut self, exception: &HvVcpuExitException) -> Result<bool> {
        let esr = exception.syndrome;
        match esr.ec() {
            EsrEl2Ec::DATA_ABORT_LOWER => {
                self.decode_data_abort(EsrEl2DataAbort(esr.iss()), exception.physical_address)
            }
            _ => Ok(false),
        }
    }

    pub fn decode_data_abort(&mut self, iss: EsrEl2DataAbort, gpa: u64) -> Result<bool> {
        if !iss.isv() {
            return Ok(false);
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
        self.vmexit = VmExit::Mmio {
            addr: gpa as _,
            write,
            size: 1 << iss.sas(),
        };
        let pc = self.get_reg(Reg::Pc)?;
        self.set_regs(&[(Reg::Pc, pc + 4)])?;
        Ok(true)
    }
}
