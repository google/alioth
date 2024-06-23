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

use crate::arch::reg::{Reg, SReg};
use crate::hv::{Result, Vcpu, VmEntry, VmExit};

#[derive(Debug)]
pub struct HvfVcpu {}

impl Vcpu for HvfVcpu {
    fn reset(&self, _is_bsp: bool) -> Result<()> {
        unimplemented!()
    }

    fn dump(&self) -> Result<()> {
        unimplemented!()
    }

    fn get_reg(&self, _reg: Reg) -> Result<u64> {
        unimplemented!()
    }

    fn run(&mut self, _entry: VmEntry) -> Result<VmExit> {
        unimplemented!()
    }

    fn set_regs(&mut self, _vals: &[(Reg, u64)]) -> Result<()> {
        unimplemented!()
    }

    fn get_sreg(&self, _reg: SReg) -> Result<u64> {
        unimplemented!()
    }

    fn set_sregs(&mut self, _sregs: &[(SReg, u64)]) -> Result<()> {
        unimplemented!()
    }
}
