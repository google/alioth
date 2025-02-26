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

use crate::hv::VmExit;
use crate::hv::hvf::bindings::hv_vcpu_set_reg;
use crate::hv::hvf::check_ret;
use crate::hv::hvf::vcpu::HvfVcpu;

impl HvfVcpu {
    pub fn entry_mmio(&mut self, data: u64) {
        if !matches!(self.vmexit, VmExit::Mmio { write: None, .. }) {
            panic!()
        }
        let Some(reg) = self.exit_reg else { panic!() };
        let ret = unsafe { hv_vcpu_set_reg(self.vcpu_id, reg, data) };
        check_ret(ret).unwrap();
    }
}
