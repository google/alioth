// Copyright 2026 Google LLC
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

use std::path::Path;

use crate::cpu::{Result, VcpuHandle, VcpuThread};
use crate::hv::{Vcpu, Vm};
use crate::loader::{InitState, Payload};

impl<V: Vm> VcpuThread<V> {
    pub(crate) fn init_vcpu(&mut self) -> Result<()> {
        self.reset_vcpu()
    }

    pub(crate) fn init_boot_vcpu(&mut self, init: &InitState) -> Result<()> {
        self.vcpu.set_regs(&init.regs)?;
        self.vcpu.set_sregs(&init.sregs)?;
        Ok(())
    }

    pub(crate) fn init_ap(&mut self, _: &[VcpuHandle]) -> Result<()> {
        Ok(())
    }

    pub(crate) fn coco_finalize(&self, _: &[VcpuHandle]) -> Result<()> {
        Ok(())
    }

    pub(crate) fn setup_firmware(&self, _: &Path, _: &Payload) -> Result<InitState> {
        unimplemented!()
    }

    pub(crate) fn reset_vcpu(&mut self) -> Result<()> {
        self.vcpu.reset(self.index == 0)?;
        Ok(())
    }
}
