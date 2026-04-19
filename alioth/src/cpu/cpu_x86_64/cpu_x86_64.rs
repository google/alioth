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

mod sev;
mod tdx;

use std::path::Path;

use crate::arch::msr::{MiscEnable, Msr};
use crate::cpu::{Result, VcpuHandle, VcpuThread};
use crate::hv::{Coco, Vcpu, Vm};
use crate::loader::{InitState, Payload, firmware};
use crate::mem::mapped::ArcMemPages;

impl<V: Vm> VcpuThread<V> {
    pub(crate) fn init_vcpu(&mut self) -> Result<()> {
        let apic_id = self.ctx.board.encode_cpu_identity(self.index) as u32;
        let mut cpuids = self.ctx.board.arch.cpuids.clone();
        for (in_, out) in &mut cpuids {
            if in_.func == 0x1 {
                out.ebx &= 0x00ff_ffff;
                out.ebx |= apic_id << 24;
            } else if in_.func == 0xb || in_.func == 0x1f || in_.func == 0x80000026 {
                out.edx = apic_id;
            }
        }
        self.vcpu.set_cpuids(cpuids)?;

        let msrs = [(Msr::MISC_ENABLE, MiscEnable::FAST_STRINGS.bits())];
        self.vcpu.set_msrs(&msrs)?;
        Ok(())
    }

    pub(crate) fn init_boot_vcpu(&mut self, init: &InitState) -> Result<()> {
        if matches!(self.ctx.board.config.coco, Some(Coco::IntelTdx { .. })) {
            return Ok(());
        }
        self.vcpu
            .set_sregs(&init.sregs, &init.seg_regs, &init.dt_regs)?;
        self.vcpu.set_regs(&init.regs)?;
        Ok(())
    }

    pub(crate) fn init_ap(&mut self, vcpus: &[VcpuHandle]) -> Result<()> {
        let Some(coco) = &self.ctx.board.config.coco else {
            return Ok(());
        };
        self.sync_vcpus(vcpus)?;
        if self.index == 0 {
            return Ok(());
        }
        match coco {
            Coco::AmdSev { policy } => {
                if policy.es() {
                    self.sev_init_ap()?;
                }
            }
            Coco::AmdSnp { .. } => self.sev_init_ap()?,
            Coco::IntelTdx { .. } => self.tdx_init_ap()?,
        }
        Ok(())
    }

    pub(crate) fn setup_coco(&self, fw: &mut ArcMemPages) -> Result<()> {
        let Some(coco) = &self.ctx.board.config.coco else {
            return Ok(());
        };
        match coco {
            Coco::AmdSev { policy } => self.setup_sev(fw, *policy),
            Coco::AmdSnp { .. } => self.setup_snp(fw),
            Coco::IntelTdx { .. } => self.setup_tdx(fw),
        }
    }

    pub(crate) fn coco_finalize(&self, vcpus: &[VcpuHandle]) -> Result<()> {
        let Some(coco) = &self.ctx.board.config.coco else {
            return Ok(());
        };
        self.sync_vcpus(vcpus)?;
        if self.index != 0 {
            return Ok(());
        };
        match coco {
            Coco::AmdSev { policy } => self.sev_finalize(*policy),
            Coco::AmdSnp { .. } => self.snp_finalize(),
            Coco::IntelTdx { .. } => self.tdx_finalize(),
        }
    }

    pub(crate) fn setup_firmware(&self, fw: &Path, payload: &Payload) -> Result<InitState> {
        let (init_state, mut rom) = firmware::load(&self.ctx.board.memory, fw)?;
        self.setup_coco(&mut rom)?;
        self.ctx.board.setup_fw_cfg(payload)?;
        Ok(init_state)
    }

    pub(crate) fn reset_vcpu(&self) -> Result<()> {
        Ok(())
    }
}
