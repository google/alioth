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

use std::sync::atomic::Ordering;

use crate::arch::layout::MEM_64_START;
use crate::cpu::{Result, VcpuThread, error};
use crate::firmware::ovmf::tdx::{TdvfSectionAttr, TdvfSectionType, create_hob, parse_entries};
use crate::hv::{Vcpu, Vm};
use crate::mem::mapped::ArcMemPages;

impl<V> VcpuThread<V>
where
    V: Vm,
{
    pub(crate) fn create_hob(&self, dst: &mut [u8], mut accepted: Vec<(u64, u64)>) -> Result<u64> {
        let hob_phys = self.ctx.board.arch.tdx_hob.load(Ordering::Relaxed);
        let mut entries = self.ctx.board.memory.mem_region_entries();
        create_hob(dst, hob_phys, &mut entries, &mut accepted)?;
        Ok(hob_phys)
    }

    pub(crate) fn setup_tdx(&self, fw: &mut ArcMemPages) -> Result<()> {
        let data = fw.as_slice();
        let entries = parse_entries(data)?;

        let fw_gpa = MEM_64_START - data.len() as u64;
        let memory = &self.ctx.board.memory;
        memory.mark_private_memory(fw_gpa, data.len() as _, true)?;

        let mut accepted = Vec::new();
        let mut hob_ram = None;
        for entry in entries {
            match entry.r#type {
                TdvfSectionType::TD_HOB => {
                    let p = ArcMemPages::from_anonymous(entry.size as usize, None, None)?;
                    hob_ram = Some(p);
                    let tdx_hob = &self.ctx.board.arch.tdx_hob;
                    tdx_hob.store(entry.address, Ordering::Relaxed);
                    accepted.push((entry.address, entry.size));
                }
                TdvfSectionType::TEMP_MEM => {
                    accepted.push((entry.address, entry.size));
                }
                _ => {}
            };
        }

        let Some(hob_ram) = &mut hob_ram else {
            return error::MissingPayload.fail();
        };
        let hob_phys = self.create_hob(hob_ram.as_slice_mut(), accepted)?;

        self.vcpu.tdx_init_vcpu(hob_phys)?;

        for entry in entries {
            let tmp_mem;
            let region = match entry.r#type {
                TdvfSectionType::TD_HOB => hob_ram.as_slice(),
                TdvfSectionType::TEMP_MEM => {
                    tmp_mem = ArcMemPages::from_anonymous(entry.size as usize, None, None)?;
                    tmp_mem.as_slice()
                }
                TdvfSectionType::BFV | TdvfSectionType::CFV => {
                    let start = entry.data_offset as usize;
                    let end = start + entry.size as usize;
                    let Some(d) = data.get(start..end) else {
                        return error::MissingPayload.fail();
                    };
                    d
                }
                t => {
                    log::error!("Unknown entry type: {t:x?}");
                    return error::UnknownFirmwareMetadata.fail();
                }
            };
            let measure = entry.attributes.contains(TdvfSectionAttr::MR_EXTEND);
            self.vcpu
                .tdx_init_mem_region(region, entry.address, measure)?;
        }

        Ok(())
    }

    pub(crate) fn tdx_init_ap(&self) -> Result<()> {
        let hob = self.ctx.board.arch.tdx_hob.load(Ordering::Relaxed);
        self.vcpu.tdx_init_vcpu(hob)?;
        Ok(())
    }

    pub(crate) fn tdx_finalize(&self) -> Result<()> {
        self.ctx.board.vm.tdx_finalize_vm()?;
        Ok(())
    }
}
