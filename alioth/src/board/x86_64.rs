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

use std::sync::Arc;

use parking_lot::Mutex;

use crate::arch::layout::{BIOS_DATA_END, EBDA_END, EBDA_START, MEM_64_START, RAM_32_SIZE};
use crate::board::{Board, Result};
use crate::hv::arch::Cpuid;
use crate::hv::{Coco, Hypervisor, Vcpu, Vm};
use crate::loader::InitState;
use crate::mem::mapped::ArcMemPages;
use crate::mem::{AddrOpt, MemRange, MemRegion, MemRegionEntry, MemRegionType};

pub struct ArchBoard {
    cpuids: Vec<Cpuid>,
}

impl ArchBoard {
    pub fn new<H: Hypervisor>(hv: &H) -> Result<Self> {
        let mut cpuids = hv.get_supported_cpuids()?;
        for cpuid in &mut cpuids {
            if cpuid.func == 0x1 {
                cpuid.ecx |= (1 << 24) | (1 << 31);
            }
        }
        Ok(Self { cpuids })
    }
}

impl<V> Board<V>
where
    V: Vm,
{
    pub fn setup_firmware(&self, fw: &mut ArcMemPages) -> Result<()> {
        match &self.config.coco {
            Some(Coco::AmdSev { .. }) => {
                self.memory.ram_bus().register_encrypted_pages(&fw)?;
            }
            None => {}
        }
        Ok(())
    }
    pub fn init_boot_vcpu(&self, vcpu: &mut V::Vcpu, init_state: &InitState) -> Result<()> {
        vcpu.set_sregs(&init_state.sregs, &init_state.seg_regs, &init_state.dt_regs)?;
        vcpu.set_regs(&init_state.regs)?;
        Ok(())
    }

    pub fn init_vcpu(&self, id: u32, vcpu: &mut V::Vcpu) -> Result<()> {
        let mut cpuids = self.arch.cpuids.clone();
        for cpuid in &mut cpuids {
            if cpuid.func == 0x1 {
                cpuid.ebx &= 0x00ff_ffff;
                cpuid.ebx |= id << 24;
            } else if cpuid.func == 0xb {
                cpuid.edx = id;
            }
        }
        vcpu.set_cpuids(cpuids)?;
        Ok(())
    }

    pub fn create_ram(&self) -> Result<()> {
        let config = &self.config;
        let memory = &self.memory;

        let low_mem_size = std::cmp::min(config.mem_size, RAM_32_SIZE);
        let pages_low = ArcMemPages::new_anon(low_mem_size)?;
        if self.config.coco.is_some() {
            self.memory.ram_bus().register_encrypted_pages(&pages_low)?;
        }
        let region_low = MemRegion {
            size: low_mem_size,
            ranges: vec![MemRange::Mapped(pages_low)],
            entries: vec![
                MemRegionEntry {
                    size: BIOS_DATA_END,
                    type_: MemRegionType::Reserved,
                },
                MemRegionEntry {
                    size: EBDA_START - BIOS_DATA_END,
                    type_: MemRegionType::Ram,
                },
                MemRegionEntry {
                    size: EBDA_END - EBDA_START,
                    type_: MemRegionType::Acpi,
                },
                MemRegionEntry {
                    size: low_mem_size - EBDA_END,
                    type_: MemRegionType::Ram,
                },
            ],
            callbacks: Mutex::new(vec![]),
        };
        memory.add_region(AddrOpt::Fixed(0), Arc::new(region_low))?;
        if config.mem_size > RAM_32_SIZE {
            let mem_hi = ArcMemPages::new_anon(config.mem_size - RAM_32_SIZE)?;
            if self.config.coco.is_some() {
                self.memory.ram_bus().register_encrypted_pages(&mem_hi)?;
            }
            let region_hi = MemRegion::with_mapped(mem_hi, MemRegionType::Ram);
            memory.add_region(AddrOpt::Fixed(MEM_64_START), Arc::new(region_hi))?;
        }
        Ok(())
    }
}
