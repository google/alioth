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

use std::arch::x86_64::__cpuid;
use std::mem::size_of;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::arch::layout::{BIOS_DATA_END, EBDA_END, EBDA_START, MEM_64_START, RAM_32_SIZE};
use crate::arch::reg::SegAccess;
use crate::arch::sev::SnpPageType;
use crate::board::{Board, BoardConfig, Result, VcpuGuard};
use crate::hv::arch::{Cpuid, Reg, SegReg, SegRegVal};
use crate::hv::{Coco, Hypervisor, Vcpu, Vm};
use crate::loader::InitState;
use crate::mem::mapped::ArcMemPages;
use crate::mem::{AddrOpt, MemRange, MemRegion, MemRegionEntry, MemRegionType};

pub struct ArchBoard {
    cpuids: Vec<Cpuid>,
    sev_ap_eip: AtomicU32,
}

impl ArchBoard {
    pub fn new<H: Hypervisor>(hv: &H, config: &BoardConfig) -> Result<Self> {
        let mut cpuids = hv.get_supported_cpuids()?;
        for cpuid in &mut cpuids {
            if cpuid.func == 0x1 {
                cpuid.ecx |= (1 << 24) | (1 << 31);
            } else if cpuid.func == 0x8000_001f {
                // AMD Volume 3, section E.4.17.
                if let Some(Coco::AmdSev { policy }) = &config.coco {
                    cpuid.eax = if policy.es() { 0x2 | 0x8 } else { 0x2 };
                    let host_ebx = unsafe { __cpuid(cpuid.func) }.ebx;
                    // set PhysAddrReduction to 1
                    cpuid.ebx = (1 << 6) | (host_ebx & 0x3f);
                    cpuid.ecx = 0;
                    cpuid.edx = 0;
                }
            }
        }
        Ok(Self {
            cpuids,
            sev_ap_eip: AtomicU32::new(0),
        })
    }
}

impl<V> Board<V>
where
    V: Vm,
{
    fn update_snp_desc(&self, offset: usize, fw_range: &mut [u8]) -> Result<()> {
        let ram_bus = self.memory.ram_bus();
        let ram = ram_bus.lock_layout();
        let desc = SevMetadataDesc::read_from_prefix(&fw_range[offset..]).unwrap();
        let snp_page_type = match desc.type_ {
            SEV_DESC_TYPE_SNP_SEC_MEM => SnpPageType::Unmeasured,
            SEV_DESC_TYPE_SNP_SECRETS => SnpPageType::Secrets,
            _ => unimplemented!(),
        };
        let range_ref = ram.get_slice::<u8>(desc.base as usize, desc.len as usize)?;
        let range_bytes =
            unsafe { std::slice::from_raw_parts_mut(range_ref.as_ptr() as _, range_ref.len()) };
        ram_bus.mark_private_memory(desc.base as _, desc.len as _, true)?;
        self.vm
            .snp_launch_update(range_bytes, desc.base as _, snp_page_type)?;
        Ok(())
    }

    pub fn setup_firmware(&self, fw: &mut ArcMemPages) -> Result<()> {
        let Some(coco) = &self.config.coco else {
            return Ok(());
        };
        let ram_bus = self.memory.ram_bus();
        ram_bus.register_encrypted_pages(fw)?;
        match coco {
            Coco::AmdSev { policy } => {
                if policy.es() {
                    let ap_eip =
                        parse_data_from_fw(fw.as_slice(), &SEV_ES_RESET_BLOCK_GUID).unwrap();
                    self.arch.sev_ap_eip.store(ap_eip, Ordering::Release);
                }
                self.vm.sev_launch_update_data(fw.as_slice_mut())?;
            }
            Coco::AmdSnp { .. } => {
                let fw_range = fw.as_slice_mut();
                let metadata_offset_r: u32 =
                    parse_data_from_fw(fw_range, &SEV_METADATA_GUID).unwrap();
                let metadata_offset = fw_range.len() - metadata_offset_r as usize;
                let metadata = SevMetaData::read_from_prefix(&fw_range[metadata_offset..]).unwrap();
                let desc_offset = metadata_offset + size_of::<SevMetaData>();
                for i in 0..metadata.num_desc as usize {
                    let offset = desc_offset + i * size_of::<SevMetadataDesc>();
                    self.update_snp_desc(offset, fw_range)?;
                }
                let fw_gpa = (MEM_64_START - fw_range.len()) as u64;
                ram_bus.mark_private_memory(fw_gpa, fw_range.len() as _, true)?;
                self.vm
                    .snp_launch_update(fw_range, fw_gpa, SnpPageType::Normal)
                    .unwrap();
            }
        }
        Ok(())
    }

    pub fn init_ap(&self, id: u32, vcpu: &mut V::Vcpu, vcpus: &VcpuGuard) -> Result<()> {
        let Some(Coco::AmdSev { policy }) = &self.config.coco else {
            return Ok(());
        };
        if !policy.es() {
            return Ok(());
        }
        self.sync_vcpus(vcpus);
        if id == 0 {
            return Ok(());
        }
        let eip = self.arch.sev_ap_eip.load(Ordering::Acquire);
        vcpu.set_regs(&[(Reg::Rip, eip as u64 & 0xffff)])?;
        vcpu.set_sregs(
            &[],
            &[(
                SegReg::Cs,
                SegRegVal {
                    selector: 0xf000,
                    base: eip as u64 & 0xffff_0000,
                    limit: 0xffff,
                    access: SegAccess(0x9b),
                },
            )],
            &[],
        )?;
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
        let ram_bus = memory.ram_bus();

        let low_mem_size = std::cmp::min(config.mem_size, RAM_32_SIZE);
        let pages_low = ArcMemPages::from_memfd(low_mem_size, None, Some(c"ram-low"))?;
        let region_low = MemRegion {
            size: low_mem_size,
            ranges: vec![MemRange::Mapped(pages_low.clone())],
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
        if let Some(coco) = &self.config.coco {
            ram_bus.register_encrypted_pages(&pages_low)?;
            if let Coco::AmdSnp { .. } = coco {
                ram_bus.mark_private_memory(0, low_mem_size as _, true)?;
            }
        }
        if config.mem_size > RAM_32_SIZE {
            let mem_hi_size = config.mem_size - RAM_32_SIZE;
            let mem_hi = ArcMemPages::from_memfd(mem_hi_size, None, Some(c"ram-high"))?;
            let region_hi = MemRegion::with_mapped(mem_hi.clone(), MemRegionType::Ram);
            memory.add_region(AddrOpt::Fixed(MEM_64_START), Arc::new(region_hi))?;
            if let Some(coco) = &self.config.coco {
                ram_bus.register_encrypted_pages(&mem_hi)?;
                if let Coco::AmdSnp { .. } = coco {
                    ram_bus.mark_private_memory(MEM_64_START as _, mem_hi_size as _, true)?;
                }
            }
        }
        Ok(())
    }
}

const GUID_TABLE_FOOTER_R_OFFSET: usize = 48;

const GUID_SIZE: usize = 16;

const GUID_TABLE_FOOTER_GUID: [u8; GUID_SIZE] = [
    0xDE, 0x82, 0xB5, 0x96, 0xB2, 0x1F, 0xF7, 0x45, 0xBA, 0xEA, 0xA3, 0x66, 0xC5, 0x5A, 0x08, 0x2D,
];

const SEV_ES_RESET_BLOCK_GUID: [u8; GUID_SIZE] = [
    0xde, 0x71, 0xf7, 0x00, 0x7e, 0x1a, 0xcb, 0x4f, 0x89, 0x0e, 0x68, 0xc7, 0x7e, 0x2f, 0xb4, 0x4e,
];

const SEV_METADATA_GUID: [u8; GUID_SIZE] = [
    0x66, 0x65, 0x88, 0xdc, 0x4a, 0x98, 0x98, 0x47, 0xA7, 0x5e, 0x55, 0x85, 0xa7, 0xbf, 0x67, 0xcc,
];

#[derive(Debug, FromZeroes, FromBytes, AsBytes)]
#[repr(C)]
struct SevMetaData {
    signature: u32,
    len: u32,
    version: u32,
    num_desc: u32,
}

pub const SEV_DESC_TYPE_SNP_SEC_MEM: u32 = 1;
pub const SEV_DESC_TYPE_SNP_SECRETS: u32 = 2;
pub const SEV_DESC_TYPE_CPUID: u32 = 3;

#[derive(Debug, FromBytes, FromZeroes, AsBytes)]
#[repr(C)]

struct SevMetadataDesc {
    base: u32,
    len: u32,
    type_: u32,
}

pub fn parse_data_from_fw<T>(blob: &[u8], guid: &[u8; GUID_SIZE]) -> Option<T>
where
    T: FromBytes,
{
    let offset_table_footer = blob.len().checked_sub(GUID_TABLE_FOOTER_R_OFFSET)?;
    if !blob[offset_table_footer..].starts_with(&GUID_TABLE_FOOTER_GUID) {
        return None;
    }
    let offset_table_len = offset_table_footer.checked_sub(size_of::<u16>())?;
    let table_len = u16::read_from_prefix(&blob[offset_table_len..])? as usize;
    let offset_table_end = offset_table_len.checked_sub(
        table_len
            .checked_sub(size_of::<u16>())?
            .checked_sub(GUID_SIZE)?,
    )?;
    let mut current = offset_table_len;
    while current > offset_table_end {
        let offset_len = current.checked_sub(GUID_SIZE + size_of::<u16>())?;
        if blob[(offset_len + 2)..].starts_with(guid) {
            return T::read_from_prefix(&blob[offset_len.checked_sub(size_of::<T>())?..]);
        }
        let table_len = u16::read_from_prefix(&blob[offset_len..])? as usize;
        current = current.checked_sub(table_len)?;
    }
    None
}
