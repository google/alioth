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

use std::cmp::min;
use std::io::Write;

use snafu::ResultExt;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::firmware::ovmf::x86_64::{GUID_SIZE, parse_data};
use crate::firmware::uefi::{
    HOB_HANDOFF_TABLE_VERSION, HobGenericHeader, HobHandoffInfoTable, HobResourceDesc,
    HobResourceType, HobType, ResourceAttr,
};
use crate::firmware::{Result, error};
use crate::mem::{MemRegionEntry, MemRegionType};
use crate::{bitflags, consts};

pub const GUID_TDX_METADATA_OFFSET: [u8; GUID_SIZE] = [
    0x35, 0x65, 0x7a, 0xe4, 0x4a, 0x98, 0x98, 0x47, 0x86, 0x5e, 0x46, 0x85, 0xa7, 0xbf, 0x8e, 0xc2,
];
pub const TDVF_SIGNATURE: u32 = u32::from_le_bytes(*b"TDVF");
pub const TDVF_VERSION: u32 = 1;

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct TdvfMetadata {
    pub signature: u32,
    pub length: u32,
    pub version: u32,
    pub number_of_entries: u32,
}

consts! {
    pub struct TdvfSectionType(u32) {
        BFV = 0;
        CFV = 1;
        TD_HOB = 2;
        TEMP_MEM = 3;
    }
}

bitflags! {
    pub struct TdvfSectionAttr(u32) {
        MR_EXTEND = 1 << 0;
        PAGE_AUG = 1 << 1;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct TdvfSectionEntry {
    pub data_offset: u32,
    pub data_size: u32,
    pub address: u64,
    pub size: u64,
    pub r#type: TdvfSectionType,
    pub attributes: TdvfSectionAttr,
}

pub fn parse_entries(data: &[u8]) -> Result<&[TdvfSectionEntry]> {
    let Some(offset_r) = parse_data(data, &GUID_TDX_METADATA_OFFSET) else {
        return error::MissingMetadata {
            name: "TdvfMetadata",
        }
        .fail();
    };
    let Ok(offset_r) = u32::read_from_bytes(offset_r) else {
        return error::InvalidLayout.fail();
    };
    let offset = data.len() - offset_r as usize;
    let Ok((metadata, remain)) = TdvfMetadata::ref_from_prefix(&data[offset..]) else {
        return error::InvalidLayout.fail();
    };
    if metadata.signature != TDVF_SIGNATURE {
        return error::MissingTdvfSignature {
            got: metadata.signature,
        }
        .fail();
    }
    if metadata.version != TDVF_VERSION {
        return error::MissingTdvfVersion {
            got: metadata.version,
        }
        .fail();
    }
    let Ok((entries, _)) = <[TdvfSectionEntry]>::ref_from_prefix_with_elems(
        remain,
        metadata.number_of_entries as usize,
    ) else {
        return error::InvalidLayout.fail();
    };
    Ok(entries)
}

fn create_hob_mem_resources(
    entries: &[(u64, MemRegionEntry)],
    accepted: &[(u64, u64)],
    mut op: impl FnMut(HobResourceDesc) -> Result<()>,
) -> Result<()> {
    let tmpl = HobResourceDesc {
        hdr: HobGenericHeader {
            r#type: HobType::RESOURCE_DESCRIPTOR,
            length: size_of::<HobResourceDesc>() as u16,
            reserved: 0,
        },
        owner: [0; 16],
        attr: ResourceAttr::PRESENT | ResourceAttr::INIT | ResourceAttr::TESTED,
        ..Default::default()
    };
    let mut iter_e = entries.iter();
    let mut iter_a = accepted.iter();
    let mut section = iter_a.next().copied();
    let mut entry = iter_e.next().copied();
    loop {
        match (&mut entry, &mut section) {
            (None, None) => break,
            (None, Some((start, size))) => {
                log::error!(
                    "Section [{start:x}, {:x}) is not covered by system memory",
                    *start + *size
                );
                return error::UncoveredTdvfSection.fail();
            }
            (Some((_, e)), _) if e.type_ != MemRegionType::Ram => {
                entry = iter_e.next().copied();
                continue;
            }
            (Some((s, e)), None) => {
                op(HobResourceDesc {
                    r#type: HobResourceType::MEMORY_UNACCEPTED,
                    address: *s,
                    len: e.size,
                    ..tmpl.clone()
                })?;
                entry = iter_e.next().copied();
            }
            (Some((s, e)), Some((start, size))) => {
                if let Some(len) = min(*s, *start + *size).checked_sub(*start)
                    && len > 0
                {
                    *size = len;
                    entry = None;
                    // Jump to branch (Some, None)
                    continue;
                }
                if let Some(len) = min(*s + e.size, *start).checked_sub(*s)
                    && len > 0
                {
                    op(HobResourceDesc {
                        r#type: HobResourceType::MEMORY_UNACCEPTED,
                        address: *s,
                        len,
                        ..tmpl.clone()
                    })?;
                    *s += len;
                    e.size -= len;
                }
                if let Some(len) = min(*s + e.size, *start + *size).checked_sub(*start)
                    && len > 0
                {
                    op(HobResourceDesc {
                        r#type: HobResourceType::SYSTEM_MEMORY,
                        address: *start,
                        len,
                        ..tmpl.clone()
                    })?;
                    *start += len;
                    *size -= len;
                    *s += len;
                    e.size -= len
                };
                if *size == 0 {
                    section = iter_a.next().copied();
                };
                if e.size == 0 {
                    entry = iter_e.next().copied();
                }
            }
        }
    }
    Ok(())
}

pub fn create_hob(
    buffer: &mut [u8],
    hob_phys: u64,
    entries: &mut [(u64, MemRegionEntry)],
    accepted: &mut [(u64, u64)],
) -> Result<()> {
    entries.sort_by_key(|(s, _)| *s);
    accepted.sort();

    let Ok((table, mut dst)) = HobHandoffInfoTable::mut_from_prefix(buffer) else {
        return error::InvalidLayout.fail();
    };

    let mut desc_size = 0;
    create_hob_mem_resources(entries, accepted, |d| {
        desc_size += size_of_val(&d);
        dst.write_all(d.as_bytes()).context(error::WriteHob)
    })?;

    let end = HobGenericHeader {
        r#type: HobType::END_OF_HOB_LIST,
        length: size_of::<HobGenericHeader>() as u16,
        reserved: 0,
    };
    dst.write_all(end.as_bytes()).context(error::WriteHob)?;

    *table = HobHandoffInfoTable {
        hdr: HobGenericHeader {
            r#type: HobType::HANDOFF,
            length: size_of::<HobHandoffInfoTable>() as u16,
            reserved: 0,
        },
        version: HOB_HANDOFF_TABLE_VERSION,
        end_of_hob_list: hob_phys + (size_of_val(table) + desc_size + size_of_val(&end)) as u64,
        ..Default::default()
    };

    Ok(())
}

#[cfg(test)]
#[path = "tdx_test.rs"]
mod tests;
