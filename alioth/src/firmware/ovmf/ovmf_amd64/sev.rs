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

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::consts;
use crate::firmware::ovmf::x86_64::{GUID_SIZE, parse_data};
use crate::firmware::{Result, error};

pub const GUID_SEV_ES_RESET_BLOCK: [u8; GUID_SIZE] = [
    0xde, 0x71, 0xf7, 0x00, 0x7e, 0x1a, 0xcb, 0x4f, 0x89, 0x0e, 0x68, 0xc7, 0x7e, 0x2f, 0xb4, 0x4e,
];

pub const GUID_SEV_METADATA: [u8; GUID_SIZE] = [
    0x66, 0x65, 0x88, 0xdc, 0x4a, 0x98, 0x98, 0x47, 0xA7, 0x5e, 0x55, 0x85, 0xa7, 0xbf, 0x67, 0xcc,
];
pub const SEV_SIGNATURE: u32 = u32::from_le_bytes(*b"ASEV");

#[derive(Debug, KnownLayout, Immutable, FromBytes, IntoBytes)]
#[repr(C)]
pub struct SevMetaData {
    pub signature: u32,
    pub len: u32,
    pub version: u32,
    pub num_desc: u32,
}

consts! {
    pub struct SevDescType(u32) {
        SNP_DESC_MEM = 1;
        SNP_SECRETS = 2;
        CPUID = 3;
    }
}

#[derive(Debug, KnownLayout, Immutable, FromBytes, IntoBytes)]
#[repr(C)]
pub struct SevMetadataDesc {
    pub base: u32,
    pub len: u32,
    pub type_: SevDescType,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct SnpCpuidFunc {
    pub eax_in: u32,
    pub ecx_in: u32,
    pub xcr0_in: u64,
    pub xss_in: u64,
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
    pub reserved: u64,
}

#[repr(C)]
#[derive(Debug, Clone, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct SnpCpuidInfo {
    pub count: u32,
    pub _reserved1: u32,
    pub _reserved2: u64,
    pub entries: [SnpCpuidFunc; 64],
}

pub fn parse_sev_ap_eip(data: &[u8]) -> Result<u32> {
    let Some(ap_eip) = parse_data(data, &GUID_SEV_ES_RESET_BLOCK) else {
        return error::MissingMetadata {
            name: "SevEsResetBlock",
        }
        .fail();
    };
    let Ok(ap_eip) = u32::read_from_bytes(ap_eip) else {
        return error::InvalidLayout.fail();
    };
    Ok(ap_eip)
}

pub fn parse_desc(data: &[u8]) -> Result<&[SevMetadataDesc]> {
    let Some(offset_r) = parse_data(data, &GUID_SEV_METADATA) else {
        return error::MissingMetadata {
            name: "SevMetadata",
        }
        .fail();
    };
    let Ok(offset_r) = u32::read_from_bytes(offset_r) else {
        return error::InvalidLayout.fail();
    };
    let offset = data.len() - offset_r as usize;
    let Ok((metadata, remain)) = SevMetaData::ref_from_prefix(&data[offset..]) else {
        return error::InvalidLayout.fail();
    };
    if metadata.signature != SEV_SIGNATURE {
        return error::MissingAmdSevSignature {
            got: metadata.signature,
        }
        .fail();
    };
    let Ok((entries, _)) =
        <[SevMetadataDesc]>::ref_from_prefix_with_elems(remain, metadata.num_desc as usize)
    else {
        return error::InvalidLayout.fail();
    };
    Ok(entries)
}
