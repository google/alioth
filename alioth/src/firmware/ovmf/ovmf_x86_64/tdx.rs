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

use crate::firmware::ovmf::x86_64::GUID_SIZE;
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
    #[derive(Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
    pub struct TdvfSectionType(u32) {
        BFV = 0;
        CFV = 1;
        TD_HOB = 2;
        TEMP_MEM = 3;
    }
}

bitflags! {
    #[derive(Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
    pub struct TdvfSectionAttribute(u32) {
        MR_EXTEND = 1 << 0;
        PAGE_AUG = 1 << 1;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct TdxMetadataSection {
    pub data_offset: u32,
    pub raw_data_size: u32,
    pub memory_address: u64,
    pub memory_data_size: u64,
    pub r#type: TdvfSectionType,
    pub attributes: TdvfSectionAttribute,
}
