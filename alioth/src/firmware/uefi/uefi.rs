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

use crate::{bitflags, consts};

consts! {
    pub struct HobType(u16) {
        HANDOFF = 0x0001;
        RESOURCE_DESCRIPTOR = 0x0003;
        END_OF_HOB_LIST = 0xffff;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct HobGenericHeader {
    pub r#type: HobType,
    pub length: u16,
    pub reserved: u32,
}

pub const HOB_HANDOFF_TABLE_VERSION: u32 = 0x9;

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct HobHandoffInfoTable {
    pub hdr: HobGenericHeader,
    pub version: u32,
    pub boot_mode: u32,
    pub memory_top: u64,
    pub memory_bottom: u64,
    pub free_memory_top: u64,
    pub free_memory_bottom: u64,
    pub end_of_hob_list: u64,
}

consts! {
    pub struct HobResourceType(u32) {
        SYSTEM_MEMORY = 0x00000000;
        MEMORY_UNACCEPTED = 0x00000007;
    }
}

bitflags! {
    pub struct ResourceAttr(u32) {
        PRESENT =  1 << 0;
        INIT =  1 << 1;
        TESTED = 1 << 2;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct HobResourceDesc {
    pub hdr: HobGenericHeader,
    pub owner: [u8; 16],
    pub r#type: HobResourceType,
    pub attr: ResourceAttr,
    pub address: u64,
    pub len: u64,
}
