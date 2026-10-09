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

pub const GUID_SIZE: usize = 16;

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
    pub owner: [u8; GUID_SIZE],
    pub r#type: HobResourceType,
    pub attr: ResourceAttr,
    pub address: u64,
    pub len: u64,
}

pub const EFI_SYSTEM_TABLE_SIGNATURE: u64 = 0x5453_5953_2049_4249; // "IBI SYST"
pub const EFI_2_100_SYSTEM_TABLE_REVISION: u32 = (2 << 16) | 100;

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct EfiTableHeader {
    pub signature: u64,
    pub revision: u32,
    pub headersize: u32,
    pub crc32: u32,
    pub reserved: u32,
}

// 8868e871-e4f1-11d3-bc22-0080c73c8881
pub const GUID_ACPI_20_TABLE: [u8; GUID_SIZE] = [
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11, 0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
];

// eb66918a-7eef-402a-842e-931d21c38ae9
pub const GUID_EFI_RT_PROPERTIES_TABLE: [u8; GUID_SIZE] = [
    0x8a, 0x91, 0x66, 0xeb, 0xef, 0x7e, 0x2a, 0x40, 0x84, 0x2e, 0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9,
];

// 888eb0c6-8ede-4ff5-a8f0-9aee5cb977c2
pub const GUID_LINUX_EFI_MEMRESERVE_TABLE: [u8; GUID_SIZE] = [
    0xc6, 0xb0, 0x8e, 0x88, 0xde, 0x8e, 0xf5, 0x4f, 0xa8, 0xf0, 0x9a, 0xee, 0x5c, 0xb9, 0x77, 0xc2,
];

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct EfiConfigTable64 {
    pub guid: [u8; GUID_SIZE],
    pub table: u64,
}

pub const EFI_RT_PROPERTIES_TABLE_VERSION: u16 = 0x1;

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct EfiRtPropertiesTable {
    pub version: u16,
    pub length: u16,
    pub runtime_services_supported: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct LinuxEfiMemreserve {
    pub size: i32,
    pub count: i32,
    pub next: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct EfiSystemTable64 {
    pub hdr: EfiTableHeader,
    pub fw_vendor: u64,
    pub fw_revision: u32,
    pub _pad: u32,
    pub con_in_handle: u64,
    pub con_in: u64,
    pub con_out_handle: u64,
    pub con_out: u64,
    pub stderr_handle: u64,
    pub stderr: u64,
    pub runtime: u64,
    pub boottime: u64,
    pub nr_tables: u64,
    pub tables: u64,
}

pub const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;

consts! {
    pub struct EfiMemoryType(u32) {
        RESERVED = 0;
        LOADER_CODE = 1;
        LOADER_DATA = 2;
        BOOT_SERVICES_CODE = 3;
        BOOT_SERVICES_DATA = 4;
        RUNTIME_SERVICES_CODE = 5;
        RUNTIME_SERVICES_DATA = 6;
        CONVENTIONAL_MEMORY = 7;
        UNUSABLE_MEMORY = 8;
        ACPI_RECLAIM_MEMORY = 9;
        ACPI_MEMORY_NVS = 10;
        MMIO = 11;
        MMIO_PORT_SPACE = 12;
        PAL_CODE = 13;
        PERSISTENT_MEMORY = 14;
    }
}

bitflags! {
    pub struct EfiMemoryAttribute(u64) {
        UC = 1 << 0;
        WC = 1 << 1;
        WT = 1 << 2;
        WB = 1 << 3;
        UCE = 1 << 4;
        WP = 1 << 12;
        RP = 1 << 13;
        XP = 1 << 14;
        NV = 1 << 15;
        MORE_RELIABLE = 1 << 16;
        RO = 1 << 17;
        SP = 1 << 18;
        CPU_CRYPTO = 1 << 19;
        RUNTIME = 1 << 63;
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, KnownLayout, Immutable, FromBytes, IntoBytes)]
pub struct EfiMemoryDesc {
    pub ty: EfiMemoryType,
    pub pad: u32,
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub num_pages: u64,
    pub attribute: EfiMemoryAttribute,
}

#[cfg(test)]
#[path = "uefi_test.rs"]
mod tests;
