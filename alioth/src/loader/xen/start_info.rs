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

use zerocopy::{FromZeros, Immutable, IntoBytes};

pub const XEN_HVM_START_MAGIC_VALUE: u32 = 0x336ec578;
pub const XEN_HVM_START_INFO_V1: u32 = 1;

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromZeros, Immutable)]
pub struct HvmStartInfo {
    pub magic: u32,
    pub version: u32,
    pub flags: u32,
    pub nr_modules: u32,
    pub modlist_paddr: u64,
    pub cmdline_paddr: u64,
    pub rsdp_paddr: u64,
    pub memmap_paddr: u64,
    pub memmap_entries: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromZeros, Immutable)]
pub struct HvmModlistEntry {
    pub paddr: u64,
    pub size: u64,
    pub cmdline_paddr: u64,
    pub reserved: u64,
}

pub const XEN_HVM_MEMMAP_TYPE_RAM: u32 = 1;
pub const XEN_HVM_MEMMAP_TYPE_RESERVED: u32 = 2;
pub const XEN_HVM_MEMMAP_TYPE_ACPI: u32 = 3;
pub const XEN_HVM_MEMMAP_TYPE_NVS: u32 = 4;
pub const XEN_HVM_MEMMAP_TYPE_UNUSABLE: u32 = 5;
pub const XEN_HVM_MEMMAP_TYPE_DISABLED: u32 = 6;
pub const XEN_HVM_MEMMAP_TYPE_PMEM: u32 = 7;

#[repr(C)]
#[derive(Debug, Clone, Default, IntoBytes, FromZeros, Immutable)]
pub struct HvmMemmapTableEntry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
    pub reserved: u32,
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::{HvmMemmapTableEntry, HvmModlistEntry, HvmStartInfo};

    #[test]
    fn test_size() {
        assert_eq!(size_of::<HvmStartInfo>(), 0x38);
        assert_eq!(size_of::<HvmModlistEntry>(), 0x20);
        assert_eq!(size_of::<HvmMemmapTableEntry>(), 0x18);
    }
}
