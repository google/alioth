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

pub const ELF_HEADER_MAGIC: [u8; 4] = *b"\x7fELF";
pub const ELF_IDENT_CLASS_64: u8 = 2;
pub const ELF_IDENT_LITTLE_ENDIAN: u8 = 1;

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct Elf64Header {
    pub ident_magic: [u8; 4],
    pub ident_class: u8,
    pub ident_data: u8,
    pub ident_version: u8,
    pub ident_os_abi: u8,
    pub ident_abi_version: u8,
    pub _pad: [u8; 7],
    pub type_: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub ph_off: u64,
    pub sh_off: u64,
    pub flags: u32,
    pub eh_sz: u16,
    pub ph_ent_sz: u16,
    pub ph_num: u16,
    pub sh_ent_sz: u16,
    pub sh_num: u16,
    pub sh_str_ndx: u16,
}
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct Elf64ProgramHeader {
    pub type_: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub file_sz: u64,
    pub mem_sz: u64,
    pub align: u64,
}

pub const SHT_NOTE: u32 = 7;

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct Elf64SectionHeader {
    pub name: u32,
    pub type_: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addr_align: u64,
    pub ent_sz: u64,
}

pub const PT_LOAD: u32 = 1;
pub const PT_NOTE: u32 = 4;

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct Elf64Note {
    pub name_sz: u32,
    pub desc_sz: u32,
    pub type_: u32,
}

#[cfg(test)]
mod test {
    use std::mem::size_of;

    use super::{Elf64Header, Elf64ProgramHeader, Elf64SectionHeader};

    #[test]
    fn test_size() {
        assert_eq!(size_of::<Elf64Header>(), 0x40);
        assert_eq!(size_of::<Elf64ProgramHeader>(), 0x38);
        assert_eq!(size_of::<Elf64SectionHeader>(), 0x40);
    }
}
