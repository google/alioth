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

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

pub const MAGIC_AA55: u16 = 0xaa55;
pub const MAGIC_HDRS: u32 = 0x53726448; // "HdrS"
pub const SETUP_HEADER_OFFSET: u64 = 0x01f1;

bitflags! {
    #[repr(C)]
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct LoadFlags: u8 {
        const LOADED_HIGH = (1<<0);
        const KASLR_FLAG = (1<<1);
        const QUIET_FLAG = (1<<5);
        const KEEP_SEGMENTS	= (1<<6);
        const CAN_USE_HEAP = (1<<7);
   }
}

bitflags! {
    #[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct XLoadFlags: u16 {
        const XLF_KERNEL_64 = (1<<0);
        const XLF_CAN_BE_LOADED_ABOVE_4G = (1<<1);
        const XLF_EFI_HANDOVER_32 = (1<<2);
        const XLF_EFI_HANDOVER_64 = (1<<3);
        const XLF_EFI_KEXEC = (1<<4);
        const XLF_5LEVEL = (1<<5);
        const XLF_5LEVEL_ENABLED = (1<<6);
    }
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
pub struct SetupHeader {
    pub setup_sects: u8,
    pub root_flags: u16,
    pub syssize: u32,
    pub ram_size: u16,
    pub vid_mode: u16,
    pub root_dev: u16,
    pub boot_flag: u16,
    pub jump: u16,
    pub header: u32,
    pub version: u16,
    pub realmode_swtch: u32,
    pub start_sys_seg: u16,
    pub kernel_version: u16,
    pub type_of_loader: u8,
    pub loadflags: u8,
    pub setup_move_size: u16,
    pub code32_start: u32,
    pub ramdisk_image: u32,
    pub ramdisk_size: u32,
    pub bootsect_kludge: u32,
    pub heap_end_ptr: u16,
    pub ext_loader_ver: u8,
    pub ext_loader_type: u8,
    pub cmd_line_ptr: u32,
    pub initrd_addr_max: u32,
    pub kernel_alignment: u32,
    pub relocatable_kernel: u8,
    pub min_alignment: u8,
    pub xloadflags: u16,
    pub cmdline_size: u32,
    pub hardware_subarch: u32,
    pub hardware_subarch_data: u64,
    pub payload_offset: u32,
    pub payload_length: u32,
    pub setup_data: u64,
    pub pref_address: u64,
    pub init_size: u32,
    pub handover_offset: u32,
    pub kernel_info_offset: u32,
}

pub const E820_RAM: u32 = 1;
pub const E820_RESERVED: u32 = 2;
pub const E820_ACPI: u32 = 3;
pub const E820_NVS: u32 = 4;
pub const E820_UNUSABLE: u32 = 5;
pub const E820_PMEM: u32 = 7;
pub const E820_RESERVED_KERN: u32 = 128;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
pub struct BootE820Entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
pub struct BootParams {
    pub screen_info: [u8; 64],
    pub apm_bios_info: [u8; 20],
    pub _pad2: [u8; 4usize],
    pub tboot_addr: u64,
    pub ist_info: [u8; 16],
    pub acpi_rsdp_addr: u64,
    pub _pad3: [u8; 8usize],
    pub hd0_info: [u8; 16usize],
    pub hd1_info: [u8; 16usize],
    pub sys_desc_table: [u8; 16],
    pub olpc_ofw_header: [u8; 16],
    pub ext_ramdisk_image: u32,
    pub ext_ramdisk_size: u32,
    pub ext_cmd_line_ptr: u32,
    pub _pad4: [u8; 112usize],
    pub cc_blob_address: u32,
    pub edid_info: [u8; 128],
    pub efi_info: [u8; 32],
    pub alt_mem_k: u32,
    pub scratch: u32,
    pub e820_entries: u8,
    pub eddbuf_entries: u8,
    pub edd_mbr_sig_buf_entries: u8,
    pub kbd_status: u8,
    pub secure_boot: u8,
    pub _pad5: [u8; 2usize],
    pub sentinel: u8,
    pub _pad6: [u8; 1usize],
    pub hdr: SetupHeader,
    pub _pad7: [u8; 36usize],
    pub edd_mbr_sig_buffer: [u32; 16usize],
    pub e820_table: [BootE820Entry; 128usize],
    pub _pad8: [u8; 48usize],
    pub eddbuf: [u8; 492usize],
    pub _pad9: [u8; 276usize],
}
