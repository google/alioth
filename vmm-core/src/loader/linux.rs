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

use alloc::vec;
use core::mem::{size_of, size_of_val};

use bitflags::bitflags;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::hw::layout::{
    BOOT_GDT_START, BOOT_PAGING_START, EBDA_START, KERNEL_CMD_LINE_LIMIT, KERNEL_CMD_LINE_START,
    KERNEL_IMAGE_START, LINUX_BOOT_PARAMS_START,
};
use crate::hw::msr::Efer;
use crate::hw::paging::Entry;
use crate::hw::reg::{Cr0, Cr4, Rflags, SegAccess};
use crate::host::arch::{DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use crate::loader::{Error, InitState, PayloadReader, search_initramfs_address};
use crate::mem::mapped::{ByteRead, RamBus};
use crate::mem::{MemRegionEntry, MemRegionType};

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
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
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
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
pub struct BootE820Entry {
    pub addr: u64,
    pub size: u64,
    pub type_: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
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

// loading bzImage and ramdisk above 4G in 64bit.
const MINIMAL_VERSION: u16 = 0x020c;

pub fn load(
    memory: &RamBus,
    mem_regions: &[(u64, MemRegionEntry)],
    kernel: &mut PayloadReader<'_>,
    cmd_line: Option<&str>,
    initramfs: Option<&mut PayloadReader<'_>>,
) -> Result<InitState, Error> {
    let mut boot_params = BootParams::new_zeroed();
    let kernel_len = kernel.size();
    kernel.seek_to(SETUP_HEADER_OFFSET);
    kernel.read_exact_into(boot_params.hdr.as_bytes_mut())?;

    // For backwards compatibility, if the setup_sects field contains 0,
    // the real value is 4.
    if boot_params.hdr.setup_sects == 0 {
        boot_params.hdr.setup_sects = 4;
    }

    if boot_params.hdr.boot_flag != MAGIC_AA55 {
        return Err(Error::MissingMagic {
            magic: MAGIC_AA55 as u64,
            found: boot_params.hdr.boot_flag as u64,
        });
    }
    if boot_params.hdr.header != MAGIC_HDRS {
        return Err(Error::MissingMagic {
            magic: MAGIC_HDRS as u64,
            found: boot_params.hdr.header as u64,
        });
    }
    if boot_params.hdr.version < MINIMAL_VERSION {
        return Err(Error::TooOld {
            name: "bzimage",
            min: MINIMAL_VERSION as u64,
            found: boot_params.hdr.version as u64,
        });
    }
    if !XLoadFlags::from_bits_retain(boot_params.hdr.xloadflags).contains(XLoadFlags::XLF_KERNEL_64)
    {
        return Err(Error::Not64BitKernel);
    }
    if boot_params.hdr.relocatable_kernel == 0 {
        return Err(Error::NotRelocatableKernel);
    }

    boot_params.hdr.type_of_loader = 0xff;

    // load cmd line
    if let Some(cmd_line) = cmd_line {
        let cmd_line_limit =
            core::cmp::min(boot_params.hdr.cmdline_size as usize, KERNEL_CMD_LINE_LIMIT);
        if cmd_line.len() > cmd_line_limit {
            return Err(Error::CmdLineTooLong(cmd_line.len(), cmd_line_limit));
        }
        memory.write_range(
            KERNEL_CMD_LINE_START as u64,
            cmd_line.len(),
            cmd_line.as_bytes(),
        )?;
        boot_params.hdr.cmd_line_ptr = KERNEL_CMD_LINE_START as u32;
        boot_params.ext_cmd_line_ptr = (KERNEL_CMD_LINE_START as u64 >> 32) as u32;
    }

    // load kernel image
    let kernel_offset = (boot_params.hdr.setup_sects as u64 + 1) * 512;
    kernel.seek_to(kernel_offset);
    let kernel_size = (kernel_len - kernel_offset) as usize;
    memory.write_range(KERNEL_IMAGE_START as u64, kernel_size, kernel)?;

    // load initramfs
    let initramfs_range;
    if let Some(initramfs) = initramfs {
        initramfs.seek_to(0);
        let initramfs_size = initramfs.size() as usize;
        let initramfs_gpa = search_initramfs_address(
            mem_regions,
            initramfs_size as u64,
            boot_params.hdr.initrd_addr_max as u64,
        )?;
        let initramfs_end = initramfs_gpa + initramfs_size as u64;
        memory.write_range(initramfs_gpa, initramfs_size, initramfs)?;
        boot_params.hdr.ramdisk_image = initramfs_gpa as u32;
        boot_params.ext_ramdisk_image = (initramfs_gpa >> 32) as u32;
        boot_params.hdr.ramdisk_size = initramfs_size as u32;
        boot_params.ext_ramdisk_size = (initramfs_size as u64 >> 32) as u32;
        log::info!(
            "initramfs loaded at {:#x} - {:#x}, ",
            initramfs_gpa,
            initramfs_end - 1,
        );
        initramfs_range = Some(initramfs_gpa..initramfs_end);
    } else {
        initramfs_range = None;
    }

    // setup e820 table
    let mut region_index = 0;
    for (addr, region) in mem_regions.iter() {
        let type_ = match region.type_ {
            MemRegionType::Ram => E820_RAM,
            MemRegionType::Reserved => E820_RESERVED,
            MemRegionType::Acpi => E820_ACPI,
            MemRegionType::Pmem => E820_PMEM,
            MemRegionType::Hidden => continue,
        };
        boot_params.e820_table[region_index] = BootE820Entry {
            addr: *addr,
            size: region.size as u64,
            type_,
        };
        region_index += 1;
    }
    boot_params.e820_entries = mem_regions.len() as u8;

    boot_params.acpi_rsdp_addr = EBDA_START as u64;

    memory.write(LINUX_BOOT_PARAMS_START as u64, &boot_params)?;

    // set up identity paging
    let pml4_start = BOOT_PAGING_START as u64;
    let pdpt_start = pml4_start + 0x1000;
    let pml4e = (Entry::P | Entry::RW).bits() as u64 | pdpt_start;
    memory.write(pml4_start, &pml4e)?;
    let alignment = boot_params.hdr.kernel_alignment as usize;
    let runtime_start = (KERNEL_IMAGE_START + alignment - 1) & !(alignment - 1);
    let max_addr = core::cmp::max(
        runtime_start + boot_params.hdr.init_size as usize,
        core::cmp::max(
            LINUX_BOOT_PARAMS_START + size_of::<BootParams>(),
            KERNEL_CMD_LINE_START + KERNEL_CMD_LINE_LIMIT,
        ),
    );
    let num_page = (max_addr as u64 + (1 << 30) - 1) >> 30;
    for i in 0..num_page {
        let pdpte = (i << 30) | (Entry::P | Entry::RW | Entry::PS).bits() as u64;
        memory.write(pdpt_start + i * size_of::<u64>() as u64, &pdpte)?;
    }

    // set up gdt
    let boot_cs = SegRegVal {
        selector: 0x10,
        base: 0,
        limit: 0xfff_ffff,
        access: SegAccess(0xa09b),
    };
    let boot_ds = SegRegVal {
        selector: 0x18,
        base: 0,
        limit: 0xfff_ffff,
        access: SegAccess(0xc093),
    };
    let boot_tr = SegRegVal {
        selector: 0x20,
        base: 0,
        limit: 0,
        access: SegAccess(0x8b),
    };
    let boot_ldtr = SegRegVal {
        selector: 0x28,
        base: 0,
        limit: 0,
        access: SegAccess(0x82),
    };
    let gdt = [
        0,
        0,
        boot_cs.to_desc(),
        boot_ds.to_desc(),
        boot_tr.to_desc(),
        boot_ldtr.to_desc(),
    ];
    let gdtr = DtRegVal {
        base: BOOT_GDT_START as u64,
        limit: size_of_val(&gdt) as u16 - 1,
    };
    let idtr = DtRegVal { base: 0, limit: 0 };
    memory.write(BOOT_GDT_START as u64, &gdt)?;

    Ok(InitState {
        regs: vec![
            (Reg::Rsi, LINUX_BOOT_PARAMS_START as u64),
            (Reg::Rip, KERNEL_IMAGE_START as u64 + 0x200),
            (Reg::Rflags, Rflags::RESERVED_1.bits() as u64),
        ],
        sregs: vec![
            (SReg::Efer, (Efer::LMA | Efer::LME).bits() as u64),
            (SReg::Cr0, (Cr0::NE | Cr0::PE | Cr0::PG).bits() as u64),
            (SReg::Cr3, pml4_start),
            (SReg::Cr4, Cr4::PAE.bits() as u64),
        ],
        seg_regs: vec![
            (SegReg::Cs, boot_cs),
            (SegReg::Ds, boot_ds),
            (SegReg::Es, boot_ds),
            (SegReg::Fs, boot_ds),
            (SegReg::Gs, boot_ds),
            (SegReg::Ss, boot_ds),
            (SegReg::Tr, boot_tr),
            (SegReg::Ldtr, boot_ldtr),
        ],
        dt_regs: vec![(DtReg::Gdtr, gdtr), (DtReg::Idtr, idtr)],
        initramfs: initramfs_range,
    })
}
