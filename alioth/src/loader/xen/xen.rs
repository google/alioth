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

pub mod start_info;

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::mem::{offset_of, size_of, size_of_val};
use std::path::Path;

use snafu::ResultExt;
use zerocopy::{FromZeros, Immutable, IntoBytes};

use crate::align_up;
use crate::arch::layout::{
    BOOT_GDT_START, EBDA_START, HVM_START_INFO_START, KERNEL_CMD_LINE_LIMIT, KERNEL_CMD_LINE_START,
};
use crate::arch::reg::{Cr0, DtReg, DtRegVal, Reg, Rflags, SReg, SegAccess, SegReg, SegRegVal};
use crate::loader::elf::{
    ELF_HEADER_MAGIC, ELF_IDENT_CLASS_64, ELF_IDENT_LITTLE_ENDIAN, Elf64Header, Elf64Note,
    Elf64ProgramHeader, Elf64SectionHeader, PT_NOTE, SHT_NOTE,
};
use crate::loader::xen::start_info::{
    XEN_HVM_MEMMAP_TYPE_ACPI, XEN_HVM_MEMMAP_TYPE_PMEM, XEN_HVM_MEMMAP_TYPE_RAM,
    XEN_HVM_MEMMAP_TYPE_RESERVED, XEN_HVM_START_INFO_V1, XEN_HVM_START_MAGIC_VALUE,
};
use crate::loader::{InitState, Result, error, search_initramfs_address};
use crate::mem::mapped::RamBus;
use crate::mem::{MemRegionEntry, MemRegionType};

use self::start_info::{HvmMemmapTableEntry, HvmModlistEntry, HvmStartInfo};

pub const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

#[repr(C)]
#[derive(Debug, IntoBytes, Default, Immutable)]
struct StartInfoPage {
    start_info: HvmStartInfo,
    initramfs: HvmModlistEntry,
    memory_map: [HvmMemmapTableEntry; 32],
}

fn search_pvh_note<F: Read + Seek>(
    file: &mut F,
    offset: u64,
    size: u64,
    align: u64,
) -> std::io::Result<Option<u64>> {
    if align.count_ones() > 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("align = {align}, not a power of 2"),
        ));
    }
    let align_bits = std::cmp::max(align, 1).trailing_zeros();
    let mut pos = 0;
    while pos < size {
        file.seek(SeekFrom::Start(offset + pos))?;
        let mut header = Elf64Note::new_zeroed();
        file.read_exact(header.as_mut_bytes())?;
        pos += size_of::<Elf64Note>() as u64;
        pos += align_up!(header.desc_sz as u64, align_bits);
        pos += align_up!(header.name_sz as u64, align_bits);
        if header.type_ != XEN_ELFNOTE_PHYS32_ENTRY {
            continue;
        }
        file.seek(SeekFrom::Current(
            align_up!(header.name_sz as u64, align_bits) as i64,
        ))?;
        match header.desc_sz {
            4 => {
                let mut entry_point = 0u32;
                file.read_exact(entry_point.as_mut_bytes())?;
                return Ok(Some(entry_point as u64));
            }
            8 => {
                let mut entry_point = 0u64;
                file.read_exact(entry_point.as_mut_bytes())?;
                return Ok(Some(entry_point));
            }
            _ => {}
        }
    }

    Ok(None)
}

// https://xenbits.xen.org/docs/4.18-testing/misc/pvh.html
pub fn load<P: AsRef<Path>>(
    memory: &RamBus,
    mem_regions: &[(u64, MemRegionEntry)],
    kernel: P,
    cmd_line: Option<&str>,
    initramfs: Option<P>,
) -> Result<InitState> {
    let access_kernel = error::AccessFile {
        path: kernel.as_ref(),
    };
    let mut kernel = BufReader::new(File::open(&kernel).context(access_kernel)?);

    // load kernel
    let mut elf_header = Elf64Header::new_zeroed();
    kernel
        .read_exact(elf_header.as_mut_bytes())
        .context(access_kernel)?;
    if elf_header.ident_magic != ELF_HEADER_MAGIC {
        return error::MissingMagic {
            magic: u32::from_ne_bytes(ELF_HEADER_MAGIC) as u64,
            found: u32::from_ne_bytes(elf_header.ident_magic) as u64,
        }
        .fail();
    }
    if elf_header.ident_class != ELF_IDENT_CLASS_64 {
        return error::Not64Bit.fail();
    }
    assert_eq!(elf_header.ident_data, ELF_IDENT_LITTLE_ENDIAN);

    let mut pvh_entry = None;

    kernel
        .seek(SeekFrom::Start(elf_header.ph_off))
        .context(access_kernel)?;
    let mut program_header =
        Elf64ProgramHeader::new_vec_zeroed(elf_header.ph_num as usize).unwrap();
    kernel
        .read_exact(program_header.as_mut_bytes())
        .context(access_kernel)?;
    for program_header in program_header.iter() {
        if program_header.type_ == PT_NOTE && pvh_entry.is_none() {
            pvh_entry = search_pvh_note(
                &mut kernel,
                program_header.offset,
                program_header.file_sz,
                program_header.align,
            )
            .context(access_kernel)?;
        }
        if program_header.file_sz > 0 {
            let addr = program_header.paddr;
            let size = program_header.file_sz;
            kernel
                .seek(SeekFrom::Start(program_header.offset))
                .context(access_kernel)?;
            memory.write_range(addr, size, &mut kernel)?;
            log::info!("loaded at {:#x?}-{:#x?}", addr, addr + size);
        }
    }

    if pvh_entry.is_none() && elf_header.sh_num > 0 {
        kernel
            .seek(SeekFrom::Start(elf_header.sh_off))
            .context(access_kernel)?;
        let mut sections = Elf64SectionHeader::new_vec_zeroed(elf_header.sh_num as usize).unwrap();
        kernel
            .read_exact(sections.as_mut_bytes())
            .context(access_kernel)?;
        for section in sections.iter() {
            if section.type_ != SHT_NOTE {
                continue;
            }
            pvh_entry = search_pvh_note(
                &mut kernel,
                section.offset,
                section.size,
                section.addr_align,
            )
            .context(access_kernel)?;
            if pvh_entry.is_some() {
                break;
            }
        }
    }

    let Some(entry_point) = pvh_entry else {
        return error::NoEntryPoint.fail();
    };
    log::info!("PVH entry = {entry_point:#x?}");

    let mut start_info_page = StartInfoPage {
        start_info: HvmStartInfo {
            magic: XEN_HVM_START_MAGIC_VALUE,
            version: XEN_HVM_START_INFO_V1,
            cmdline_paddr: KERNEL_CMD_LINE_START,
            rsdp_paddr: EBDA_START,
            ..Default::default()
        },
        ..Default::default()
    };

    // load cmd line
    if let Some(cmd_line) = cmd_line {
        if cmd_line.len() as u64 > KERNEL_CMD_LINE_LIMIT {
            return error::CmdLineTooLong {
                len: cmd_line.len(),
                limit: KERNEL_CMD_LINE_LIMIT,
            }
            .fail();
        }
        memory.write_range(
            KERNEL_CMD_LINE_START,
            cmd_line.len() as u64,
            cmd_line.as_bytes(),
        )?;
        start_info_page.start_info.cmdline_paddr = KERNEL_CMD_LINE_START;
    }

    // load initramfs
    let initramfs_range;
    if let Some(initramfs) = initramfs {
        let access_initramfs = error::AccessFile {
            path: initramfs.as_ref(),
        };
        let initramfs = File::open(&initramfs).context(access_initramfs)?;
        let initramfs_size = initramfs.metadata().context(access_initramfs)?.len();
        let initramfs_gpa = search_initramfs_address(mem_regions, initramfs_size, 2 << 30)?;
        let initramfs_end = initramfs_gpa + initramfs_size;
        memory.write_range(initramfs_gpa, initramfs_size, initramfs)?;
        start_info_page.start_info.nr_modules = 1;
        start_info_page.start_info.modlist_paddr =
            HVM_START_INFO_START + offset_of!(StartInfoPage, initramfs) as u64;
        start_info_page.initramfs.paddr = initramfs_gpa as u64;
        start_info_page.initramfs.size = initramfs_size;
        log::info!(
            "initramfs loaded at {:#x} - {:#x}, ",
            initramfs_gpa,
            initramfs_end - 1
        );
        initramfs_range = Some(initramfs_gpa..initramfs_end);
    } else {
        initramfs_range = None;
    }

    // setup memory mapping table
    let mut index = 0;
    for (addr, region) in mem_regions.iter() {
        let type_ = match region.type_ {
            MemRegionType::Ram => XEN_HVM_MEMMAP_TYPE_RAM,
            MemRegionType::Reserved => XEN_HVM_MEMMAP_TYPE_RESERVED,
            MemRegionType::Acpi => XEN_HVM_MEMMAP_TYPE_ACPI,
            MemRegionType::Pmem => XEN_HVM_MEMMAP_TYPE_PMEM,
            MemRegionType::Hidden => continue,
        };
        start_info_page.memory_map[index] = HvmMemmapTableEntry {
            addr: *addr,
            size: region.size,
            type_,
            reserved: 0,
        };
        index += 1;
    }
    start_info_page.start_info.memmap_entries = index as u32;
    start_info_page.start_info.memmap_paddr =
        HVM_START_INFO_START + offset_of!(StartInfoPage, memory_map) as u64;

    memory.write(HVM_START_INFO_START, &start_info_page)?;

    // set up gdt
    let boot_cs = SegRegVal {
        selector: 0x10,
        base: 0,
        limit: 0xfff_ffff,
        access: SegAccess(0xc09b),
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
        limit: 0x67,
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
        base: BOOT_GDT_START,
        limit: size_of_val(&gdt) as u16 - 1,
    };
    memory.write(BOOT_GDT_START, &gdt)?;

    let idtr = DtRegVal { base: 0, limit: 0 };

    Ok(InitState {
        regs: vec![
            (Reg::Rbx, HVM_START_INFO_START),
            (Reg::Rflags, Rflags::RESERVED_1.bits() as u64),
            (Reg::Rip, entry_point),
        ],
        sregs: vec![
            (SReg::Cr0, Cr0::PE.bits() as u64),
            (SReg::Cr4, 0),
            (SReg::Efer, 0),
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
