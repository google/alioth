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

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::mem::{offset_of, size_of, size_of_val};
use std::path::Path;

use zerocopy::{AsBytes, FromZeroes};

use crate::align_up;
use crate::arch::layout::{
    BOOT_GDT_START, EBDA_START, HVM_START_INFO_START, KERNEL_CMD_LINE_LIMIT, KERNEL_CMD_LINE_START,
};
use crate::arch::reg::{Cr0, Rflags, SegAccess};
use crate::hv::arch::{DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use crate::loader::elf::{
    ELF_HEADER_MAGIC, ELF_IDENT_CLASS_64, ELF_IDENT_LITTLE_ENDIAN, Elf64Header, Elf64Note,
    Elf64ProgramHeader, Elf64SectionHeader, PT_NOTE, SHT_NOTE,
};
use crate::loader::xen::start_info::{
    XEN_HVM_MEMMAP_TYPE_ACPI, XEN_HVM_MEMMAP_TYPE_PMEM, XEN_HVM_MEMMAP_TYPE_RAM,
    XEN_HVM_MEMMAP_TYPE_RESERVED, XEN_HVM_START_INFO_V1, XEN_HVM_START_MAGIC_VALUE,
};
use crate::loader::{Error, InitState, Result, search_initramfs_address};
use crate::mem::Memory;
use crate::mem::{MemRegionEntry, MemRegionType};

pub mod start_info;

use start_info::{HvmMemmapTableEntry, HvmModlistEntry, HvmStartInfo};

pub const XEN_ELFNOTE_PHYS32_ENTRY: u32 = 18;

#[repr(C)]
#[derive(Debug, AsBytes, Default)]
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
) -> Result<Option<u64>> {
    let mut pos = 0;
    while pos < size {
        file.seek(SeekFrom::Start(offset + pos))?;
        let mut header = Elf64Note::new_zeroed();
        file.read_exact(header.as_bytes_mut())?;
        pos += size_of::<Elf64Note>() as u64;
        pos += align_up!(header.desc_sz as u64, align);
        pos += align_up!(header.name_sz as u64, align);
        if header.type_ != XEN_ELFNOTE_PHYS32_ENTRY {
            continue;
        }
        let name_sz_aligned = align_up!(header.name_sz as u64, align) as usize;
        let mut name = vec![0u8; name_sz_aligned];
        file.read_exact(&mut name)?;
        let name_str = std::str::from_utf8(&name)
            .unwrap_or("")
            .trim_matches('\0')
            .trim();
        if name_str != "Xen" {
            continue;
        }
        match header.desc_sz {
            4 => {
                let mut entry_point = 0u32;
                file.read_exact(entry_point.as_bytes_mut())?;
                return Ok(Some(entry_point as u64));
            }
            8 => {
                let mut entry_point = 0u64;
                file.read_exact(entry_point.as_bytes_mut())?;
                return Ok(Some(entry_point));
            }
            _ => {}
        }
    }

    Ok(None)
}

// https://xenbits.xen.org/docs/4.18-testing/misc/pvh.html
pub fn find_pvh_entry_point<P: AsRef<Path>>(kernel: P) -> Result<u64> {
    let mut kernel_file = BufReader::new(
        File::open(&kernel).map_err(|source| Error::KernelOpen {
            path: kernel.as_ref().to_path_buf(),
            source,
        })?,
    );

    let mut elf_header = Elf64Header::new_zeroed();
    kernel_file.read_exact(elf_header.as_bytes_mut())?;
    if elf_header.ident_magic != ELF_HEADER_MAGIC {
        return Err(Error::MissingMagic {
            magic: u32::from_ne_bytes(ELF_HEADER_MAGIC) as u64,
            found: u32::from_ne_bytes(elf_header.ident_magic) as u64,
        });
    }
    if elf_header.ident_class != ELF_IDENT_CLASS_64 {
        return Err(Error::Not64BitKernel);
    }
    if elf_header.ident_data != ELF_IDENT_LITTLE_ENDIAN {
        return Err(Error::NoEntryPoint);
    }

    let mut pvh_entry = None;

    kernel_file.seek(SeekFrom::Start(elf_header.ph_off))?;
    let mut program_header = Elf64ProgramHeader::new_vec_zeroed(elf_header.ph_num as usize);
    kernel_file.read_exact(program_header.as_bytes_mut())?;
    for program_header in program_header.iter() {
        if program_header.type_ == PT_NOTE && pvh_entry.is_none() {
            pvh_entry = search_pvh_note(
                &mut kernel_file,
                program_header.offset,
                program_header.file_sz,
                program_header.align,
            )?;
        }
    }

    if pvh_entry.is_none() && elf_header.sh_num > 0 {
        kernel_file.seek(SeekFrom::Start(elf_header.sh_off))?;
        let mut sections = Elf64SectionHeader::new_vec_zeroed(elf_header.sh_num as usize);
        kernel_file.read_exact(sections.as_bytes_mut())?;
        for section in sections.iter() {
            if section.type_ != SHT_NOTE {
                continue;
            }
            pvh_entry = search_pvh_note(
                &mut kernel_file,
                section.offset,
                section.size,
                section.addr_align,
            )?;
            if pvh_entry.is_some() {
                break;
            }
        }
    }

    pvh_entry.ok_or(Error::NoEntryPoint)
}

pub fn check_pvh_note<P: AsRef<Path>>(kernel: P) -> Result<()> {
    find_pvh_entry_point(kernel).map(|_| ())
}

pub fn load<P: AsRef<Path>>(
    memory: &Memory,
    mem_regions: &[(usize, MemRegionEntry)],
    kernel: P,
    cmd_line: Option<&str>,
    initramfs: Option<P>,
) -> Result<InitState> {
    let entry_point = find_pvh_entry_point(&kernel)?;

    let mut kernel_file = BufReader::new(
        File::open(&kernel).map_err(|source| Error::KernelOpen {
            path: kernel.as_ref().to_path_buf(),
            source,
        })?,
    );

    let mut elf_header = Elf64Header::new_zeroed();
    kernel_file.read_exact(elf_header.as_bytes_mut())?;
    kernel_file.seek(SeekFrom::Start(elf_header.ph_off))?;
    let mut program_header = Elf64ProgramHeader::new_vec_zeroed(elf_header.ph_num as usize);
    kernel_file.read_exact(program_header.as_bytes_mut())?;
    for program_header in program_header.iter() {
        if program_header.file_sz > 0 {
            let addr = program_header.paddr as usize;
            let size = program_header.file_sz as usize;
            kernel_file.seek(SeekFrom::Start(program_header.offset))?;
            memory.write_range(addr, size, &mut kernel_file)?;
            log::info!("loaded at {:#x?}-{:#x?}", addr, addr + size);
        }
    }

    log::info!("PVH entry = {entry_point:#x?}");

    let mut in_ram = false;
    for (start, entry) in memory.mem_region_entries() {
        if entry.type_ == MemRegionType::Ram
            && (entry_point as usize) >= start
            && (entry_point as usize) < start + entry.size
        {
            in_ram = true;
            break;
        }
    }
    if !in_ram {
        return Err(Error::InvalidEntryPoint(entry_point));
    }

    let mut start_info_page = StartInfoPage {
        start_info: HvmStartInfo {
            magic: XEN_HVM_START_MAGIC_VALUE,
            version: XEN_HVM_START_INFO_V1,
            cmdline_paddr: KERNEL_CMD_LINE_START as u64,
            rsdp_paddr: EBDA_START as u64,
            ..Default::default()
        },
        ..Default::default()
    };

    // load cmd line
    if let Some(cmd_line) = cmd_line {
        if cmd_line.len() > KERNEL_CMD_LINE_LIMIT {
            return Err(Error::CmdLineTooLong(cmd_line.len(), KERNEL_CMD_LINE_LIMIT));
        }
        memory.write_range(KERNEL_CMD_LINE_START, cmd_line.len(), cmd_line.as_bytes())?;
        start_info_page.start_info.cmdline_paddr = KERNEL_CMD_LINE_START as u64;
    }

    // load initramfs
    let initramfs_range;
    if let Some(initramfs) = initramfs {
        let initramfs = File::open(&initramfs).map_err(|source| Error::InitramfsOpen {
            path: initramfs.as_ref().to_path_buf(),
            source,
        })?;
        let initramfs_size = initramfs.metadata()?.len() as usize;
        let initramfs_gpa = search_initramfs_address(mem_regions, initramfs_size, 2 << 30)?;
        let initramfs_end = initramfs_gpa + initramfs_size;
        memory.write_range(initramfs_gpa, initramfs_size, initramfs)?;
        start_info_page.start_info.nr_modules = 1;
        start_info_page.start_info.modlist_paddr =
            (HVM_START_INFO_START + offset_of!(StartInfoPage, initramfs)) as u64;
        start_info_page.initramfs.paddr = initramfs_gpa as u64;
        start_info_page.initramfs.size = initramfs_size as u64;
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
            addr: *addr as u64,
            size: region.size as u64,
            type_,
            reserved: 0,
        };
        index += 1;
    }
    start_info_page.start_info.memmap_entries = index as u32;
    start_info_page.start_info.memmap_paddr =
        (HVM_START_INFO_START + offset_of!(StartInfoPage, memory_map)) as u64;

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
        base: BOOT_GDT_START as u64,
        limit: size_of_val(&gdt) as u16 - 1,
    };
    memory.write(BOOT_GDT_START, &gdt)?;

    let idtr = DtRegVal { base: 0, limit: 0 };

    Ok(InitState {
        regs: vec![
            (Reg::Rbx, HVM_START_INFO_START as u64),
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

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Write;
    use zerocopy::AsBytes;
    use crate::loader::elf::{
        ELF_HEADER_MAGIC, ELF_IDENT_CLASS_64, ELF_IDENT_LITTLE_ENDIAN, Elf64Header, Elf64Note,
        Elf64ProgramHeader, PT_NOTE,
    };
    use super::{check_pvh_note, XEN_ELFNOTE_PHYS32_ENTRY};

    #[test]
    fn test_check_pvh_note_valid() {
        let temp_file = std::env::temp_dir().join("test_pvh_valid.elf");
        let mut file = File::create(&temp_file).unwrap();

        let mut header = Elf64Header::default();
        header.ident_magic = ELF_HEADER_MAGIC;
        header.ident_class = ELF_IDENT_CLASS_64;
        header.ident_data = ELF_IDENT_LITTLE_ENDIAN;
        header.ph_num = 1;
        header.ph_off = std::mem::size_of::<Elf64Header>() as u64;

        let note_header = Elf64Note {
            name_sz: 4,
            desc_sz: 8,
            type_: XEN_ELFNOTE_PHYS32_ENTRY,
        };
        let name = b"Xen\0";
        let entry_point: u64 = 0x100000;

        let mut ph = Elf64ProgramHeader::default();
        ph.type_ = PT_NOTE;
        ph.offset = header.ph_off + std::mem::size_of::<Elf64ProgramHeader>() as u64;
        ph.file_sz = (std::mem::size_of::<Elf64Note>() + 4 + 8) as u64;
        ph.align = 4;

        file.write_all(header.as_bytes()).unwrap();
        file.write_all(ph.as_bytes()).unwrap();
        file.write_all(note_header.as_bytes()).unwrap();
        file.write_all(name).unwrap();
        file.write_all(entry_point.as_bytes()).unwrap();
        file.flush().unwrap();

        assert!(check_pvh_note(&temp_file).is_ok());
        let _ = std::fs::remove_file(temp_file);
    }

    #[test]
    fn test_check_pvh_note_missing() {
        let temp_file = std::env::temp_dir().join("test_pvh_missing.elf");
        let mut file = File::create(&temp_file).unwrap();

        let mut header = Elf64Header::default();
        header.ident_magic = ELF_HEADER_MAGIC;
        header.ident_class = ELF_IDENT_CLASS_64;
        header.ident_data = ELF_IDENT_LITTLE_ENDIAN;
        header.ph_num = 0;

        file.write_all(header.as_bytes()).unwrap();
        file.flush().unwrap();

        assert!(check_pvh_note(&temp_file).is_err());
        let _ = std::fs::remove_file(temp_file);
    }
}
