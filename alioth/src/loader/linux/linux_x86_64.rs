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

use std::ffi::CStr;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::mem::{size_of, size_of_val};
use std::path::Path;

use snafu::ResultExt;
use zerocopy::{FromZeros, IntoBytes};

use crate::arch::layout::{
    BOOT_GDT_START, BOOT_PAGING_START, EBDA_START, KERNEL_CMDLINE_LIMIT, KERNEL_CMDLINE_START,
    KERNEL_IMAGE_START, LINUX_BOOT_PARAMS_START,
};
use crate::arch::msr::Efer;
use crate::arch::paging::Entry;
use crate::arch::reg::{
    Cr0, Cr4, DtReg, DtRegVal, Reg, Rflags, SReg, SegAccess, SegReg, SegRegVal,
};
use crate::mem::mapped::RamBus;
use crate::mem::{MemRegionEntry, MemRegionType};

use crate::loader::linux::bootparams::{
    BootE820Entry, BootParams, E820_ACPI, E820_PMEM, E820_RAM, E820_RESERVED, MAGIC_AA55,
    MAGIC_HDRS, SETUP_HEADER_OFFSET, XLoadFlags,
};
use crate::loader::{Error, InitState, error, search_initramfs_address};

// loading bzImage and ramdisk above 4G in 64bit.
const MINIMAL_VERSION: u16 = 0x020c;

pub fn load<P: AsRef<Path>>(
    memory: &RamBus,
    mem_regions: &[(u64, MemRegionEntry)],
    kernel: P,
    cmdline: Option<&CStr>,
    initramfs: Option<P>,
) -> Result<InitState, Error> {
    let mut boot_params = BootParams::new_zeroed();
    let access_kernel = error::AccessFile {
        path: kernel.as_ref(),
    };
    let kernel = File::open(&kernel).context(access_kernel)?;
    let kernel_meta = kernel.metadata().context(access_kernel)?;
    let mut kernel = BufReader::new(kernel);

    kernel
        .seek(SeekFrom::Start(SETUP_HEADER_OFFSET))
        .context(access_kernel)?;
    kernel
        .read_exact(boot_params.hdr.as_mut_bytes())
        .context(access_kernel)?;

    // For backwards compatibility, if the setup_sects field contains 0,
    // the real value is 4.
    if boot_params.hdr.setup_sects == 0 {
        boot_params.hdr.setup_sects = 4;
    }

    if boot_params.hdr.boot_flag != MAGIC_AA55 {
        return error::MissingMagic {
            magic: MAGIC_AA55 as u64,
            found: boot_params.hdr.boot_flag as u64,
        }
        .fail();
    }
    if boot_params.hdr.header != MAGIC_HDRS {
        return error::MissingMagic {
            magic: MAGIC_HDRS as u64,
            found: boot_params.hdr.header as u64,
        }
        .fail();
    }
    if boot_params.hdr.version < MINIMAL_VERSION {
        return error::TooOld {
            name: "bzimage",
            min: MINIMAL_VERSION as u64,
            found: boot_params.hdr.version as u64,
        }
        .fail();
    }
    if !XLoadFlags::from_bits_retain(boot_params.hdr.xloadflags).contains(XLoadFlags::XLF_KERNEL_64)
    {
        return error::Not64Bit.fail();
    }
    if boot_params.hdr.relocatable_kernel == 0 {
        return error::NotRelocatable.fail();
    }

    boot_params.hdr.type_of_loader = 0xff;

    // load cmd line
    if let Some(cmdline) = cmdline {
        let cmdline = cmdline.to_bytes_with_nul();
        let cmdline_limit =
            std::cmp::min(boot_params.hdr.cmdline_size as u64, KERNEL_CMDLINE_LIMIT);
        if cmdline.len() as u64 > cmdline_limit {
            return error::CmdLineTooLong {
                len: cmdline.len(),
                limit: cmdline_limit,
            }
            .fail();
        }
        memory.write_range(KERNEL_CMDLINE_START, cmdline.len() as u64, cmdline)?;
        boot_params.hdr.cmdline_ptr = KERNEL_CMDLINE_START as u32;
        boot_params.ext_cmdline_ptr = (KERNEL_CMDLINE_START >> 32) as u32;
    }

    // load kernel image
    let kernel_offset = (boot_params.hdr.setup_sects as u64 + 1) * 512;
    kernel
        .seek(SeekFrom::Start(kernel_offset))
        .context(access_kernel)?;
    let kernel_size = kernel_meta.len() - kernel_offset;
    memory.write_range(KERNEL_IMAGE_START, kernel_size, kernel)?;

    // load initramfs
    let initramfs_range;
    if let Some(initramfs) = initramfs {
        let access_initramfs = error::AccessFile {
            path: initramfs.as_ref(),
        };
        let initramfs = File::open(&initramfs).context(access_initramfs)?;
        let initramfs_size = initramfs.metadata().context(access_initramfs)?.len();
        let initramfs_gpa = search_initramfs_address(
            mem_regions,
            initramfs_size,
            boot_params.hdr.initrd_addr_max as u64,
        )?;
        let initramfs_end = initramfs_gpa + initramfs_size;
        memory.write_range(initramfs_gpa, initramfs_size, initramfs)?;
        boot_params.hdr.ramdisk_image = initramfs_gpa as u32;
        boot_params.ext_ramdisk_image = (initramfs_gpa >> 32) as u32;
        boot_params.hdr.ramdisk_size = initramfs_size as u32;
        boot_params.ext_ramdisk_size = (initramfs_size >> 32) as u32;
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
            size: region.size,
            type_,
        };
        region_index += 1;
    }
    boot_params.e820_entries = mem_regions.len() as u8;

    boot_params.acpi_rsdp_addr = EBDA_START;

    memory.write_t(LINUX_BOOT_PARAMS_START, &boot_params)?;

    // set up identity paging
    let pml4_start = BOOT_PAGING_START;
    let pdpt_start = pml4_start + 0x1000;
    let pml4e = (Entry::P | Entry::RW).bits() as u64 | pdpt_start;
    memory.write_t(pml4_start, &pml4e)?;
    let alignment = boot_params.hdr.kernel_alignment as u64;
    let runtime_start = (KERNEL_IMAGE_START + alignment - 1) & !(alignment - 1);
    let max_addr = std::cmp::max(
        runtime_start + boot_params.hdr.init_size as u64,
        std::cmp::max(
            LINUX_BOOT_PARAMS_START + size_of::<BootParams>() as u64,
            KERNEL_CMDLINE_START + KERNEL_CMDLINE_LIMIT,
        ),
    );
    let num_page = (max_addr + (1 << 30) - 1) >> 30;
    for i in 0..num_page {
        let pdpte = (i << 30) | (Entry::P | Entry::RW | Entry::PS).bits() as u64;
        memory.write_t(pdpt_start + i * size_of::<u64>() as u64, &pdpte)?;
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
        base: BOOT_GDT_START,
        limit: size_of_val(&gdt) as u16 - 1,
    };
    let idtr = DtRegVal { base: 0, limit: 0 };
    memory.write_t(BOOT_GDT_START, &gdt)?;

    Ok(InitState {
        regs: vec![
            (Reg::Rsi, LINUX_BOOT_PARAMS_START),
            (Reg::Rip, KERNEL_IMAGE_START + 0x200),
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
