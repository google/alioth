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
use std::path::Path;

use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::arch::layout::{DEVICE_TREE_START, KERNEL_IMAGE_START};
use crate::arch::reg::{Pstate, Reg};
use crate::loader::{search_initramfs_address, Error, InitState, Result};
use crate::mem::mapped::RamBus;
use crate::mem::MemRegionEntry;

#[repr(C)]
#[derive(Debug, FromBytes, FromZeroes, AsBytes)]
struct ImageHeader {
    code0: u32,
    code1: u32,
    text_offset: u64,
    image_size: u64,
    flags: u64,
    res2: u64,
    res3: u64,
    res4: u64,
    magic: u32,
    res5: u32,
}

const IMAGE_MAGIC: u32 = 0x644d5241;

pub fn load<P: AsRef<Path>>(
    memory: &RamBus,
    mem_regions: &[(u64, MemRegionEntry)],
    kernel: P,
    _cmd_line: Option<&str>,
    initramfs: Option<P>,
) -> Result<InitState> {
    let kernel_file = File::open(kernel)?;
    let kernel_meta = kernel_file.metadata()?;
    let mut kernel = BufReader::new(kernel_file);
    let mut header = ImageHeader::new_zeroed();
    kernel.read_exact(header.as_bytes_mut())?;
    if header.magic != IMAGE_MAGIC {
        return Err(Error::MissingMagic {
            magic: IMAGE_MAGIC as u64,
            found: header.magic as u64,
        });
    }
    if header.image_size == 0 {
        header.text_offset = 0x80000;
    }
    kernel.seek(SeekFrom::Start(0))?;
    let kernel_image_start = KERNEL_IMAGE_START + header.text_offset;
    memory.write_range(kernel_image_start, kernel_meta.len(), kernel)?;
    let kernel_image_end = KERNEL_IMAGE_START + header.text_offset + kernel_meta.len();
    log::info!(
        "kernel loaded at {kernel_image_start:#x} - {:#x}",
        kernel_image_end - 1
    );

    let initramfs_range;
    if let Some(initramfs) = initramfs {
        let initramfs = File::open(initramfs)?;
        let initramfs_size = initramfs.metadata()?.len();
        let initramfs_gpa =
            search_initramfs_address(mem_regions, initramfs_size, KERNEL_IMAGE_START + (1 << 30))?;
        if initramfs_gpa < kernel_image_end {
            return Err(Error::CannotLoadInitramfs);
        }
        let initramfs_end = initramfs_gpa + initramfs_size;
        memory.write_range(initramfs_gpa, initramfs_size, initramfs)?;
        log::info!(
            "initramfs loaded at {initramfs_gpa:#x} - {:#x}",
            initramfs_end - 1,
        );
        initramfs_range = Some(initramfs_gpa..initramfs_end);
    } else {
        initramfs_range = None;
    }
    let init_state = InitState {
        regs: vec![
            (Reg::X0, DEVICE_TREE_START),
            (Reg::X1, 0),
            (Reg::X2, 0),
            (Reg::X3, 0),
            (
                Reg::Pstate,
                (Pstate::D | Pstate::A | Pstate::I | Pstate::F | Pstate::EL_H | Pstate::EL_BIT2)
                    .bits() as u64,
            ),
            (Reg::Pc, kernel_image_start),
        ],
        initramfs: initramfs_range,
        ..Default::default()
    };
    Ok(init_state)
}
