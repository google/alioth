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

use std::ops::Range;
use std::path::PathBuf;

use thiserror::Error;

#[cfg(target_arch = "x86_64")]
use crate::arch::reg::{DtReg, DtRegVal, SegReg, SegRegVal};
use crate::arch::reg::{Reg, SReg};
use crate::mem::{MemRegionEntry, MemRegionType};

pub mod elf;
#[path = "firmware/firmware.rs"]
pub mod firmware;
#[path = "linux/linux.rs"]
pub mod linux;
#[cfg(target_arch = "x86_64")]
#[path = "xen/xen.rs"]
pub mod xen;

#[derive(Debug)]
pub struct Payload {
    pub executable: PathBuf,
    pub exec_type: ExecType,
    pub initramfs: Option<PathBuf>,
    pub cmd_line: Option<String>,
}

#[derive(Debug)]
pub enum ExecType {
    Linux,
    #[cfg(target_arch = "x86_64")]
    Pvh,
    Firmware,
}

#[derive(Debug, Clone, Default)]
pub struct InitState {
    pub regs: Vec<(Reg, u64)>,
    pub sregs: Vec<(SReg, u64)>,
    #[cfg(target_arch = "x86_64")]
    pub dt_regs: Vec<(DtReg, DtRegVal)>,
    #[cfg(target_arch = "x86_64")]
    pub seg_regs: Vec<(SegReg, SegRegVal)>,
    pub initramfs: Option<Range<u64>>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("mem: {0}")]
    Mem(#[from] crate::mem::Error),

    #[error("msssing magic number {magic:#x}, found {found:#x}")]
    MissingMagic { magic: u64, found: u64 },

    #[error("cannot find entry point")]
    NoEntryPoint,

    #[error("not a 64bit kernel")]
    Not64BitKernel,

    #[error("not a relocatable kernel")]
    NotRelocatableKernel,

    #[error("kernel command line too long, length: {0}, limit: {1}")]
    CmdLineTooLong(usize, u64),

    #[error("cannot load initramfs at {addr:#x} - {max:#x}, initramfs max address: {addr_max:#x}")]
    InitramfsAddrLimit {
        addr: usize,
        max: usize,
        addr_max: usize,
    },

    #[error("cannot find a memory region to load initramfs")]
    CannotLoadInitramfs,

    #[error("{name} too old, minimum supported version {min:#x}, found version {found:#x}")]
    TooOld {
        name: &'static str,
        min: u64,
        found: u64,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub fn search_initramfs_address(
    entries: &[(u64, MemRegionEntry)],
    size: u64,
    addr_max: u64,
) -> Result<u64, Error> {
    for (start, entry) in entries.iter().rev() {
        let region_max = entry.size - 1 + start;
        let limit = std::cmp::min(region_max, addr_max);
        if limit < size - 1 {
            continue;
        }
        let load_addr = (limit - (size - 1)) & !0xfff;
        if entry.type_ == MemRegionType::Ram && load_addr >= *start {
            return Ok(load_addr);
        }
    }
    Err(Error::CannotLoadInitramfs)
}
