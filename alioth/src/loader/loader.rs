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

pub mod elf;
#[path = "firmware/firmware.rs"]
pub mod firmware;
#[path = "linux/linux.rs"]
pub mod linux;
#[cfg(target_arch = "x86_64")]
#[path = "xen/xen.rs"]
pub mod xen;

use std::ffi::CString;
use std::ops::Range;
use std::path::Path;

use serde::Deserialize;
use snafu::Snafu;

#[cfg(target_arch = "x86_64")]
use crate::arch::reg::{DtReg, DtRegVal, SegReg, SegRegVal};
use crate::arch::reg::{Reg, SReg};
use crate::errors::{DebugTrace, trace_error};
use crate::mem::{MemRegionEntry, MemRegionType};

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
pub struct Payload {
    pub firmware: Option<Box<Path>>,
    pub executable: Option<Executable>,
    pub initramfs: Option<Box<Path>>,
    pub cmdline: Option<CString>,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
pub enum Executable {
    Linux(Box<Path>),
    #[cfg(target_arch = "x86_64")]
    Pvh(Box<Path>),
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

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Cannot access file {path:?}"))]
    AccessFile {
        path: Box<Path>,
        error: std::io::Error,
    },
    #[snafu(display("Firmware image size is not 4-KiB aligned"))]
    SizeNotAligned { size: u64 },
    #[snafu(display("Failed to add a guest memory slot"))]
    AddMemSlot { source: Box<crate::mem::Error> },
    #[snafu(display("Failed to access guest memory"), context(false))]
    RwMemory { source: Box<crate::mem::Error> },
    #[snafu(display("Missing magic number {magic:#x}, found {found:#x}"))]
    MissingMagic { magic: u64, found: u64 },
    #[snafu(display("Cannot find payload entry point"))]
    NoEntryPoint,
    #[snafu(display("Not a 64-bit kernel"))]
    Not64Bit,
    #[snafu(display("Not a relocatable kernel"))]
    NotRelocatable,
    #[snafu(display("Kernel command line too long, length: {len}, limit: {limit}"))]
    CmdLineTooLong { len: usize, limit: u64 },
    #[snafu(display("Cannot find a memory region to load initramfs"))]
    CannotLoadInitramfs,
    #[snafu(display(
        "{name} is too old, minimum supported version {min:#x}, found version {found:#x}"
    ))]
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
    error::CannotLoadInitramfs.fail()
}
