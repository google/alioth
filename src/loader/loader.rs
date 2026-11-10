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

use crate::hv::arch::Reg;
use crate::hv::arch::{DtReg, DtRegVal, SReg, SegReg, SegRegVal};
use crate::mem::{MemRegionEntry, MemRegionType};

pub mod elf;

#[path = "xen/xen.rs"]
pub mod xen;

#[derive(Debug)]
pub struct Payload {
    pub executable: PathBuf,
    pub initramfs: Option<PathBuf>,
    pub cmd_line: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct InitState {
    pub regs: Vec<(Reg, u64)>,
    pub sregs: Vec<(SReg, u64)>,
    pub dt_regs: Vec<(DtReg, DtRegVal)>,
    pub seg_regs: Vec<(SegReg, SegRegVal)>,
    pub initramfs: Option<Range<usize>>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to open kernel file {path:?}: {source}")]
    KernelOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to open initramfs file {path:?}: {source}")]
    InitramfsOpen {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("mem: {0}")]
    Mem(#[from] crate::mem::Error),

    #[error("Xen/PVH loader: missing magic number {magic:#x}, found {found:#x}")]
    MissingMagic { magic: u64, found: u64 },

    #[error("the kernel does not support PVH booting (no ELF note for PVH entry point found)")]
    NoEntryPoint,

    #[error(
        "PVH entry point {0:#x} is not in mapped RAM. The kernel might not support PVH booting or is invalid."
    )]
    InvalidEntryPoint(u64),

    #[error("not a 64bit kernel")]
    Not64BitKernel,

    #[error("kernel command line too long, length: {0}, limit: {1}")]
    CmdLineTooLong(usize, usize),

    #[error("cannot find a memory region to load initramfs")]
    CannotLoadInitramfs,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub fn search_initramfs_address(
    entries: &[(usize, MemRegionEntry)],
    size: usize,
    addr_max: usize,
) -> Result<usize, Error> {
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
