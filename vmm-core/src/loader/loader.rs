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

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{self, Display, Formatter};
use core::ops::Range;

use crate::host::arch::{DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use crate::host::{HvError, HvResult, PayloadKind, VmmCoreBridge};
use crate::mem::mapped::ByteRead;
use crate::mem::{MemRegionEntry, MemRegionType};

pub mod elf;
pub mod linux;
pub mod xen;

#[derive(Debug, Clone)]
pub struct Payload {
    pub exec_type: ExecType,
    pub kernel_size: u64,
    pub initramfs_size: Option<u64>,
    pub cmd_line: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecType {
    Linux,
    Pvh,
}

pub struct PayloadReader<'a> {
    bridge: &'a dyn VmmCoreBridge,
    kind: PayloadKind,
    size: u64,
    pos: u64,
}

impl<'a> PayloadReader<'a> {
    pub fn new(bridge: &'a dyn VmmCoreBridge, kind: PayloadKind, size: u64) -> Self {
        Self {
            bridge,
            kind,
            size,
            pos: 0,
        }
    }

    pub fn size(&self) -> u64 {
        self.size
    }

    pub fn seek_to(&mut self, offset: u64) {
        self.pos = offset;
    }

    pub fn skip(&mut self, delta: u64) {
        self.pos = self.pos.saturating_add(delta);
    }
}

impl ByteRead for PayloadReader<'_> {
    fn read_bytes(&mut self, buf: &mut [u8]) -> HvResult<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let max_len = core::cmp::min(buf.len() as u64, self.size - self.pos) as usize;
        let n = self
            .bridge
            .read_payload(self.kind, self.pos, &mut buf[..max_len])?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[derive(Debug, Clone, Default)]
pub struct InitState {
    pub regs: Vec<(Reg, u64)>,
    pub sregs: Vec<(SReg, u64)>,
    pub dt_regs: Vec<(DtReg, DtRegVal)>,
    pub seg_regs: Vec<(SegReg, SegRegVal)>,
    pub initramfs: Option<Range<u64>>,
}

#[derive(Debug)]
pub enum Error {
    Hv(HvError),
    Mem(crate::mem::Error),
    MissingMagic {
        magic: u64,
        found: u64,
    },
    NoEntryPoint,
    Not64BitKernel,
    NotRelocatableKernel,
    CmdLineTooLong(usize, usize),
    InitramfsAddrLimit {
        addr: u64,
        max: u64,
        addr_max: u64,
    },
    CannotLoadInitramfs,
    TooOld {
        name: &'static str,
        min: u64,
        found: u64,
    },
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hv(e) => write!(f, "hv: {e}"),
            Self::Mem(e) => write!(f, "mem: {e}"),
            Self::MissingMagic { magic, found } => {
                write!(f, "missing magic number {magic:#x}, found {found:#x}")
            }
            Self::NoEntryPoint => f.write_str("cannot find entry point"),
            Self::Not64BitKernel => f.write_str("not a 64bit kernel"),
            Self::NotRelocatableKernel => f.write_str("not a relocatable kernel"),
            Self::CmdLineTooLong(len, limit) => {
                write!(
                    f,
                    "kernel command line too long, length: {len}, limit: {limit}"
                )
            }
            Self::InitramfsAddrLimit {
                addr,
                max,
                addr_max,
            } => write!(
                f,
                "cannot load initramfs at {addr:#x} - {max:#x}, initramfs max address: {addr_max:#x}"
            ),
            Self::CannotLoadInitramfs => f.write_str("cannot find a memory region to load initramfs"),
            Self::TooOld { name, min, found } => write!(
                f,
                "{name} too old, minimum supported version {min:#x}, found version {found:#x}"
            ),
        }
    }
}

impl core::error::Error for Error {}

impl From<HvError> for Error {
    fn from(e: HvError) -> Self {
        Self::Hv(e)
    }
}

impl From<crate::mem::Error> for Error {
    fn from(e: crate::mem::Error) -> Self {
        Self::Mem(e)
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

pub fn search_initramfs_address(
    entries: &[(u64, MemRegionEntry)],
    size: u64,
    addr_max: u64,
) -> Result<u64, Error> {
    for (start, entry) in entries.iter().rev() {
        let region_max = entry.size as u64 - 1 + start;
        let limit = core::cmp::min(region_max, addr_max);
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
