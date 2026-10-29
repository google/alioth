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

use std::io::{self, Read, Seek, SeekFrom};
use std::ops::Range;

use thiserror::Error;

use crate::host::arch::{DtReg, DtRegVal, Reg, SReg, SegReg, SegRegVal};
use crate::host::{PayloadKind, VmmCoreBridge};
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
}

impl Read for PayloadReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let max_len = std::cmp::min(buf.len() as u64, self.size - self.pos) as usize;
        let n = self
            .bridge
            .read_payload(self.kind, self.pos, &mut buf[..max_len])
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for PayloadReader<'_> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(offset) => offset as i128,
            SeekFrom::End(delta) => self.size as i128 + delta as i128,
            SeekFrom::Current(delta) => self.pos as i128 + delta as i128,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid seek to negative position",
            ));
        }
        self.pos = new_pos as u64;
        Ok(self.pos)
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
    CmdLineTooLong(usize, usize),

    #[error("cannot load initramfs at {addr:#x} - {max:#x}, initramfs max address: {addr_max:#x}")]
    InitramfsAddrLimit {
        addr: u64,
        max: u64,
        addr_max: u64,
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
        let region_max = entry.size as u64 - 1 + start;
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
