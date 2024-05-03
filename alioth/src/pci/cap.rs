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

use std::fmt::Debug;

use bitfield::bitfield;

use crate::mem;
use crate::mem::addressable::SlotBackend;
use crate::mem::emulated::{Mmio, MmioBus};

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PciCapId {
    Msi = 0x05,
    Vendor = 0x09,
    Msix = 0x11,
}

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct PciCapHdr {
    pub id: u8,
    pub next: u8,
}

bitfield! {
    #[derive(Copy, Clone, Default)]
    #[repr(C)]
    pub struct PcieExtCapHdr(u32);
    impl Debug;
    pub next, _: 31,20;
    pub version, _: 19,16;
    pub id, _: 15,0;
}

bitfield! {
    #[derive(Copy, Clone, Default)]
    #[repr(C)]
    pub struct MsixMsgCtrl(u16);
    impl Debug;
    pub table_len, _ : 10, 0;
    pub masked, set_masked: 14;
    pub enabled, set_enabled: 15;
}

impl MsixMsgCtrl {
    pub fn new(len: u16) -> Self {
        assert_ne!(len, 1);
        MsixMsgCtrl(len - 1)
    }
}

bitfield! {
    #[derive(Copy, Clone, Default)]
    #[repr(C)]
    pub struct MsixCapOffset(u32);
    impl Debug;
    pub bar, set_bar: 2, 0;
}

impl MsixCapOffset {
    pub fn offset(&self) -> u32 {
        self.0 & !0b111
    }

    pub fn set_offset(&mut self, val: u32) {
        self.0 = (val & !0b111) | self.bar()
    }
}

#[derive(Debug, Default, Clone)]
#[repr(C)]
pub struct MsixCap {
    pub header: PciCapHdr,
    pub control: MsixMsgCtrl,
    pub table_offset: MsixCapOffset,
    pub pba_offset: MsixCapOffset,
}

bitfield! {
    #[derive(Copy, Clone, Default)]
    #[repr(C)]
    pub struct MsixVectorCtrl(u32);
    impl Debug;
    pub masked, set_masked: 0;
}

#[derive(Debug, Clone)]
pub struct MsixTableEntry {
    pub addr_lo: u32,
    pub addr_hi: u32,
    pub data: u32,
    pub control: MsixVectorCtrl,
}

impl Default for MsixTableEntry {
    fn default() -> Self {
        MsixTableEntry {
            addr_lo: 0,
            addr_hi: 0,
            data: 0,
            control: MsixVectorCtrl(1),
        }
    }
}

pub trait PciCap: Mmio {
    fn set_next(&mut self, val: u8);
}

impl SlotBackend for Box<dyn PciCap> {
    fn size(&self) -> usize {
        Mmio::size(self.as_ref())
    }
}

impl Mmio for Box<dyn PciCap> {
    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        Mmio::read(self.as_ref(), offset, size)
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        Mmio::write(self.as_ref(), offset, size, val)
    }

    fn size(&self) -> usize {
        Mmio::size(self.as_ref())
    }
}

#[derive(Debug)]
pub struct PciCapList {
    inner: MmioBus<Box<dyn PciCap>>,
}

impl Default for PciCapList {
    fn default() -> Self {
        Self::new()
    }
}

impl PciCapList {
    pub fn new() -> PciCapList {
        Self {
            inner: MmioBus::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Mmio for PciCapList {
    fn read(&self, offset: usize, size: u8) -> Result<u64, mem::Error> {
        self.inner.read(offset, size)
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> Result<(), mem::Error> {
        self.inner.write(offset, size, val)
    }

    fn size(&self) -> usize {
        4096
    }
}
