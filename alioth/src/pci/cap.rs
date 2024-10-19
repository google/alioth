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
use std::mem::size_of;

use bitfield::bitfield;
use macros::Layout;
use parking_lot::{RwLock, RwLockWriteGuard};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::hv::IrqFd;
use crate::mem::addressable::SlotBackend;
use crate::mem::emulated::{Action, Mmio, MmioBus};
use crate::pci::config::DeviceHeader;
use crate::pci::Error;
use crate::{align_up, impl_mmio_for_zerocopy, mem};

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum PciCapId {
    Msi = 0x05,
    Vendor = 0x09,
    Msix = 0x11,
}

#[repr(C)]
#[derive(Debug, Default, Clone, FromBytes, Immutable, IntoBytes, KnownLayout, Layout)]
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
    #[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
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
    #[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes)]
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

#[derive(Debug, Default, Clone, FromBytes, Immutable, IntoBytes, Layout)]
#[repr(C)]
pub struct MsixCap {
    pub header: PciCapHdr,
    pub control: MsixMsgCtrl,
    pub table_offset: MsixCapOffset,
    pub pba_offset: MsixCapOffset,
}
impl_mmio_for_zerocopy!(MsixCap);

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
    fn reset(&self);
}

impl SlotBackend for Box<dyn PciCap> {
    fn size(&self) -> u64 {
        Mmio::size(self.as_ref())
    }
}

impl Mmio for Box<dyn PciCap> {
    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        Mmio::read(self.as_ref(), offset, size)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        Mmio::write(self.as_ref(), offset, size, val)
    }

    fn size(&self) -> u64 {
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

    pub fn reset(&self) {
        let inner = self.inner.inner.read();
        for (_, cap) in inner.iter() {
            cap.reset();
        }
    }
}

impl Mmio for PciCapList {
    fn read(&self, offset: u64, size: u8) -> Result<u64, mem::Error> {
        self.inner.read(offset, size)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        self.inner.write(offset, size, val)
    }

    fn size(&self) -> u64 {
        4096
    }
}

impl TryFrom<Vec<Box<dyn PciCap>>> for PciCapList {
    type Error = Error;
    fn try_from(caps: Vec<Box<dyn PciCap>>) -> Result<Self, Self::Error> {
        let bus = MmioBus::new();
        let mut ptr = size_of::<DeviceHeader>() as u64;
        let num_caps = caps.len();
        for (index, mut cap) in caps.into_iter().enumerate() {
            let next = if index == num_caps - 1 {
                0
            } else {
                align_up!(ptr + Mmio::size(&cap), 4)
            };
            cap.set_next(next as u8);
            bus.add(ptr, cap)?;
            ptr = next;
        }
        Ok(Self { inner: bus })
    }
}

#[derive(Debug)]
pub struct MsixCapMmio {
    pub cap: RwLock<MsixCap>,
}

impl Mmio for MsixCapMmio {
    fn size(&self) -> u64 {
        size_of::<MsixCap>() as u64
    }

    fn read(&self, offset: u64, size: u8) -> Result<u64, mem::Error> {
        let cap = self.cap.read();
        Mmio::read(&*cap, offset, size)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        if offset == 2 && size == 2 {
            let mut cap = self.cap.write();
            let control = MsixMsgCtrl(val as u16);
            cap.control.set_enabled(control.enabled());
            cap.control.set_masked(control.masked());
        }
        Ok(Action::None)
    }
}

impl PciCap for MsixCapMmio {
    fn set_next(&mut self, val: u8) {
        self.cap.write().header.next = val;
    }

    fn reset(&self) {
        let mut cap = self.cap.write();
        cap.control.set_enabled(false);
        cap.control.set_masked(false);
    }
}

#[derive(Debug)]
pub enum MsixTableMmioEntry<F> {
    Entry(MsixTableEntry),
    IrqFd(F),
}

macro_rules! impl_msix_table_mmio_entry_method {
    ($field:ident, $get:ident, $set:ident) => {
        pub fn $get(&self) -> u32 {
            match self {
                MsixTableMmioEntry::Entry(e) => e.$field,
                MsixTableMmioEntry::IrqFd(f) => f.$get(),
            }
        }
        fn $set(&mut self, val: u32) -> mem::Result<()> {
            match self {
                MsixTableMmioEntry::Entry(e) => e.$field = val,
                MsixTableMmioEntry::IrqFd(f) => f.$set(val)?,
            }
            Ok(())
        }
    };
}

impl<F> MsixTableMmioEntry<F>
where
    F: IrqFd,
{
    impl_msix_table_mmio_entry_method!(addr_lo, get_addr_lo, set_addr_lo);
    impl_msix_table_mmio_entry_method!(addr_hi, get_addr_hi, set_addr_hi);
    impl_msix_table_mmio_entry_method!(data, get_data, set_data);
    fn set_masked(&mut self, val: bool) -> mem::Result<bool> {
        match self {
            MsixTableMmioEntry::Entry(e) => {
                let masked = e.control.masked();
                e.control.set_masked(val);
                Ok(masked != val)
            }
            MsixTableMmioEntry::IrqFd(f) => {
                let changed = f.set_masked(val)?;
                Ok(changed)
            }
        }
    }
    pub fn get_masked(&self) -> bool {
        match self {
            MsixTableMmioEntry::Entry(e) => e.control.masked(),
            MsixTableMmioEntry::IrqFd(f) => f.get_masked(),
        }
    }
}

#[derive(Debug)]
pub struct MsixTableMmio<F> {
    pub entries: Vec<RwLock<MsixTableMmioEntry<F>>>,
}

impl<F> MsixTableMmio<F>
where
    F: IrqFd,
{
    /// Write `val` to `offset`.
    ///
    /// Returns an MSI entry if its `masked` bit gets flipped.
    pub fn write_val(
        &self,
        offset: u64,
        size: u8,
        val: u64,
    ) -> mem::Result<Option<RwLockWriteGuard<MsixTableMmioEntry<F>>>> {
        if size != 4 || offset & 0b11 != 0 {
            log::error!("unaligned access to msix table: size = {size}, offset = {offset:#x}");
            return Ok(None);
        }
        let val = val as u32;
        let index = offset as usize / size_of::<MsixTableEntry>();
        let Some(entry) = self.entries.get(index) else {
            log::error!(
                "MSI-X table size: {}, accessing index {index}",
                self.entries.len()
            );
            return Ok(None);
        };
        let mut entry = entry.write();
        let mut state_changed = false;
        match offset as usize % size_of::<MsixTableEntry>() {
            0 => entry.set_addr_lo(val)?,
            4 => entry.set_addr_hi(val)?,
            8 => entry.set_data(val)?,
            12 => state_changed = entry.set_masked(MsixVectorCtrl(val).masked())?,
            _ => unreachable!(),
        };
        if state_changed {
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    pub fn reset(&self) {
        for entry in self.entries.iter() {
            let mut entry = entry.write();
            *entry = MsixTableMmioEntry::Entry(MsixTableEntry::default());
        }
    }
}

impl<F> Mmio for MsixTableMmio<F>
where
    F: IrqFd,
{
    fn size(&self) -> u64 {
        (size_of::<MsixTableEntry>() * self.entries.len()) as u64
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        if size != 4 || offset & 0b11 != 0 {
            log::error!("unaligned access to msix table: size = {size}, offset = {offset:#x}");
            return Ok(0);
        }
        let index = offset as usize / size_of::<MsixTableEntry>();
        let Some(entry) = self.entries.get(index) else {
            log::error!(
                "MSI-X table size: {}, accessing index {index}",
                self.entries.len()
            );
            return Ok(0);
        };
        let entry = entry.read();
        let ret = match offset as usize % size_of::<MsixTableEntry>() {
            0 => entry.get_addr_lo(),
            4 => entry.get_addr_hi(),
            8 => entry.get_data(),
            12 => entry.get_masked() as _,
            _ => unreachable!(),
        };
        Ok(ret as u64)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        self.write_val(offset, size, val)?;
        Ok(Action::None)
    }
}
