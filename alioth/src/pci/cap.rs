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

use alioth_macros::Layout;
use bitfield::bitfield;
use parking_lot::RwLock;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::hv::IrqFd;
use crate::mem::addressable::SlotBackend;
use crate::mem::emulated::{Action, Mmio, MmioBus};
use crate::pci::Error;
use crate::pci::config::{DeviceHeader, PciConfigArea};
use crate::utils::truncate_u64;
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

#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct NullCap {
    pub next: u8,
    pub size: u8,
}

impl Mmio for NullCap {
    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let shift = std::cmp::min(63, offset << 3);
        let val = ((self.next as u64) << 8) >> shift;
        Ok(truncate_u64(val, size as u64))
    }

    fn write(&self, _offset: u64, _size: u8, _val: u64) -> mem::Result<Action> {
        Ok(Action::None)
    }

    fn size(&self) -> u64 {
        self.size as u64
    }
}

impl PciConfigArea for NullCap {
    fn reset(&self) {}
}

bitfield! {
    #[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
    #[repr(C)]
    pub struct MsiMsgCtrl(u16);
    impl Debug;
    pub enable, set_enable: 0;
    pub multi_msg_cap, set_multi_msg_cap: 3, 1;
    pub multi_msg, set_multi_msg: 6, 4;
    pub addr_64_cap, set_addr_64_cap: 7;
    pub per_vector_masking_cap, set_per_vector_masking_cap: 8;
    pub ext_msg_data_cap, set_ext_msg_data_cap: 9;
    pub ext_msg_data, set_ext_msg_data: 10;
}

impl MsiMsgCtrl {
    pub fn cap_size(&self) -> u8 {
        let mut size = 12;
        if self.addr_64_cap() {
            size += 4;
        }
        if self.per_vector_masking_cap() {
            size += 8;
        }
        size
    }
}

#[derive(Debug, Default, Clone, FromBytes, Immutable, IntoBytes, Layout)]
#[repr(C)]
pub struct MsiCapHdr {
    pub header: PciCapHdr,
    pub control: MsiMsgCtrl,
}
impl_mmio_for_zerocopy!(MsiCapHdr);

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

pub trait PciCap: PciConfigArea {
    fn set_next(&mut self, val: u8);
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
        for (_, cap) in self.inner.inner.iter() {
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
        let mut bus = MmioBus::new();
        let mut ptr = size_of::<DeviceHeader>() as u64;
        let num_caps = caps.len();
        for (index, mut cap) in caps.into_iter().enumerate() {
            let next = if index == num_caps - 1 {
                0
            } else {
                align_up!(ptr + Mmio::size(&cap), 2)
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

impl PciConfigArea for MsixCapMmio {
    fn reset(&self) {
        let mut cap = self.cap.write();
        cap.control.set_enabled(false);
        cap.control.set_masked(false);
    }
}

impl PciCap for MsixCapMmio {
    fn set_next(&mut self, val: u8) {
        self.cap.write().header.next = val;
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
    pub entries: RwLock<Box<[MsixTableMmioEntry<F>]>>,
}

impl<F> MsixTableMmio<F>
where
    F: IrqFd,
{
    /// Write `val` to `offset`.
    ///
    /// Returns `true` if a `masked` bit gets flipped.
    pub fn write_val(&self, offset: u64, size: u8, val: u64) -> mem::Result<bool> {
        if size != 4 || offset & 0b11 != 0 {
            log::error!("unaligned access to msix table: size = {size}, offset = {offset:#x}");
            return Ok(false);
        }
        let val = val as u32;
        let index = offset as usize / size_of::<MsixTableEntry>();
        let mut entries = self.entries.write();
        let Some(entry) = entries.get_mut(index) else {
            log::error!(
                "MSI-X table size: {}, accessing index {index}",
                entries.len()
            );
            return Ok(false);
        };
        let mut state_changed = false;
        match offset as usize % size_of::<MsixTableEntry>() {
            0 => entry.set_addr_lo(val)?,
            4 => entry.set_addr_hi(val)?,
            8 => entry.set_data(val)?,
            12 => state_changed = entry.set_masked(MsixVectorCtrl(val).masked())?,
            _ => unreachable!(),
        };
        Ok(state_changed)
    }

    pub fn reset(&self) {
        let mut entries = self.entries.write();
        for entry in entries.iter_mut() {
            *entry = MsixTableMmioEntry::Entry(MsixTableEntry::default());
        }
    }
}

impl<F> Mmio for MsixTableMmio<F>
where
    F: IrqFd,
{
    fn size(&self) -> u64 {
        (size_of::<MsixTableEntry>() * self.entries.read().len()) as u64
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        if size != 4 || offset & 0b11 != 0 {
            log::error!("unaligned access to msix table: size = {size}, offset = {offset:#x}");
            return Ok(0);
        }
        let index = offset as usize / size_of::<MsixTableEntry>();
        let entries = self.entries.read();
        let Some(entry) = entries.get(index) else {
            log::error!(
                "MSI-X table size: {}, accessing index {index}",
                entries.len()
            );
            return Ok(0);
        };
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

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;
    use rstest::rstest;

    use crate::mem::emulated::Mmio;
    use crate::pci::cap::NullCap;

    #[rstest]
    #[case(0x0, 1, 0x0)]
    #[case(0x0, 2, 0x60_00)]
    #[case(0x0, 4, 0x60_00)]
    #[case(0x1, 1, 0x60)]
    #[case(0x1, 2, 0x60)]
    #[case(0x1, 2, 0x60)]
    #[case(0x2, 1, 0x0)]
    #[case(0x2, 2, 0x0)]
    #[case(0xb, 1, 0x0)]
    fn test_null_cap(#[case] offset: u64, #[case] size: u8, #[case] val: u64) {
        let null_cap = NullCap {
            next: 0x60,
            size: 0xc,
        };
        assert_matches!(null_cap.read(offset, size), Ok(v) if v == val);
    }
}
