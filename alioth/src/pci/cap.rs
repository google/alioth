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

#[cfg(test)]
#[path = "cap_test.rs"]
mod tests;

use std::cmp::min;
use std::fmt::Debug;
use std::mem::size_of;

use alioth_macros::Layout;
use bitfield::bitfield;
use parking_lot::RwLock;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::errors::BoxTrace;
use crate::hv::{self, IrqFd};
use crate::mem::addressable::SlotBackend;
use crate::mem::emulated::{Action, Mmio, MmioBus};
use crate::pci::config::{DeviceHeader, PciConfigArea};
use crate::pci::{self, Error, Result};
use crate::utils::truncate_u64;
use crate::{align_up, c_enum, impl_mmio_for_zerocopy, mask_bits, mem};

c_enum! {
    #[derive(Default, FromBytes, Immutable, IntoBytes, KnownLayout)]
    pub struct PciCapId(u8);
    {
        MSI = 0x05;
        VENDOR = 0x09;
        MSIX = 0x11;
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, FromBytes, Immutable, IntoBytes, KnownLayout, Layout)]
pub struct PciCapHdr {
    pub id: PciCapId,
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

#[derive(Debug, Default, Clone, FromBytes, Immutable, IntoBytes, Layout)]
#[repr(C)]
struct MsiCapBody {
    data: [u32; 4],
}
impl_mmio_for_zerocopy!(MsiCapBody);

#[derive(Debug)]
pub struct MsiCapMmio<F>
where
    F: IrqFd,
{
    cap: RwLock<(MsiCapHdr, MsiCapBody)>,
    irqfds: Box<[F]>,
}

impl<F> MsiCapMmio<F>
where
    F: IrqFd,
{
    pub fn new(ctrl: MsiMsgCtrl, irqfds: Box<[F]>) -> Self {
        debug_assert_eq!(irqfds.len(), 1 << ctrl.multi_msg_cap());
        let cap = RwLock::new((
            MsiCapHdr {
                header: PciCapHdr {
                    id: PciCapId::MSI,
                    next: 0,
                },
                control: ctrl,
            },
            MsiCapBody::default(),
        ));
        Self { cap, irqfds }
    }

    fn update_msi(&self) -> hv::Result<()> {
        let (hdr, body) = &*self.cap.read();
        let ctrl = &hdr.control;
        let data = &body.data;
        let msg_mask = if ctrl.ext_msg_data() {
            0xffff_ffff
        } else {
            0xffff
        };
        let (addr, msg) = if ctrl.addr_64_cap() {
            (
                ((data[1] as u64) << 32) | data[0] as u64,
                data[2] & msg_mask,
            )
        } else {
            (data[0] as u64, data[1] & msg_mask)
        };
        let mask = match (ctrl.addr_64_cap(), ctrl.per_vector_masking_cap()) {
            (true, true) => data[3],
            (false, true) => data[2],
            (_, false) => 0,
        };
        let count = 1 << ctrl.multi_msg();
        for (index, irqfd) in self.irqfds.iter().enumerate() {
            irqfd.set_masked(true)?;
            if !ctrl.enable() || index >= count || mask & (1 << index) > 0 {
                continue;
            }
            let msg = msg | index as u32;
            irqfd.set_addr_hi((addr >> 32) as u32)?;
            irqfd.set_addr_lo(addr as u32)?;
            irqfd.set_data(msg)?;
            irqfd.set_masked(false)?;
        }
        Ok(())
    }
}

impl<F> Mmio for MsiCapMmio<F>
where
    F: IrqFd,
{
    fn size(&self) -> u64 {
        let (hdr, _) = &*self.cap.read();
        hdr.control.cap_size() as u64
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let (hdr, body) = &*self.cap.read();
        if offset < 4 {
            hdr.read(offset, size)
        } else {
            body.read(offset - size_of_val(hdr) as u64, size)
        }
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        let mut need_update = false;
        let mut cap = self.cap.write();
        let (hdr, body) = &mut *cap;
        let ctrl = &mut hdr.control;
        let addr_64_cap = ctrl.addr_64_cap();
        let per_vector_masking_cap = ctrl.per_vector_masking_cap();
        match (offset, size, addr_64_cap, per_vector_masking_cap) {
            (0x2, 2, _, _) => {
                let new_ctrl = MsiMsgCtrl(val as u16);

                if !ctrl.enable() || !new_ctrl.enable() {
                    let multi_msg = min(ctrl.multi_msg_cap(), new_ctrl.multi_msg());
                    ctrl.set_multi_msg(multi_msg);
                }

                let ext_msg_data = ctrl.ext_msg_data_cap() && new_ctrl.ext_msg_data();
                need_update |= new_ctrl.enable() && ctrl.ext_msg_data() != ext_msg_data;
                ctrl.set_ext_msg_data(ext_msg_data);

                need_update |= ctrl.enable() != new_ctrl.enable();
                ctrl.set_enable(new_ctrl.enable());
            }
            (0x4, 4, _, _) | (0x8, 4, true, _) | (0xc, 4, false, true) | (0x10, 4, true, true) => {
                let data_offset = (offset as usize - size_of::<MsiCapHdr>()) >> 2;
                let reg = &mut body.data[data_offset];
                need_update = hdr.control.enable() && *reg != val as u32;
                *reg = val as u32;
            }
            (0x8, 2 | 4, false, _) | (0xc, 2 | 4, true, _) => {
                let data_offset = (offset as usize - size_of::<MsiCapHdr>()) >> 2;
                let reg = &mut body.data[data_offset];
                let mask = if size == 4 && hdr.control.ext_msg_data_cap() {
                    0xffff_ffff
                } else {
                    0xffff
                };
                let new_val = mask_bits!(*reg, val as u32, mask);
                need_update = hdr.control.enable() && *reg != new_val;
                *reg = new_val;
            }
            _ => log::error!(
                "MsiCapMmio: write 0x{val:0width$x} to invalid offset 0x{offset:x}.",
                width = 2 * size as usize
            ),
        }
        drop(cap);
        if need_update {
            self.update_msi().box_trace(mem::error::Mmio)?;
        }
        Ok(Action::None)
    }
}

impl<F> PciCap for MsiCapMmio<F>
where
    F: IrqFd,
{
    fn set_next(&mut self, val: u8) {
        let (hdr, _) = self.cap.get_mut();
        hdr.header.next = val;
    }
}

impl<F> PciConfigArea for MsiCapMmio<F>
where
    F: IrqFd,
{
    fn reset(&self) -> pci::Result<()> {
        {
            let (hdr, _) = &mut *self.cap.write();
            hdr.control.set_enable(false);
        }
        self.update_msi().box_trace(pci::error::Reset)
    }
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
        MsixMsgCtrl(len - 1)
    }
}

bitfield! {
    #[derive(Copy, Clone, Default, FromBytes, Immutable, IntoBytes)]
    #[repr(C)]
    pub struct MsixCapOffset(u32);
    impl Debug;
    pub bar, _: 2, 0;
}

impl MsixCapOffset {
    pub fn new(offset: u32, bar: u8) -> Self {
        MsixCapOffset(mask_bits!(offset, bar as u32, 0b111))
    }

    pub fn offset(&self) -> u32 {
        self.0 & !0b111
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
}

impl PciConfigArea for PciCapList {
    fn reset(&self) -> Result<()> {
        for (_, cap) in self.inner.inner.iter() {
            cap.reset()?;
        }
        Ok(())
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
    cap: RwLock<MsixCap>,
}

impl MsixCapMmio {
    pub fn new(cap: MsixCap) -> Self {
        Self {
            cap: RwLock::new(cap),
        }
    }
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
    fn reset(&self) -> pci::Result<()> {
        let mut cap = self.cap.write();
        cap.control.set_enabled(false);
        cap.control.set_masked(false);
        Ok(())
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

impl<F> Default for MsixTableMmioEntry<F> {
    fn default() -> Self {
        MsixTableMmioEntry::Entry(MsixTableEntry::default())
    }
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
            *entry = MsixTableMmioEntry::default();
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

impl PciCap for NullCap {
    fn set_next(&mut self, val: u8) {
        self.next = val;
    }
}

impl PciConfigArea for NullCap {
    fn reset(&self) -> Result<()> {
        Ok(())
    }
}
