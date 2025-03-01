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

use std::iter::zip;
use std::mem::size_of;
use std::sync::Arc;

use bitflags::bitflags;
use macros::Layout;
use parking_lot::RwLock;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::mem::addressable::SlotBackend;
use crate::mem::emulated::{Action, ChangeLayout, Mmio};
use crate::pci::cap::PciCapList;
use crate::pci::{Bdf, PciBar};
use crate::{assign_bits, impl_mmio_for_zerocopy, mask_bits, mem};

pub trait PciConfigArea: Mmio {
    fn reset(&self);
}

impl Mmio for Box<dyn PciConfigArea> {
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

impl SlotBackend for Box<dyn PciConfigArea> {
    fn size(&self) -> u64 {
        Mmio::size(self.as_ref())
    }
}

#[derive(Clone, Copy, Default, IntoBytes, FromBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct Command(u16);

bitflags! {
    impl Command: u16 {
        const INTX_DISABLE = 1 << 10;
        const SERR = 1 << 8;
        const PARITY_ERR = 1 << 6;
        const BUS_MASTER = 1 << 2;
        const MEM = 1 << 1;
        const IO = 1 << 0;
        const WRITABLE_BITS = Self::INTX_DISABLE.bits()
            | Self::SERR.bits()
            | Self::PARITY_ERR.bits()
            | Self::BUS_MASTER.bits()
            | Self::MEM.bits()
            | Self::IO.bits();
    }
}

impl std::fmt::Debug for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

#[derive(Clone, Copy, Default, IntoBytes, FromBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct Status(u16);

bitflags! {
    impl Status: u16 {
        const PARITY_ERR = 1 << 15;
        const SYSTEM_ERR = 1 << 14;
        const RECEIVED_MASTER_ABORT = 1 << 13;
        const RECEIVED_TARGET_ABORT = 1 << 12;
        const SIGNALED_TARGET_ABORT = 1 << 11;
        const MASTER_PARITY_ERR = 1 << 8;
        const CAP = 1 << 4;
        const INTX = 1 << 3;
        const IMMEDIATE_READINESS = 1 << 0;
        const RW1C_BITS = Self::PARITY_ERR.bits()
            | Self::SYSTEM_ERR.bits()
            | Self::RECEIVED_MASTER_ABORT.bits()
            | Self::RECEIVED_TARGET_ABORT.bits()
            | Self::SIGNALED_TARGET_ABORT.bits()
            | Self::MASTER_PARITY_ERR.bits();
    }
}

impl std::fmt::Debug for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        bitflags::parser::to_writer(self, f)
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum HeaderType {
    Device = 0,
    Bridge = 1,
}

#[derive(Debug, Clone, Default, FromBytes, Immutable, KnownLayout, IntoBytes, Layout)]
#[repr(C, align(8))]
pub struct CommonHeader {
    pub vendor: u16,
    pub device: u16,
    pub command: Command,
    pub status: Status,
    pub revision: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub class: u8,
    pub cache_line_size: u8,
    pub latency_timer: u8,
    pub header_type: u8,
    pub bist: u8,
}

#[derive(Debug, Clone, Default, FromBytes, Immutable, KnownLayout, IntoBytes, Layout)]
#[repr(C, align(8))]
pub struct DeviceHeader {
    pub common: CommonHeader,
    pub bars: [u32; 6],
    pub cardbus_cis_pointer: u32,
    pub subsystem_vendor: u16,
    pub subsystem: u16,
    pub expansion_rom: u32,
    pub capability_pointer: u8,
    pub reserved: [u8; 7],
    pub intx_line: u8,
    pub intx_pin: u8,
    pub min_gnt: u8,
    pub max_lat: u8,
}
impl_mmio_for_zerocopy!(DeviceHeader);

pub const OFFSET_BAR0: usize = DeviceHeader::OFFSET_BARS;
pub const OFFSET_BAR5: usize = OFFSET_BAR0 + 5 * size_of::<u32>();

pub const BAR_PREFETCHABLE: u32 = 0b1000;
pub const BAR_MEM64: u32 = 0b0100;
pub const BAR_MEM32: u32 = 0b0000;
pub const BAR_IO: u32 = 0b01;

pub const BAR_IO_MASK: u32 = 0b11;
pub const BAR_MEM_MASK: u32 = 0b1111;

#[derive(Debug)]
pub enum ConfigHeader {
    Device(DeviceHeader),
}

impl ConfigHeader {
    pub fn bars(&self) -> [u32; 6] {
        match self {
            ConfigHeader::Device(header) => header.bars,
        }
    }
}

#[derive(Debug)]
struct UpdateCommandCallback {
    pci_bars: [PciBar; 6],
    bars: [u32; 6],
    changed: Command,
    current: Command,
}

impl ChangeLayout for UpdateCommandCallback {
    fn change(&self, memory: &mem::Memory) -> mem::Result<()> {
        for (i, (pci_bar, bar)) in zip(&self.pci_bars, self.bars).enumerate() {
            match pci_bar {
                PciBar::Empty => {}
                PciBar::Mem(region) => {
                    if !self.changed.contains(Command::MEM) {
                        continue;
                    }
                    let mut addr = (bar & !BAR_MEM_MASK) as u64;
                    if bar & BAR_MEM64 == BAR_MEM64 {
                        addr |= (self.bars[i + 1] as u64) << 32;
                    }
                    if self.current.contains(Command::MEM) {
                        memory.add_region(addr, region.clone())?;
                    } else {
                        memory.remove_region(addr)?;
                    }
                }
                PciBar::Io(region) => {
                    if !self.changed.contains(Command::IO) {
                        continue;
                    }
                    let port = (bar & !BAR_IO_MASK) as u16;
                    if self.current.contains(Command::IO) {
                        memory.add_io_region(port, region.clone())?;
                    } else {
                        memory.remove_io_region(port)?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
struct MoveBarCallback {
    bdf: Bdf,
    src: u64,
    dst: u64,
}

impl ChangeLayout for MoveBarCallback {
    fn change(&self, memory: &mem::Memory) -> mem::Result<()> {
        log::debug!(
            "{}: moving bar from {:#x} to {:#x}...",
            self.bdf,
            self.src,
            self.dst
        );
        if self.src as u32 & BAR_IO == BAR_IO {
            let src_port = self.src & !(BAR_IO_MASK as u64);
            let dst_port = self.dst & !(BAR_IO_MASK as u64);
            let region = memory.remove_io_region(src_port as u16)?;
            memory.add_io_region(dst_port as u16, region)?;
        } else {
            let src_addr = self.src & !(BAR_MEM_MASK as u64);
            let dst_addr = self.dst & !(BAR_MEM_MASK as u64);
            let region = memory.remove_region(src_addr)?;
            memory.add_region(dst_addr, region)?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct HeaderData {
    pub header: ConfigHeader,
    pub bar_masks: [u32; 6],
    pub bdf: Bdf,
}

impl HeaderData {
    pub fn set_bar(&mut self, index: usize, val: u32) -> (u32, u32) {
        match &mut self.header {
            ConfigHeader::Device(header) => {
                let mask = self.bar_masks[index];
                let old_val = header.bars[index];
                let masked_val = mask_bits!(old_val, val, mask);
                header.bars[index] = masked_val;
                log::info!(
                    "{}: bar {index}: set to {val:#010x}, update: {old_val:#010x} -> {masked_val:#010x}",
                    self.bdf
                );
                (old_val, masked_val)
            }
        }
    }

    pub fn get_bar(&self, index: usize) -> (u32, u32) {
        match &self.header {
            ConfigHeader::Device(header) => (header.bars[index], self.bar_masks[index]),
        }
    }

    pub fn set_command(&mut self, command: Command) {
        match &mut self.header {
            ConfigHeader::Device(header) => header.common.command = command,
        }
    }

    fn write_header(
        &mut self,
        offset: u64,
        size: u8,
        val: u64,
        pci_bars: &[PciBar; 6],
    ) -> Option<Box<dyn ChangeLayout>> {
        let bdf = self.bdf;
        let offset = offset as usize;
        match &mut self.header {
            ConfigHeader::Device(header) => match (offset, size as usize) {
                CommonHeader::LAYOUT_COMMAND => {
                    let val = Command::from_bits_retain(val as u16);
                    let old = header.common.command;
                    assign_bits!(header.common.command, val, Command::WRITABLE_BITS);
                    let current = header.common.command;
                    log::trace!("{bdf}: write command: {val:x?}\n   {old:x?}\n-> {current:x?}",);
                    let changed = old ^ current;
                    if !(changed & (Command::MEM | Command::IO)).is_empty() {
                        Some(Box::new(UpdateCommandCallback {
                            pci_bars: pci_bars.clone(),
                            bars: header.bars,
                            changed,
                            current,
                        }))
                    } else {
                        None
                    }
                }
                CommonHeader::LAYOUT_STATUS => {
                    let val = Status::from_bits_retain(val as u16);
                    let old = header.common.status;
                    header.common.status &= !(val & Status::RW1C_BITS);
                    log::trace!(
                        "{bdf}: write status: {val:x?}\n   {old:x?}\n-> {:x?}",
                        header.common.status,
                    );
                    None
                }
                (OFFSET_BAR0..=OFFSET_BAR5, 4) => {
                    let bar_index = (offset - OFFSET_BAR0) >> 2;

                    let mask = self.bar_masks[bar_index];
                    let old_val = header.bars[bar_index];
                    let masked_val = mask_bits!(old_val, val as u32, mask);
                    if old_val == masked_val {
                        return None;
                    }
                    log::info!(
                        "{bdf}: updating bar {bar_index}: {old_val:#010x} -> {masked_val:#010x}, mask={mask:#010x}",
                    );
                    let command = header.common.command;
                    match &pci_bars[bar_index] {
                        PciBar::Io(_) if command.contains(Command::IO) => {
                            Some(Box::new(MoveBarCallback {
                                bdf,
                                src: old_val as u64,
                                dst: masked_val as u64,
                            }))
                        }
                        PciBar::Mem(_) if command.contains(Command::MEM) => {
                            let hi_32 = if old_val & BAR_MEM64 == BAR_MEM64 {
                                (header.bars[bar_index + 1] as u64) << 32
                            } else {
                                0
                            };
                            Some(Box::new(MoveBarCallback {
                                bdf,
                                src: old_val as u64 | hi_32,
                                dst: masked_val as u64 | hi_32,
                            }))
                        }
                        PciBar::Empty
                            if command.contains(Command::MEM)
                                && bar_index > 0
                                && header.bars[bar_index - 1] & BAR_MEM64 == BAR_MEM64 =>
                        {
                            let lo_32 = header.bars[bar_index - 1] as u64;
                            Some(Box::new(MoveBarCallback {
                                bdf,
                                src: lo_32 | ((old_val as u64) << 32),
                                dst: lo_32 | ((masked_val as u64) << 32),
                            }))
                        }
                        _ => {
                            header.bars[bar_index] = masked_val;
                            log::info!("{bdf}: bar {bar_index}: write {val:#010x}, update: {old_val:#010x} -> {masked_val:#010x}");
                            None
                        }
                    }
                }
                DeviceHeader::LAYOUT_EXPANSION_ROM => {
                    log::info!("{bdf}: write {val:#010x} to expansion_rom: ignored");
                    None
                }
                _ => {
                    log::warn!(
                        "{bdf}: unknown write: offset = {offset:#x}, size = {size}, val = {val:#x}"
                    );
                    None
                }
            },
        }
    }
}

#[derive(Debug)]
pub struct EmulatedHeader {
    pub data: Arc<RwLock<HeaderData>>,
    pub bars: [PciBar; 6],
}

impl EmulatedHeader {
    pub fn set_bdf(&self, bdf: Bdf) {
        self.data.write().bdf = bdf
    }

    pub fn set_command(&self, command: Command) {
        let mut header = self.data.write();
        header.set_command(command)
    }
}

impl Mmio for EmulatedHeader {
    fn size(&self) -> u64 {
        0x40
    }

    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        let data = self.data.read();
        match &data.header {
            ConfigHeader::Device(header) => Mmio::read(header, offset, size),
        }
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        let mut data = self.data.write();
        if let Some(callback) = data.write_header(offset, size, val, &self.bars) {
            Ok(Action::ChangeLayout { callback })
        } else {
            Ok(Action::None)
        }
    }
}

impl PciConfigArea for EmulatedHeader {
    fn reset(&self) {
        let mut header = self.data.write();
        header.set_command(Command::empty());
    }
}

pub trait PciConfig: Mmio {
    fn get_header(&self) -> &EmulatedHeader;
    fn reset(&self);
}

#[derive(Debug)]
pub struct EmulatedConfig {
    pub header: EmulatedHeader,
    pub caps: PciCapList,
}

impl Mmio for EmulatedConfig {
    fn read(&self, offset: u64, size: u8) -> mem::Result<u64> {
        if offset < size_of::<DeviceHeader>() as u64 {
            self.header.read(offset, size)
        } else {
            self.caps.read(offset, size)
        }
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> mem::Result<Action> {
        if offset < size_of::<DeviceHeader>() as u64 {
            self.header.write(offset, size, val)
        } else {
            self.caps.write(offset, size, val)
        }
    }

    fn size(&self) -> u64 {
        4096
    }
}

impl EmulatedConfig {
    pub fn new_device(
        mut header: DeviceHeader,
        bar_masks: [u32; 6],
        bars: [PciBar; 6],
        caps: PciCapList,
    ) -> EmulatedConfig {
        if !caps.is_empty() {
            header.common.status |= Status::CAP;
            header.capability_pointer = size_of::<DeviceHeader>() as u8;
        }
        let header = EmulatedHeader {
            data: Arc::new(RwLock::new(HeaderData {
                header: ConfigHeader::Device(header),
                bar_masks,
                bdf: Bdf(0),
            })),
            bars,
        };
        EmulatedConfig { header, caps }
    }
}

impl PciConfig for EmulatedConfig {
    fn get_header(&self) -> &EmulatedHeader {
        &self.header
    }

    fn reset(&self) {
        self.header.reset();
        self.caps.reset();
    }
}
