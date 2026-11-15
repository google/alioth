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

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::mem::size_of;

use bitflags::bitflags;
use derive_layout::Layout;
use crate::sync::RwLock;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::mem::addressable::SlotBackend;
use crate::mem::mmio::Mmio;
use crate::mem::{AddrOpt, ChangeLayout};
use crate::hw::pci::cap::PciCapList;
use crate::hw::pci::{Bdf, PciBar};
use crate::{assign_bits, mask_bits, mem, unsafe_impl_zerocopy};

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Command: u16 {
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
unsafe_impl_zerocopy!(Command, FromBytes, FromZeroes, AsBytes);

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Status: u16 {
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
unsafe_impl_zerocopy!(Status, FromBytes, FromZeroes, AsBytes);

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum HeaderType {
    Device = 0,
    Bridge = 1,
}

#[derive(Debug, Clone, Default, FromBytes, FromZeroes, AsBytes, Layout)]
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

#[derive(Debug, Clone, Default, FromBytes, FromZeroes, AsBytes, Layout)]
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

const MAX_GUEST_PA_END: u64 = 1u64 << 46;

#[derive(Debug)]
struct BarTransition {
    pci_bar: PciBar,
    old_addr: Option<u64>,
    new_addr: Option<u64>,
}

#[derive(Debug)]
struct SyncBarsCallback {
    bdf: Bdf,
    transitions: Vec<BarTransition>,
}

impl ChangeLayout for SyncBarsCallback {
    fn change(&self, memory: &mem::Memory) -> mem::Result<()> {
        for t in &self.transitions {
            if let Some(src) = t.old_addr {
                log::debug!("{}: unmapping BAR at {src:#x}", self.bdf);
                match &t.pci_bar {
                    PciBar::Empty => {}
                    PciBar::Io(_) => {
                        memory.remove_io_region(src as u16)?;
                    }
                    PciBar::Mem32(_) | PciBar::Mem64(_) => {
                        memory.remove_region(src)?;
                    }
                }
            }
        }
        for t in &self.transitions {
            if let Some(dst) = t.new_addr {
                log::debug!("{}: mapping BAR at {dst:#x}", self.bdf);
                match &t.pci_bar {
                    PciBar::Empty => {}
                    PciBar::Io(region) => {
                        memory.add_io_region(Some(dst as u16), region.clone())?;
                    }
                    PciBar::Mem32(region) | PciBar::Mem64(region) => {
                        memory.add_region(AddrOpt::Fixed(dst), region.clone())?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn desired_bar_addr(
    bars: &[u32; 6],
    bar_masks: &[u32; 6],
    command: Command,
    index: usize,
    pci_bar: &PciBar,
) -> Option<u64> {
    match pci_bar {
        PciBar::Empty => None,
        PciBar::Io(region) => {
            if !command.contains(Command::IO) {
                return None;
            }
            let mask = bar_masks[index];
            let masked = bars[index] & mask;
            if mask != 0 && masked == mask {
                return None;
            }
            let port = (bars[index] & !BAR_IO_MASK) as u16;
            if port == 0
                || (port as usize)
                    .checked_add(region.size())
                    .is_none_or(|end| end > (u16::MAX as usize) + 1)
            {
                return None;
            }
            Some(port as u64)
        }
        PciBar::Mem32(region) => {
            if !command.contains(Command::MEM) {
                return None;
            }
            let mask = bar_masks[index];
            let masked = bars[index] & mask;
            if mask != 0 && masked == mask {
                return None;
            }
            let addr = (bars[index] & !BAR_MEM_MASK) as u32;
            if addr == 0 || addr.checked_add(region.size() as u32).is_none() {
                return None;
            }
            Some(addr as u64)
        }
        PciBar::Mem64(region) => {
            if !command.contains(Command::MEM) {
                return None;
            }
            let mask_lo = bar_masks[index];
            let masked_lo = bars[index] & mask_lo;
            if mask_lo != 0 && masked_lo == mask_lo {
                return None;
            }
            let lo = (bars[index] & !BAR_MEM_MASK) as u64;
            let hi = (bars[index + 1] as u64) << 32;
            let addr = hi | lo;
            if addr == 0
                || addr
                    .checked_add(region.size() as u64)
                    .is_none_or(|end| end > MAX_GUEST_PA_END)
            {
                return None;
            }
            Some(addr)
        }
    }
}

#[derive(Debug)]
pub struct HeaderData {
    pub header: ConfigHeader,
    pub bar_masks: [u32; 6],
    pub mapped_bars: [Option<u64>; 6],
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

    pub fn set_command(&mut self, command: Command) {
        match &mut self.header {
            ConfigHeader::Device(header) => header.common.command = command,
        }
    }

    fn reconcile_bars(&mut self, pci_bars: &[PciBar; 6]) -> Option<Box<dyn ChangeLayout>> {
        let ConfigHeader::Device(header) = &self.header;
        let mut transitions = Vec::new();
        for (i, pci_bar) in pci_bars.iter().enumerate() {
            let want = desired_bar_addr(
                &header.bars,
                &self.bar_masks,
                header.common.command,
                i,
                pci_bar,
            );
            if self.mapped_bars[i] != want {
                transitions.push(BarTransition {
                    pci_bar: pci_bar.clone(),
                    old_addr: self.mapped_bars[i],
                    new_addr: want,
                });
                self.mapped_bars[i] = want;
            }
        }
        if transitions.is_empty() {
            None
        } else {
            Some(Box::new(SyncBarsCallback {
                bdf: self.bdf,
                transitions,
            }))
        }
    }

    fn write_header(
        &mut self,
        offset: usize,
        size: u8,
        val: u64,
        pci_bars: &[PciBar; 6],
    ) -> Option<Box<dyn ChangeLayout>> {
        let bdf = self.bdf;
        match (offset, size as usize) {
            CommonHeader::LAYOUT_COMMAND => {
                let cmd_in = Command::from_bits_retain(val as u16);
                let changed = {
                    let ConfigHeader::Device(header) = &mut self.header;
                    let old = header.common.command;
                    assign_bits!(header.common.command, cmd_in, Command::WRITABLE_BITS);
                    let current = header.common.command;
                    log::trace!("{bdf}: write command: {cmd_in:x?}\n   {old:x?}\n-> {current:x?}");
                    old ^ current
                };
                if !(changed & (Command::MEM | Command::IO)).is_empty() {
                    self.reconcile_bars(pci_bars)
                } else {
                    None
                }
            }
            (CommonHeader::OFFSET_COMMAND, 4) => {
                let cmd_in = Command::from_bits_retain(val as u16);
                let status_in = Status::from_bits_retain((val >> 16) as u16);
                let changed = {
                    let ConfigHeader::Device(header) = &mut self.header;
                    let old = header.common.command;
                    assign_bits!(header.common.command, cmd_in, Command::WRITABLE_BITS);
                    header.common.status &= !(status_in & Status::RW1C_BITS);
                    old ^ header.common.command
                };
                if !(changed & (Command::MEM | Command::IO)).is_empty() {
                    self.reconcile_bars(pci_bars)
                } else {
                    None
                }
            }
            CommonHeader::LAYOUT_STATUS => {
                let ConfigHeader::Device(header) = &mut self.header;
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
                let updated = {
                    let ConfigHeader::Device(header) = &mut self.header;
                    let old_val = header.bars[bar_index];
                    let masked_val = mask_bits!(old_val, val as u32, mask);
                    if old_val == masked_val {
                        false
                    } else {
                        header.bars[bar_index] = masked_val;
                        log::info!(
                            "{bdf}: bar {bar_index}: write {val:#010x}, update: {old_val:#010x} -> {masked_val:#010x}"
                        );
                        true
                    }
                };
                if updated {
                    self.reconcile_bars(pci_bars)
                } else {
                    None
                }
            }
            _ => {
                log::warn!(
                    "{bdf}: unaligned write offset = {offset:#x}, size = {size}, val = {val:#x}"
                );
                None
            }
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
    fn size(&self) -> usize {
        0x40
    }

    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        let data = self.data.read();
        let bytes = match &data.header {
            ConfigHeader::Device(header) => AsBytes::as_bytes(header),
        };
        let ret = match size {
            1 => bytes.get(offset).map(|b| *b as u64),
            2 => u16::read_from_prefix(&bytes[offset..]).map(|w| w as u64),
            4 => u32::read_from_prefix(&bytes[offset..]).map(|d| d as u64),
            8 => u64::read_from_prefix(&bytes[offset..]),
            _ => Some(0),
        };
        Ok(ret.unwrap_or(0))
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        let mut data = self.data.write();
        if let Some(callback) = data.write_header(offset, size, val, &self.bars) {
            Err(mem::Error::Action(mem::Action::ChangeLayout { callback }))
        } else {
            Ok(())
        }
    }
}

pub trait PciConfig: Mmio {
    fn get_header(&self) -> &EmulatedHeader;
}

#[derive(Debug)]
pub struct EmulatedConfig {
    pub header: EmulatedHeader,
    pub caps: PciCapList,
}

impl Mmio for EmulatedConfig {
    fn read(&self, offset: usize, size: u8) -> mem::Result<u64> {
        if offset < size_of::<DeviceHeader>() {
            self.header.read(offset, size)
        } else {
            self.caps.read(offset, size)
        }
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> mem::Result<()> {
        if offset < size_of::<DeviceHeader>() {
            self.header.write(offset, size, val)
        } else {
            self.caps.write(offset, size, val)
        }
    }

    fn size(&self) -> usize {
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
                mapped_bars: [None; 6],
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
}
