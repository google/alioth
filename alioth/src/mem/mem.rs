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

use std::any::type_name;
use std::fmt::Debug;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use parking_lot::Mutex;
use snafu::Snafu;

use crate::errors::{trace_error, DebugTrace};
use crate::hv::{VmEntry, VmMemory};

pub mod addressable;
pub mod emulated;
pub mod mapped;

use addressable::{Addressable, SlotBackend};
use emulated::{Action, MmioBus, MmioRange};
use mapped::{ArcMemPages, RamBus};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, visibility(pub), context(suffix(false)))]
pub enum Error {
    #[snafu(display("Hypervisor internal error"), context(false))]
    HvError { source: Box<crate::hv::Error> },
    #[snafu(display("Cannot add a zero-sized slot"))]
    ZeroSizedSlot,
    #[snafu(display("(addr={addr:#x}, size={size:#x}) exceeds the address limit"))]
    ExceedsLimit { addr: u64, size: u64 },
    #[snafu(display("{new_item:#x?} overlaps with {exist_item:#x?}"))]
    Overlap {
        new_item: [u64; 2],
        exist_item: [u64; 2],
    },
    #[snafu(display("{addr:#x} is not mapped"))]
    NotMapped { addr: u64 },
    #[snafu(display("Sum of backend range sizes {sum:#x} exceeds the region total size"))]
    BackendTooBig { sum: u64, size: u64 },
    #[snafu(display("address {addr:#x} is not {align}-byte aligned"))]
    NotAligned { addr: u64, align: usize },
    #[snafu(display(
        "Guest address {addr:#x} (size = {:#x}) is not backed by continuous host memory"
    ))]
    NotContinuous { addr: u64, size: u64 },
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("Failed to write data to destination"))]
    Write { error: std::io::Error },
    #[snafu(display("Failed to read data from source"))]
    Read { error: std::io::Error },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum MemRange {
    Mapped(ArcMemPages),
    Emulated(MmioRange),
    Span(u64),
}

impl MemRange {
    pub fn size(&self) -> u64 {
        match self {
            MemRange::Mapped(pages) => pages.size(),
            MemRange::Emulated(range) => range.size(),
            MemRange::Span(size) => *size,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemRegionType {
    Hidden,
    Ram,
    Reserved,
    Acpi,
    Pmem,
}

#[derive(Debug, Clone, Copy)]
pub struct MemRegionEntry {
    pub size: u64,
    pub type_: MemRegionType,
}

pub trait MemRegionCallback: Debug + Send + Sync + 'static {
    fn mapped(&self, addr: u64) -> Result<()>;
    fn unmapped(&self) -> Result<()> {
        log::debug!("{} unmapped", type_name::<Self>());
        Ok(())
    }
}

#[derive(Debug)]
pub struct MemRegion {
    pub ranges: Vec<MemRange>,
    pub entries: Vec<MemRegionEntry>,
    pub callbacks: Mutex<Vec<Box<dyn MemRegionCallback>>>,
}

impl MemRegion {
    pub fn size(&self) -> u64 {
        self.entries.iter().fold(0, |accu, e| accu + e.size)
    }

    pub fn with_mapped(pages: ArcMemPages, type_: MemRegionType) -> MemRegion {
        let size = pages.size();
        MemRegion {
            ranges: vec![MemRange::Mapped(pages)],
            entries: vec![MemRegionEntry { type_, size }],
            callbacks: Mutex::new(vec![]),
        }
    }

    pub fn with_emulated(range: MmioRange, type_: MemRegionType) -> MemRegion {
        let size = range.size();
        MemRegion {
            ranges: vec![MemRange::Emulated(range)],
            entries: vec![MemRegionEntry { type_, size }],
            callbacks: Mutex::new(vec![]),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let entries_size = self.size();
        let ranges_size = self.ranges.iter().fold(0, |accu, r| accu + r.size());
        if ranges_size > entries_size {
            return error::BackendTooBig {
                sum: ranges_size,
                size: entries_size,
            }
            .fail();
        }
        Ok(())
    }
}

impl SlotBackend for Arc<MemRegion> {
    fn size(&self) -> u64 {
        MemRegion::size(self.as_ref())
    }
}

#[derive(Debug)]
pub struct IoRegion {
    pub range: MmioRange,
    pub callbacks: Mutex<Vec<Box<dyn MemRegionCallback>>>,
}

impl IoRegion {
    pub fn new(range: MmioRange) -> IoRegion {
        IoRegion {
            range,
            callbacks: Mutex::new(vec![]),
        }
    }
}

impl SlotBackend for Arc<IoRegion> {
    fn size(&self) -> u64 {
        self.range.size()
    }
}

#[derive(Debug)]
pub struct Memory {
    ram_bus: Arc<RamBus>,
    mmio_bus: MmioBus,
    regions: Mutex<Addressable<Arc<MemRegion>>>,
    io_bus: MmioBus,
    io_regions: Mutex<Addressable<Arc<IoRegion>>>,
}

impl Memory {
    pub fn new(vm_memory: impl VmMemory) -> Self {
        Memory {
            ram_bus: Arc::new(RamBus::new(vm_memory)),
            mmio_bus: MmioBus::new(),
            regions: Mutex::new(Addressable::new()),
            io_bus: MmioBus::new(),
            io_regions: Mutex::new(Addressable::new()),
        }
    }

    pub fn reset(&self) -> Result<()> {
        self.clear()?;
        self.ram_bus.next_slot_id.store(0, Ordering::Relaxed);
        Ok(())
    }

    pub fn ram_bus(&self) -> Arc<RamBus> {
        self.ram_bus.clone()
    }

    pub fn add_region(&self, addr: u64, region: Arc<MemRegion>) -> Result<()> {
        region.validate()?;
        let mut regions = self.regions.lock();
        regions.add(addr, region.clone())?;
        let mut offset = 0;
        for range in &region.ranges {
            match range {
                MemRange::Emulated(r) => self.mmio_bus.add(addr + offset, r.clone())?,
                MemRange::Mapped(r) => self.ram_bus.add(addr + offset, r.clone())?,
                MemRange::Span(_) => {}
            }
            offset += range.size();
        }
        let callbacks = region.callbacks.lock();
        for callback in callbacks.iter() {
            callback.mapped(addr)?;
        }
        Ok(())
    }

    fn unmap_region(&self, addr: u64, region: &MemRegion) -> Result<()> {
        let mut offset = 0;
        for range in &region.ranges {
            match range {
                MemRange::Emulated(_) => {
                    self.mmio_bus.remove(addr + offset)?;
                }
                MemRange::Mapped(_) => {
                    self.ram_bus.remove(addr + offset)?;
                }
                MemRange::Span(_) => {}
            };
            offset += range.size();
        }
        let callbacks = region.callbacks.lock();
        for callback in callbacks.iter() {
            callback.unmapped()?;
        }
        Ok(())
    }

    pub fn remove_region(&self, addr: u64) -> Result<Arc<MemRegion>> {
        let mut regions = self.regions.lock();
        let region = regions.remove(addr)?;
        self.unmap_region(addr, &region)?;
        Ok(region)
    }

    // TODO can be optimized
    fn clear(&self) -> Result<()> {
        let mut regions = self.regions.lock();
        let regions = regions.drain(..);
        for (addr, region) in regions {
            self.unmap_region(addr, &region)?;
        }
        #[cfg(target_arch = "x86_64")]
        {
            let mut io_regions = self.io_regions.lock();
            let io_regions = io_regions.drain(..);
            for (port, io_region) in io_regions {
                self.unmap_io_region(port as u16, &io_region)?;
            }
        }
        Ok(())
    }

    pub fn mem_region_entries(&self) -> Vec<(u64, MemRegionEntry)> {
        let mut entries = vec![];
        let regions = self.regions.lock();
        for (start, region) in regions.iter() {
            let mut offset = 0;
            for entry in region.entries.iter() {
                entries.push((start + offset, *entry));
                offset += entry.size;
            }
        }
        entries
    }

    pub fn add_io_dev(&self, port: u16, dev: MmioRange) -> Result<()> {
        self.add_io_region(port, Arc::new(IoRegion::new(dev)))
    }

    pub fn add_io_region(&self, port: u16, region: Arc<IoRegion>) -> Result<()> {
        let mut regions = self.io_regions.lock();
        regions.add(port as u64, region.clone())?;
        self.io_bus.add(port as u64, region.range.clone())?;
        let callbacks = region.callbacks.lock();
        for callback in callbacks.iter() {
            callback.mapped(port as u64)?;
        }
        Ok(())
    }

    fn unmap_io_region(&self, port: u16, region: &IoRegion) -> Result<()> {
        self.io_bus.remove(port as u64)?;
        let callbacks = region.callbacks.lock();
        for callback in callbacks.iter() {
            callback.unmapped()?;
        }
        Ok(())
    }

    pub fn remove_io_region(&self, port: u16) -> Result<Arc<IoRegion>> {
        let mut io_regions = self.io_regions.lock();
        let io_region = io_regions.remove(port as u64)?;
        self.unmap_io_region(port, &io_region)?;
        Ok(io_region)
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        if let Err(e) = self.clear() {
            log::info!("dropping memory: {e}")
        }
    }
}

impl Memory {
    fn handle_action(&self, action: Action) -> Result<VmEntry> {
        match action {
            Action::None => Ok(VmEntry::None),
            Action::Shutdown => Ok(VmEntry::Shutdown),
            Action::ChangeLayout { callback } => {
                callback.change(self)?;
                Ok(VmEntry::None)
            }
        }
    }

    pub fn handle_mmio(&self, gpa: u64, write: Option<u64>, size: u8) -> Result<VmEntry> {
        if let Some(val) = write {
            let action = self.mmio_bus.write(gpa, size, val)?;
            self.handle_action(action)
        } else {
            let data = self.mmio_bus.read(gpa, size)?;
            Ok(VmEntry::Mmio { data })
        }
    }

    pub fn handle_io(&self, port: u16, write: Option<u32>, size: u8) -> Result<VmEntry> {
        if port == 0x600 || port == 0x601 {
            log::warn!("port = {:#x}, val = {:#x?}, size = {}", port, write, size);
            if write == Some(0x34) {
                return Ok(VmEntry::Shutdown);
            }
        }
        // TODO: add an IO device
        if port == 0x604 && write == Some(0x1) {
            return Ok(VmEntry::Reboot);
        }
        if let Some(val) = write {
            let action = self.io_bus.write(port as u64, size, val as u64)?;
            self.handle_action(action)
        } else {
            let data = self.io_bus.read(port as u64, size)? as u32;
            Ok(VmEntry::Io { data })
        }
    }
}
