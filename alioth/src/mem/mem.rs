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
use std::sync::Arc;

use parking_lot::Mutex;
use serde::Deserialize;
use snafu::Snafu;

use crate::errors::{trace_error, DebugTrace};
use crate::hv::{MemMapOption, VmEntry, VmMemory};

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
    #[snafu(display("Failed to do MMIO"))]
    Mmio {
        source: Box<dyn DebugTrace + Send + Sync + 'static>,
    },
    #[snafu(display("Failed to change memory layout"))]
    ChangeLayout {
        source: Box<dyn DebugTrace + Send + Sync + 'static>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

fn default_memory_size() -> u64 {
    1 << 30
}

#[derive(Debug, Deserialize, Default)]
pub struct MemConfig {
    #[serde(default = "default_memory_size")]
    pub size: u64,
    #[serde(default)]
    pub backend: MemBackend,
    #[serde(default)]
    pub shared: bool,
    #[cfg(target_os = "linux")]
    #[serde(default, alias = "thp")]
    pub transparent_hugepage: bool,
}

#[derive(Debug, Deserialize, Default)]
pub enum MemBackend {
    #[default]
    #[serde(alias = "anon")]
    Anonymous,
    #[cfg(target_os = "linux")]
    #[serde(alias = "memfd")]
    Memfd,
}

impl MemConfig {
    pub fn has_shared_fd(&self) -> bool {
        match &self.backend {
            #[cfg(target_os = "linux")]
            MemBackend::Memfd => true,
            MemBackend::Anonymous => false,
        }
    }
}

#[derive(Debug)]
pub enum MemRange {
    Ram(ArcMemPages),
    DevMem(ArcMemPages),
    Emulated(MmioRange),
    Span(u64),
}

impl MemRange {
    pub fn size(&self) -> u64 {
        match self {
            MemRange::Ram(pages) | MemRange::DevMem(pages) => pages.size(),
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

    pub fn with_ram(pages: ArcMemPages, type_: MemRegionType) -> MemRegion {
        let size = pages.size();
        MemRegion {
            ranges: vec![MemRange::Ram(pages)],
            entries: vec![MemRegionEntry { type_, size }],
            callbacks: Mutex::new(vec![]),
        }
    }

    pub fn with_dev_mem(pages: ArcMemPages, type_: MemRegionType) -> MemRegion {
        let size = pages.size();
        MemRegion {
            ranges: vec![MemRange::DevMem(pages)],
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

pub trait LayoutChanged: Debug + Send + Sync + 'static {
    fn ram_added(&self, gpa: u64, pages: &ArcMemPages) -> Result<()>;
    fn ram_removed(&self, gpa: u64, pages: &ArcMemPages) -> Result<()>;
}

#[derive(Debug)]
pub struct Memory {
    ram_bus: Arc<RamBus>,
    mmio_bus: MmioBus,
    regions: Mutex<Addressable<Arc<MemRegion>>>,
    vm_memory: Box<dyn VmMemory>,
    io_bus: MmioBus,
    io_regions: Mutex<Addressable<Arc<IoRegion>>>,
    callbacks: Mutex<Vec<Box<dyn LayoutChanged>>>,
}

impl Memory {
    pub fn new(vm_memory: impl VmMemory) -> Self {
        Memory {
            ram_bus: Arc::new(RamBus::new()),
            mmio_bus: MmioBus::new(),
            regions: Mutex::new(Addressable::new()),
            vm_memory: Box::new(vm_memory),
            io_bus: MmioBus::new(),
            io_regions: Mutex::new(Addressable::new()),
            callbacks: Mutex::new(Vec::new()),
        }
    }

    pub fn register_callback(&self, callback: Box<dyn LayoutChanged>) -> Result<()> {
        let regions = self.regions.lock();
        for (addr, region) in regions.iter() {
            let mut offset = 0;
            for range in &region.ranges {
                let gpa = addr + offset;
                match range {
                    MemRange::Ram(r) => callback.ram_added(gpa, r)?,
                    MemRange::Span(_) | MemRange::Emulated(_) | MemRange::DevMem(_) => {}
                }
                offset += range.size();
            }
        }
        let mut callbacks = self.callbacks.lock();
        callbacks.push(callback);

        Ok(())
    }

    pub fn reset(&self) -> Result<()> {
        self.clear()?;
        self.vm_memory.reset()?;
        Ok(())
    }

    pub fn ram_bus(&self) -> Arc<RamBus> {
        self.ram_bus.clone()
    }

    fn map_to_vm(&self, gpa: u64, user_mem: &ArcMemPages) -> Result<(), Error> {
        let mem_options = MemMapOption {
            read: true,
            write: true,
            exec: true,
            log_dirty: false,
        };
        self.vm_memory
            .mem_map(gpa, user_mem.size(), user_mem.addr(), mem_options)?;
        Ok(())
    }

    fn unmap_from_vm(&self, gpa: u64, user_mem: &ArcMemPages) -> Result<(), Error> {
        self.vm_memory.unmap(gpa, user_mem.size())?;
        Ok(())
    }

    pub fn add_region(&self, addr: u64, region: Arc<MemRegion>) -> Result<()> {
        region.validate()?;
        let mut regions = self.regions.lock();
        regions.add(addr, region.clone())?;
        let mut offset = 0;
        let callbacks = self.callbacks.lock();
        for range in &region.ranges {
            let gpa = addr + offset;
            match range {
                MemRange::Emulated(r) => self.mmio_bus.add(gpa, r.clone())?,
                MemRange::Ram(r) => {
                    self.map_to_vm(gpa, r)?;
                    for callback in callbacks.iter() {
                        callback.ram_added(gpa, r)?;
                    }
                    self.ram_bus.add(gpa, r.clone())?;
                }
                MemRange::DevMem(r) => self.map_to_vm(gpa, r)?,
                MemRange::Span(_) => {}
            }
            offset += range.size();
        }

        let region_callbacks = region.callbacks.lock();
        for callback in region_callbacks.iter() {
            callback.mapped(addr)?;
        }
        Ok(())
    }

    fn unmap_region(&self, addr: u64, region: &MemRegion) -> Result<()> {
        let mut offset = 0;
        let callbacks = self.callbacks.lock();
        for range in &region.ranges {
            let gpa = addr + offset;
            match range {
                MemRange::Emulated(_) => {
                    self.mmio_bus.remove(gpa)?;
                }
                MemRange::Ram(r) => {
                    self.ram_bus.remove(gpa)?;
                    for callback in callbacks.iter() {
                        callback.ram_removed(gpa, r)?;
                    }
                    self.unmap_from_vm(gpa, r)?;
                }
                MemRange::DevMem(r) => self.unmap_from_vm(gpa, r)?,
                MemRange::Span(_) => {}
            };
            offset += range.size();
        }
        let region_callbacks = region.callbacks.lock();
        for callback in region_callbacks.iter() {
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

    pub fn register_encrypted_pages(&self, pages: &ArcMemPages) -> Result<()> {
        self.vm_memory.register_encrypted_range(pages.as_slice())?;
        Ok(())
    }

    pub fn deregister_encrypted_pages(&self, pages: &ArcMemPages) -> Result<()> {
        self.vm_memory
            .deregister_encrypted_range(pages.as_slice())?;
        Ok(())
    }

    pub fn mark_private_memory(&self, gpa: u64, size: u64, private: bool) -> Result<()> {
        let vm_memory = &self.vm_memory;
        let regions = self.regions.lock();
        let end = gpa + size;
        let mut start = gpa;
        'out: while let Some((mut addr, region)) = regions.search_next(start) {
            let next_start = addr + region.size();
            for range in &region.ranges {
                let (MemRange::DevMem(r) | MemRange::Ram(r)) = range else {
                    addr += range.size();
                    continue;
                };
                let range_end = addr + r.size();
                if range_end <= start {
                    addr = range_end;
                    continue;
                }
                let gpa_start = std::cmp::max(addr, start);
                let gpa_end = std::cmp::min(end, range_end);
                if gpa_start >= gpa_end {
                    break 'out;
                }
                vm_memory.mark_private_memory(gpa_start, gpa_end - gpa_start, private)?;
                start = gpa_end;
            }
            if next_start >= end {
                break;
            }
            start = next_start;
        }
        Ok(())
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
            Action::Reset => Ok(VmEntry::Reboot),
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
        if let Some(val) = write {
            let action = self.io_bus.write(port as u64, size, val as u64)?;
            self.handle_action(action)
        } else {
            let data = self.io_bus.read(port as u64, size)? as u32;
            Ok(VmEntry::Io { data })
        }
    }
}
