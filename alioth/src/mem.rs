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

mod addressable;
pub mod io;
pub mod mmio;
pub mod ram;

use std::sync::{Arc, Mutex, PoisonError};

use thiserror::Error;

use crate::action::Action;
use crate::align_up;
use crate::hv::{self, VmEntry, VmMemory};
use ram::UserMem;

use addressable::{Addressable, SlotBackend};
use io::IoBus;
use mmio::{Mmio, MmioBus};
use ram::RamBus;

use self::io::IoDev;

use crate::arch::layout::{
    MEM_64_START, MMIO_32_START, PCIE_CONFIG_END, PCIE_CONFIG_START, RAM_32_END,
};

#[derive(Debug, Error)]
pub enum Error {
    #[error("{new_item:#x?} overlaps with {exist_item:#x?}")]
    Overlap {
        new_item: [usize; 2],
        exist_item: [usize; 2],
    },
    #[error("(addr={addr:#x}, size={size:#x}) is out of range")]
    OutOfRange { addr: usize, size: usize },
    #[error("io: {source:#x?}")]
    Io {
        #[from]
        source: std::io::Error,
    },
    #[error("mmap: {0}")]
    Mmap(#[source] std::io::Error),
    #[error("offset {offset:#x} exceeds limit {limit:#x}")]
    ExceedLimit { offset: usize, limit: usize },
    #[error("{0:#x} is not mapped")]
    NotMapped(usize),
    #[error("zero memory size")]
    ZeroMemorySize,
    #[error("lock poisoned")]
    LockPoisoned,
    #[error("cannot allocate")]
    CanotAllocate,
    #[error("cannot register MMIO notifier: {0}")]
    Notifier(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),
    #[error("{0}")]
    Hv(#[from] hv::Error),
    #[error("cannot handle action: {0:x?}")]
    Action(Action),
    #[error("not aligned")]
    NotAligned,
    #[error("not backed by continuous host memory")]
    NotContinuous,
    #[error("adding a slot of size 0")]
    ZeroSizedSlot,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl<T> From<PoisonError<T>> for Error {
    fn from(_: PoisonError<T>) -> Self {
        Error::LockPoisoned
    }
}

#[derive(Debug, Default)]
pub struct Allocator {
    ram32: Addressable<MemRegion>,
    dev32: Addressable<MemRegion>,
    mem64: Addressable<MemRegion>,
    #[cfg(target_arch = "x86_64")]
    io: Addressable<MemRegion>,
}

#[derive(Debug)]
pub struct Memory {
    ram_bus: Arc<RamBus>,
    mmio_bus: MmioBus,
    io_bus: IoBus,
    // TODO do we need a global lock?
    allocator: Mutex<Allocator>,
}

pub enum AddrOpt {
    Any,
    Fixed(usize),
    Below4G,
    Above4G,
}

#[derive(Debug)]
pub enum DevMem {
    UserMem(UserMem),
    Mmio(Arc<dyn Mmio + Send + Sync>),
}

impl Memory {
    pub fn new<M>(vm_memory: M) -> Self
    where
        M: VmMemory,
    {
        Memory {
            ram_bus: Arc::new(RamBus::new(vm_memory)),
            mmio_bus: MmioBus::new(),
            allocator: Mutex::new(Allocator::default()),
            io_bus: IoBus::new(),
        }
    }

    pub fn ram_bus(&self) -> &Arc<RamBus> {
        &self.ram_bus
    }

    pub fn to_mem_regions(&self) -> Result<Vec<(usize, MemRegion)>, Error> {
        let mut regions = Vec::new();
        let allocator = self.allocator.lock()?;
        for (addr, region) in allocator.ram32.iter() {
            regions.push((addr, *region));
        }
        for (addr, region) in allocator.dev32.iter() {
            regions.push((addr, *region));
        }
        for (addr, region) in allocator.mem64.iter() {
            regions.push((addr, *region));
        }
        Ok(regions)
    }

    fn alloc_sub(
        size: usize,
        segment: &mut Addressable<MemRegion>,
        segment_start: usize,
        segment_end: usize,
        regions: &[(usize, MemRegionType)],
    ) -> Result<usize, Error> {
        // let rounded_size = usize::next_power_of_two(usize::max(size, PAGE_SIZE));
        let rounded_size = size;
        let start = if let Some((start, region)) = segment.last() {
            start + region.size
        } else {
            segment_start
        };
        let start = std::cmp::max(start, segment_start);
        let aligned_start = align_up!(start, rounded_size);
        log::info!(
            "aligned start = {:#x}, segment_end = {:#x}",
            aligned_start,
            segment_end
        );
        if aligned_start + rounded_size <= segment_end {
            let mut addr = aligned_start;
            for (size, type_) in regions.iter() {
                let region = MemRegion {
                    size: *size,
                    type_: *type_,
                };
                segment.add(addr, region)?;
                addr += size;
            }
            Ok(aligned_start)
        } else {
            Err(Error::CanotAllocate)
        }
    }

    pub fn add_ram(
        &self,
        gpa: AddrOpt,
        user_mem: UserMem,
        regions: &[(usize, MemRegionType)],
    ) -> Result<usize, Error> {
        let addr = self.alloc(gpa, user_mem.size(), false, regions)?;
        self.ram_bus.add(addr, user_mem)?;
        Ok(addr)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_io_dev(&self, port: Option<u16>, dev: IoDev) -> Result<u16, Error> {
        let mut allocator = self.allocator.lock()?;
        let port = match port {
            Some(port) => {
                allocator.io.add(
                    port as usize,
                    MemRegion {
                        size: dev.size(),
                        type_: MemRegionType::Reserved,
                    },
                )?;
                port
            }
            None => {
                let port = Self::alloc_sub(
                    dev.size(),
                    &mut allocator.io,
                    0x1000,
                    0xffff,
                    &[(dev.size(), MemRegionType::Reserved)],
                )?;
                port as u16
            }
        };
        self.io_bus.add(port, dev)?;
        Ok(port)
    }

    fn alloc(
        &self,
        gpa: AddrOpt,
        size: usize,
        is_dev: bool,
        regions: &[(usize, MemRegionType)],
    ) -> Result<usize, Error> {
        let mut allocator = self.allocator.lock()?;
        let addr_start = match gpa {
            AddrOpt::Fixed(gpa) => {
                let below_4g = gpa + size <= u32::MAX as usize;
                let mut region_gpa = gpa;
                for (size, type_) in regions.iter() {
                    let region = MemRegion {
                        size: *size,
                        type_: *type_,
                    };
                    if below_4g {
                        if is_dev {
                            allocator.dev32.add(region_gpa, region)?;
                        } else {
                            allocator.ram32.add(region_gpa, region)?;
                        }
                    } else {
                        allocator.mem64.add(region_gpa, region)?;
                    }
                    region_gpa += size;
                }
                Ok(gpa)
            }
            AddrOpt::Above4G | AddrOpt::Any => Self::alloc_sub(
                size,
                &mut allocator.mem64,
                MEM_64_START,
                usize::MAX,
                regions,
            ),
            AddrOpt::Below4G => {
                if is_dev {
                    Self::alloc_sub(
                        size,
                        &mut allocator.dev32,
                        MMIO_32_START,
                        PCIE_CONFIG_END,
                        regions,
                    )
                } else {
                    Self::alloc_sub(size, &mut allocator.ram32, 0, RAM_32_END, regions)
                }
            }
        }?;
        Ok(addr_start)
    }

    fn handle_action(&self, action: Action) -> Result<VmEntry> {
        match action {
            Action::Shutdown => Ok(VmEntry::Shutdown),
        }
    }

    pub fn handle_mmio(&self, gpa: usize, write: Option<u64>, size: u8) -> Result<VmEntry> {
        if let Some(val) = write {
            match self.mmio_bus.write(gpa, size, val) {
                Ok(()) => Ok(VmEntry::None),
                Err(Error::Action(action)) => self.handle_action(action),
                Err(e) => Err(e),
            }
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
        if let Some(val) = write {
            match self.io_bus.write(port, size, val) {
                Ok(()) => Ok(VmEntry::None),
                Err(Error::Action(action)) => self.handle_action(action),
                Err(e) => Err(e),
            }
        } else {
            let data = self.io_bus.read(port, size)?;
            Ok(VmEntry::Io { data })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemRegionType {
    Ram,
    Reserved,
    Acpi,
    Pmem,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemRegion {
    pub size: usize,
    pub type_: MemRegionType,
}

impl SlotBackend for MemRegion {
    fn size(&self) -> usize {
        self.size
    }
}
