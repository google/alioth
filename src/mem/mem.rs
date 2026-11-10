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
use std::cell::UnsafeCell;
use std::fmt::Debug;
use std::io::{IoSlice, IoSliceMut, Read, Write};
use std::mem::{align_of, size_of};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use parking_lot::{Mutex, RwLock, RwLockReadGuard};
use thiserror::Error;
use zerocopy::{AsBytes, FromBytes};

use crate::arch::layout::{MEM_64_START, MMIO_32_END, MMIO_32_START, PAGE_SIZE};
use crate::hv::{self, VmEntry, VmMemory};

pub mod addressable;
pub mod mapped;
pub mod mmio;

use addressable::{Addressable, SlotBackend};
pub use mapped::ArcMemPages;
pub use mmio::{Mmio, MmioRange};

#[derive(Debug)]
pub enum Action {
    Shutdown,
    ChangeLayout { callback: Box<dyn ChangeLayout> },
}

pub trait ChangeLayout: Debug + Send + Sync + 'static {
    fn change(&self, memory: &Memory) -> Result<()>;
}

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
    #[error("total length of region entries does not match mam range size")]
    MemRegionEntryMismatch,
    #[error("total length of backends does not match the mem range size")]
    MemRangeMismatch,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug)]
pub enum MemRange {
    Mapped(ArcMemPages),
    Emulated(MmioRange),
    Span(usize),
}

impl MemRange {
    pub fn size(&self) -> usize {
        match self {
            MemRange::Mapped(pages) => pages.size(),
            MemRange::Emulated(range) => range.as_ref().size(),
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
    pub size: usize,
    pub type_: MemRegionType,
}

pub trait MemRegionCallback: Debug + Send + Sync + 'static {
    fn mapped(&self, addr: usize) -> Result<()>;
    fn unmapped(&self) -> Result<()> {
        log::debug!("{} unmapped", type_name::<Self>());
        Ok(())
    }
}

#[derive(Debug)]
pub struct MemRegion {
    pub size: usize,
    pub ranges: Vec<MemRange>,
    pub entries: Vec<MemRegionEntry>,
    pub callbacks: Mutex<Vec<Box<dyn MemRegionCallback>>>,
}

impl MemRegion {
    pub fn with_mapped(pages: ArcMemPages, type_: MemRegionType) -> MemRegion {
        let size = pages.size();
        MemRegion {
            size,
            ranges: vec![MemRange::Mapped(pages)],
            entries: vec![MemRegionEntry { type_, size }],
            callbacks: Mutex::new(vec![]),
        }
    }

    pub fn with_emulated(range: MmioRange, type_: MemRegionType) -> MemRegion {
        let size = range.as_ref().size();
        MemRegion {
            size,
            ranges: vec![MemRange::Emulated(range)],
            entries: vec![MemRegionEntry { type_, size }],
            callbacks: Mutex::new(vec![]),
        }
    }

    pub fn validate(&self) -> Result<()> {
        let entries_size = self.entries.iter().fold(0, |accu, e| accu + e.size);
        if entries_size != self.size {
            return Err(Error::MemRegionEntryMismatch);
        }
        let ranges_size = self.ranges.iter().fold(0, |accu, r| accu + r.size());
        if ranges_size > self.size {
            return Err(Error::MemRangeMismatch);
        }
        Ok(())
    }
}

impl SlotBackend for Arc<MemRegion> {
    fn size(&self) -> usize {
        self.size
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
    fn size(&self) -> usize {
        self.range.as_ref().size()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AddrOpt {
    Any,
    Fixed(usize),
    Below4G,
    Above4G,
}

#[derive(Debug)]
pub struct GpaRegion {
    pub region: Arc<MemRegion>,
    pub slots: Vec<u32>,
}

impl SlotBackend for GpaRegion {
    fn size(&self) -> usize {
        self.region.size
    }
}

#[derive(Debug)]
pub struct Memory {
    pub(super) vm_memory: VmMemory,
    regions: RwLock<Addressable<GpaRegion>>,
    #[cfg(target_arch = "x86_64")]
    pub(super) io_ports: RwLock<Addressable<Arc<IoRegion>>>,
    next_slot_id: AtomicU32,
    max_mem_slots: u32,
}

pub struct MemoryReadGuard<'a> {
    _guard: RwLockReadGuard<'a, Addressable<GpaRegion>>,
}

impl<'a> MemoryReadGuard<'a> {
    fn get_mapped_pages(&self, gpa: usize) -> Result<(ArcMemPages, usize)> {
        let Some((start, gpa_region)) = self._guard.search(gpa) else {
            return Err(Error::NotMapped(gpa));
        };
        let offset = gpa - start;
        let mut cur_offset = 0;
        for range in &gpa_region.region.ranges {
            if offset >= cur_offset && offset < cur_offset + range.size() {
                match range {
                    MemRange::Mapped(pages) => {
                        return Ok((pages.clone(), offset - cur_offset));
                    }
                    _ => return Err(Error::NotContinuous),
                }
            }
            cur_offset += range.size();
        }
        Err(Error::NotMapped(gpa))
    }

    pub fn read<T>(&self, gpa: usize) -> Result<T>
    where
        T: FromBytes + AsBytes,
    {
        let (pages, offset) = self.get_mapped_pages(gpa)?;
        pages.read(offset)
    }

    pub fn write<T>(&self, gpa: usize, val: &T) -> Result<()>
    where
        T: AsBytes,
    {
        let (pages, offset) = self.get_mapped_pages(gpa)?;
        pages.write(offset, val)
    }

    pub fn get_ref<T>(&self, gpa: usize) -> Result<&UnsafeCell<T>> {
        let (pages, offset) = self.get_mapped_pages(gpa)?;
        let total_len = size_of::<T>();
        if offset + total_len > pages.size() {
            return Err(Error::OutOfRange { addr: gpa, size: total_len });
        }
        let host_ref = pages.get_partial_slice(offset, total_len)?;
        let ptr = host_ref.as_ptr() as *const UnsafeCell<T>;
        if host_ref.len() != total_len {
            Err(Error::NotContinuous)
        } else if ptr as usize & (align_of::<T>() - 1) != 0 {
            Err(Error::NotAligned)
        } else {
            Ok(unsafe { &*ptr })
        }
    }

    pub fn get_slice<T>(&self, gpa: usize, len: usize) -> Result<&[UnsafeCell<T>]> {
        let (pages, offset) = self.get_mapped_pages(gpa)?;
        let total_len = len * size_of::<T>();
        if offset + total_len > pages.size() {
            return Err(Error::OutOfRange { addr: gpa, size: total_len });
        }
        let host_ref = pages.get_partial_slice(offset, total_len)?;
        let ptr = host_ref.as_ptr() as *const UnsafeCell<T>;
        if host_ref.len() != total_len {
            Err(Error::NotContinuous)
        } else if ptr as usize & (align_of::<T>() - 1) != 0 {
            Err(Error::NotAligned)
        } else {
            Ok(unsafe { &*core::ptr::slice_from_raw_parts(ptr, len) })
        }
    }

    pub fn translate_iov(&self, iov: &[(usize, usize)]) -> Result<Vec<IoSlice<'_>>> {
        let mut slices = vec![];
        for (gpa, len) in iov {
            let (pages, offset) = self.get_mapped_pages(*gpa)?;
            if offset + *len > pages.size() {
                return Err(Error::OutOfRange { addr: *gpa, size: *len });
            }
            let slice = unsafe { std::slice::from_raw_parts((pages.addr() + offset) as *const u8, *len) };
            slices.push(IoSlice::new(slice));
        }
        Ok(slices)
    }

    pub fn translate_iov_mut(&self, iov: &[(usize, usize)]) -> Result<Vec<IoSliceMut<'_>>> {
        let mut slices = vec![];
        for (gpa, len) in iov {
            let (pages, offset) = self.get_mapped_pages(*gpa)?;
            if offset + *len > pages.size() {
                return Err(Error::OutOfRange { addr: *gpa, size: *len });
            }
            let slice = unsafe { std::slice::from_raw_parts_mut((pages.addr() + offset) as *mut u8, *len) };
            slices.push(IoSliceMut::new(slice));
        }
        Ok(slices)
    }

    pub fn read_range(&self, gpa: usize, len: usize, mut dst: impl Write) -> Result<()> {
        let (pages, offset) = self.get_mapped_pages(gpa)?;
        if offset + len > pages.size() {
            return Err(Error::OutOfRange { addr: gpa, size: len });
        }
        let slice = pages.get_partial_slice(offset, len)?;
        dst.write_all(slice)?;
        Ok(())
    }

    pub fn write_range(&self, gpa: usize, len: usize, mut src: impl Read) -> Result<()> {
        let (pages, offset) = self.get_mapped_pages(gpa)?;
        if offset + len > pages.size() {
            return Err(Error::OutOfRange { addr: gpa, size: len });
        }
        let slice = pages.get_partial_slice_mut(offset, len)?;
        src.read_exact(slice)?;
        Ok(())
    }

    pub fn read_vectored<T, F>(&self, bufs: &[(usize, usize)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&[IoSlice<'_>]) -> T,
    {
        let mut iov = vec![];
        for (gpa, len) in bufs {
            let (pages, offset) = self.get_mapped_pages(*gpa)?;
            if offset + *len > pages.size() {
                return Err(Error::OutOfRange { addr: *gpa, size: *len });
            }
            let slice = unsafe { std::slice::from_raw_parts((pages.addr() + offset) as *const u8, *len) };
            iov.push(IoSlice::new(slice));
        }
        Ok(callback(&iov))
    }

    pub fn write_vectored<T, F>(&self, bufs: &[(usize, usize)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&mut [IoSliceMut<'_>]) -> T,
    {
        let mut iov = vec![];
        for (gpa, len) in bufs {
            let (pages, offset) = self.get_mapped_pages(*gpa)?;
            if offset + *len > pages.size() {
                return Err(Error::OutOfRange { addr: *gpa, size: *len });
            }
            let slice = unsafe { std::slice::from_raw_parts_mut((pages.addr() + offset) as *mut u8, *len) };
            iov.push(IoSliceMut::new(slice));
        }
        Ok(callback(&mut iov))
    }
}

impl Memory {
    pub fn new(vm_memory: VmMemory) -> Self {
        let max_mem_slots = match vm_memory.max_mem_slots() {
            Ok(val) => val,
            Err(e) => {
                log::error!(
                    "quering hypervisor for maximum supported memory slots, got error {e:?}"
                );
                log::error!(
                    "assuming the maximum supported memory slots is {:#x}",
                    u16::MAX
                );
                u16::MAX as u32
            }
        };
        Memory {
            vm_memory,
            regions: RwLock::new(Addressable::new()),
            #[cfg(target_arch = "x86_64")]
            io_ports: RwLock::new(Addressable::new()),
            next_slot_id: AtomicU32::new(0),
            max_mem_slots,
        }
    }

    pub fn lock_layout(&self) -> MemoryReadGuard<'_> {
        MemoryReadGuard {
            _guard: self.regions.read(),
        }
    }

    pub fn reset(&self) -> Result<()> {
        self.clear()?;
        self.next_slot_id.store(0, Ordering::Relaxed);
        Ok(())
    }

    fn alloc(
        regions: &mut Addressable<GpaRegion>,
        addr: AddrOpt,
        region: GpaRegion,
    ) -> Result<usize> {
        match addr {
            AddrOpt::Fixed(addr) => {
                regions.add(addr, region)?;
                Ok(addr)
            }
            AddrOpt::Any | AddrOpt::Above4G => {
                let align = std::cmp::max(region.size().next_power_of_two(), PAGE_SIZE);
                regions.add_within(MEM_64_START, usize::MAX, align, region)
            }
            AddrOpt::Below4G => {
                let align = std::cmp::max(region.size().next_power_of_two(), PAGE_SIZE);
                regions.add_within(MMIO_32_START, MMIO_32_END - 1, align, region)
            }
        }
    }

    pub fn add_region(&self, addr: AddrOpt, region: Arc<MemRegion>) -> Result<usize> {
        region.validate()?;
        let mut regions = self.regions.write();
        
        let gpa_region = GpaRegion {
            region: region.clone(),
            slots: Vec::new(),
        };
        let addr = Self::alloc(&mut regions, addr, gpa_region)?;
        
        let (inserted_addr, inserted_gpa_region) = regions.search_mut(addr).ok_or(Error::NotMapped(addr))?;
        assert_eq!(inserted_addr, addr);
        
        let mut offset = 0;
        for range in &region.ranges {
            match range {
                MemRange::Mapped(pages) => {
                    let slot_id = self.next_slot_id.fetch_add(1, Ordering::AcqRel) % self.max_mem_slots;
                    let mem_options = hv::MemMapOption {
                        read: true,
                        write: true,
                        exec: true,
                        log_dirty: false,
                    };
                    self.vm_memory.mem_map(
                        slot_id,
                        addr + offset,
                        pages.size(),
                        pages.addr(),
                        mem_options,
                    )?;
                    inserted_gpa_region.slots.push(slot_id);
                }
                MemRange::Emulated(_) | MemRange::Span(_) => {}
            }
            offset += range.size();
        }
        
        let callbacks = region.callbacks.lock();
        for callback in callbacks.iter() {
            callback.mapped(addr)?;
        }
        Ok(addr)
    }

    fn unmap_region(&self, addr: usize, gpa_region: &GpaRegion) -> Result<()> {
        let mut slot_idx = 0;
        let mut offset = 0;
        for range in &gpa_region.region.ranges {
            match range {
                MemRange::Mapped(pages) => {
                    let slot_id = gpa_region.slots[slot_idx];
                    self.vm_memory.unmap(slot_id, addr + offset, pages.size())?;
                    slot_idx += 1;
                }
                MemRange::Emulated(_) | MemRange::Span(_) => {}
            }
            offset += range.size();
        }
        let callbacks = gpa_region.region.callbacks.lock();
        for callback in callbacks.iter() {
            callback.unmapped()?;
        }
        Ok(())
    }

    pub fn remove_region(&self, addr: usize) -> Result<Arc<MemRegion>> {
        let mut regions = self.regions.write();
        let gpa_region = regions.remove(addr)?;
        self.unmap_region(addr, &gpa_region)?;
        Ok(gpa_region.region)
    }

    fn clear(&self) -> Result<()> {
        let mut regions = self.regions.write();
        let regions_drain = regions.drain(..);
        for (addr, gpa_region) in regions_drain {
            self.unmap_region(addr, &gpa_region)?;
        }
        #[cfg(target_arch = "x86_64")]
        {
            let mut io_ports = self.io_ports.write();
            let io_ports_drain = io_ports.drain(..);
            for (port, io_region) in io_ports_drain {
                self.unmap_io_region(port as u16, &io_region)?;
            }
        }
        Ok(())
    }

    pub fn mem_region_entries(&self) -> Vec<(usize, MemRegionEntry)> {
        let mut entries = vec![];
        let regions = self.regions.read();
        for (start, gpa_region) in regions.iter() {
            let mut offset = 0;
            for entry in gpa_region.region.entries.iter() {
                entries.push((start + offset, *entry));
                offset += entry.size;
            }
        }
        entries
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_io_dev(&self, port: Option<u16>, dev: MmioRange) -> Result<u16, Error> {
        self.add_io_region(port, Arc::new(IoRegion::new(dev)))
    }

    #[cfg(target_arch = "x86_64")]
    pub fn add_io_region(&self, port: Option<u16>, region: Arc<IoRegion>) -> Result<u16, Error> {
        let mut io_ports = self.io_ports.write();
        let port_val = port.unwrap() as usize;
        io_ports.add(port_val, region.clone())?;
        let callbacks = region.callbacks.lock();
        for callback in callbacks.iter() {
            callback.mapped(port_val)?;
        }
        Ok(port_val as u16)
    }

    #[cfg(target_arch = "x86_64")]
    fn unmap_io_region(&self, _port: u16, region: &IoRegion) -> Result<()> {
        let callbacks = region.callbacks.lock();
        for callback in callbacks.iter() {
            callback.unmapped()?;
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn remove_io_region(&self, port: u16) -> Result<Arc<IoRegion>> {
        let mut io_ports = self.io_ports.write();
        let io_region = io_ports.remove(port as usize)?;
        self.unmap_io_region(port, &io_region)?;
        Ok(io_region)
    }

    // RAM access methods delegating to MemoryReadGuard
    pub fn read<T>(&self, gpa: usize) -> Result<T>
    where
        T: FromBytes + AsBytes,
    {
        let guard = self.lock_layout();
        guard.read(gpa)
    }

    pub fn write<T>(&self, gpa: usize, val: &T) -> Result<()>
    where
        T: AsBytes,
    {
        let guard = self.lock_layout();
        guard.write(gpa, val)
    }

    pub fn read_range(&self, gpa: usize, len: usize, dst: impl Write) -> Result<()> {
        let guard = self.lock_layout();
        guard.read_range(gpa, len, dst)
    }

    pub fn write_range(&self, gpa: usize, len: usize, src: impl Read) -> Result<()> {
        let guard = self.lock_layout();
        guard.write_range(gpa, len, src)
    }

    pub fn read_vectored<T, F>(&self, bufs: &[(usize, usize)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&[IoSlice<'_>]) -> T,
    {
        let guard = self.lock_layout();
        guard.read_vectored(bufs, callback)
    }

    pub fn write_vectored<T, F>(&self, bufs: &[(usize, usize)], callback: F) -> Result<T, Error>
    where
        F: FnOnce(&mut [IoSliceMut<'_>]) -> T,
    {
        let guard = self.lock_layout();
        guard.write_vectored(bufs, callback)
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
            Action::Shutdown => Ok(VmEntry::Shutdown),
            Action::ChangeLayout { callback } => {
                callback.change(self)?;
                Ok(VmEntry::None)
            }
        }
    }

    pub fn handle_mmio(&self, gpa: usize, write: Option<u64>, size: u8) -> Result<VmEntry> {
        let regions = self.regions.read();
        let Some((start, gpa_region)) = regions.search(gpa) else {
            return Ok(VmEntry::None);
        };
        let offset = gpa - start;
        let mut cur_offset = 0;
        for range in &gpa_region.region.ranges {
            if offset >= cur_offset && offset < cur_offset + range.size() {
                match range {
                    MemRange::Emulated(dev) => {
                        let dev_offset = offset - cur_offset;
                        if let Some(val) = write {
                            match dev.write(dev_offset, size, val) {
                                Ok(()) => return Ok(VmEntry::None),
                                Err(Error::Action(action)) => return self.handle_action(action),
                                Err(e) => return Err(e),
                            }
                        } else {
                            let val = dev.read(dev_offset, size)?;
                            return Ok(VmEntry::Mmio { data: val });
                        }
                    }
                    _ => return Err(Error::NotContinuous),
                }
            }
            cur_offset += range.size();
        }
        Ok(VmEntry::None)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn handle_io(&self, port: u16, write: Option<u32>, size: u8) -> Result<VmEntry> {
        if port == 0x600 || port == 0x601 {
            log::warn!("port = {port:#x}, val = {write:#x?}, size = {size}");
            if write == Some(0x34) {
                return Ok(VmEntry::Shutdown);
            }
        }
        if port == 0x604 && write == Some(0x1) {
            return Ok(VmEntry::Reboot);
        }
        
        let io_ports = self.io_ports.read();
        let Some((start, io_region)) = io_ports.search(port as usize) else {
            return Ok(VmEntry::None);
        };
        let offset = port as usize - start;
        if let Some(val) = write {
            match io_region.range.write(offset, size, val as u64) {
                Ok(()) => Ok(VmEntry::None),
                Err(Error::Action(action)) => self.handle_action(action),
                Err(e) => Err(e),
            }
        } else {
            let data = io_region.range.read(offset, size)? as u32;
            Ok(VmEntry::Io { data })
        }
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::mem::size_of;
    use std::ptr::null_mut;

    use libc::{MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_READ, PROT_WRITE, mmap, munmap};
    use zerocopy::{AsBytes, FromBytes, FromZeroes};

    use crate::hv::VmMemory;
    use crate::mem::mmio::Mmio;
    use crate::mem::{AddrOpt, MMIO_32_START, MemRegion, MemRegionType, Memory, Result, ArcMemPages};

    #[derive(Debug, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
    #[repr(C)]
    struct MyStruct {
        data: [u32; 8],
    }

    const PAGE_SIZE: usize = 1 << 12;

    #[test]
    fn test_memory_ram_read() {
        let memory = Memory::new(VmMemory::new_fake());
        let prot = PROT_READ | PROT_WRITE;
        let size = 3 * PAGE_SIZE;
        let addr = unsafe { mmap(null_mut(), size, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0) };
        assert_ne!(addr, MAP_FAILED);
        let munmap_ret = unsafe { munmap(addr.add(PAGE_SIZE), PAGE_SIZE) };
        assert_ne!(munmap_ret, -1);
        let mem1 = ArcMemPages::new_raw(addr, PAGE_SIZE);
        let mem2_addr = unsafe { addr.add(2 * PAGE_SIZE) };
        let mem2 = ArcMemPages::new_raw(mem2_addr, PAGE_SIZE);

        let region1 = Arc::new(MemRegion::with_mapped(mem1, MemRegionType::Ram));
        let region2 = Arc::new(MemRegion::with_mapped(mem2, MemRegionType::Ram));

        memory.add_region(AddrOpt::Fixed(0x0), region1).unwrap();
        memory.add_region(AddrOpt::Fixed(PAGE_SIZE), region2).unwrap();

        let data = MyStruct {
            data: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let data_size = size_of::<MyStruct>();
        for gpa in (PAGE_SIZE - data_size)..=PAGE_SIZE {
            if gpa < PAGE_SIZE && gpa + data_size > PAGE_SIZE {
                assert!(memory.write(gpa, &data).is_err());
            } else {
                memory.write(gpa, &data).unwrap();
                let r: MyStruct = memory.read(gpa).unwrap();
                assert_eq!(r, data)
            }
        }
    }

    #[test]
    fn test_memory_add_remove() {
        #[derive(Debug)]
        struct TestMmio {
            size: usize,
        }

        impl Mmio for TestMmio {
            fn read(&self, _offset: usize, _size: u8) -> Result<u64> {
                Ok(0)
            }
            fn write(&self, _offset: usize, _size: u8, _val: u64) -> Result<()> {
                Ok(())
            }
            fn size(&self) -> usize {
                self.size
            }
        }

        let memory = Memory::new(VmMemory::new_fake());
        assert_eq!(
            memory
                .add_region(
                    AddrOpt::Below4G,
                    Arc::new(MemRegion::with_emulated(
                        Arc::new(TestMmio { size: 0x1000 }),
                        MemRegionType::Reserved
                    )),
                )
                .unwrap(),
            MMIO_32_START
        );
        assert_eq!(
            memory
                .add_region(
                    AddrOpt::Below4G,
                    Arc::new(MemRegion::with_emulated(
                        Arc::new(TestMmio { size: 0x1000 }),
                        MemRegionType::Reserved
                    )),
                )
                .unwrap(),
            MMIO_32_START + 0x1000,
        );
        memory.remove_region(MMIO_32_START).unwrap();

        assert_eq!(
            memory
                .add_region(
                    AddrOpt::Below4G,
                    Arc::new(MemRegion::with_emulated(
                        Arc::new(TestMmio { size: 0x1000 }),
                        MemRegionType::Reserved
                    )),
                )
                .unwrap(),
            MMIO_32_START,
        );
    }
}
