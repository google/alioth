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
use std::sync::{Arc, RwLock};

use super::addressable::{Addressable, SlotBackend};
use super::{Error, Result};

pub trait Mmio: Debug {
    fn read(&self, offset: usize, size: u8) -> Result<u64>;
    fn write(&self, offset: usize, size: u8, val: u64) -> Result<()>;
    fn mapped(&self, addr: usize) -> Result<()> {
        log::trace!("{:#x} -> {}", addr, type_name::<Self>());
        Ok(())
    }
    fn unmapped(&self) -> Result<()> {
        log::trace!("{} unmapped", type_name::<Self>());
        Ok(())
    }
    fn size(&self) -> usize;
}

pub type MmioRegion = Arc<dyn Mmio + Send + Sync + 'static>;

impl SlotBackend for MmioRegion {
    fn size(&self) -> usize {
        Mmio::size(self.as_ref())
    }
}

#[derive(Debug)]
pub struct MmioRange {
    limit: usize,
    inner: Addressable<MmioRegion>,
}

impl MmioRange {
    pub fn with_size(size: usize) -> Self {
        assert_ne!(size, 0);
        MmioRange {
            limit: size - 1,
            inner: Addressable::new(),
        }
    }

    fn new() -> Self {
        MmioRange {
            limit: usize::MAX,
            inner: Addressable::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn add(&mut self, offset: usize, dev: MmioRegion) -> Result<&mut MmioRegion> {
        let in_range = (dev.size() - 1)
            .checked_add(offset)
            .map(|max| max <= self.limit);
        match in_range {
            Some(true) => self.inner.add(offset, dev),
            Some(false) | None => Err(Error::OutOfRange {
                addr: offset,
                size: dev.size(),
            }),
        }
    }

    pub fn remove(&mut self, addr: usize) -> Result<MmioRegion> {
        self.inner.remove(addr)
    }

    pub fn read(&self, addr: usize, size: u8) -> Result<u64> {
        match self.inner.search(addr) {
            Some((start, dev)) => dev.read(addr - start, size),
            None => Ok(0),
        }
    }

    pub fn write(&self, addr: usize, size: u8, val: u64) -> Result<()> {
        match self.inner.search(addr) {
            Some((start, dev)) => dev.write(addr - start, size, val),
            None => Ok(()),
        }
    }
}

impl Mmio for MmioRange {
    fn size(&self) -> usize {
        // Overflow happens when limit = usize::MAX, which is only possible when
        // it was constructed through MmioRange::new(). MmioRange::new() is private
        // and only MmioBus uses it.
        self.limit.wrapping_add(1)
    }

    fn read(&self, offset: usize, size: u8) -> Result<u64> {
        self.read(offset, size)
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> Result<()> {
        self.write(offset, size, val)
    }

    fn mapped(&self, addr: usize) -> Result<()> {
        for (offset, range) in self.inner.iter() {
            range.mapped(addr + offset)?;
        }
        Ok(())
    }

    fn unmapped(&self) -> Result<()> {
        for (_, range) in self.inner.iter() {
            range.unmapped()?;
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct MmioBus {
    inner: RwLock<MmioRange>,
}

impl Default for MmioBus {
    fn default() -> Self {
        Self::new()
    }
}

impl MmioBus {
    pub fn new() -> MmioBus {
        Self {
            inner: RwLock::new(MmioRange::new()),
        }
    }

    pub(super) fn add(&self, addr: usize, dev: MmioRegion) -> Result<()> {
        let mut inner = self.inner.write()?;
        let dev = inner.add(addr, dev)?;
        dev.mapped(addr)?;
        Ok(())
    }

    pub(super) fn remove(&self, addr: usize) -> Result<MmioRegion> {
        let mut inner = self.inner.write()?;
        let dev = inner.remove(addr)?;
        dev.unmapped()?;
        Ok(dev)
    }

    pub fn read(&self, addr: usize, size: u8) -> Result<u64> {
        let inner = self.inner.read()?;
        inner.read(addr, size)
    }

    pub fn write(&self, addr: usize, size: u8, val: u64) -> Result<()> {
        let inner = self.inner.read()?;
        inner.write(addr, size, val)
    }
}
