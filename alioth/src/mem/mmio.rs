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
use std::sync::Arc;

use crate::mem::addressable::{Addressable, SlotBackend};
use crate::mem::Result;
use parking_lot::RwLock;

pub trait Mmio: Debug + Send + Sync + 'static {
    fn read(&self, offset: usize, size: u8) -> Result<u64>;
    fn write(&self, offset: usize, size: u8, val: u64) -> Result<()>;
    fn size(&self) -> usize;
}

pub type MmioRegion = Arc<dyn Mmio>;

impl Mmio for MmioRegion {
    fn read(&self, offset: usize, size: u8) -> Result<u64> {
        Mmio::read(self.as_ref(), offset, size)
    }

    fn write(&self, offset: usize, size: u8, val: u64) -> Result<()> {
        Mmio::write(self.as_ref(), offset, size, val)
    }

    fn size(&self) -> usize {
        Mmio::size(self.as_ref())
    }
}

impl SlotBackend for MmioRegion {
    fn size(&self) -> usize {
        Mmio::size(self.as_ref())
    }
}

#[derive(Debug)]
pub struct MmioBus<R = MmioRegion>
where
    R: Debug + SlotBackend,
{
    inner: RwLock<Addressable<R>>,
}

impl<R> Default for MmioBus<R>
where
    R: Debug + SlotBackend + Mmio,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<R> MmioBus<R>
where
    R: Debug + SlotBackend + Mmio,
{
    pub fn new() -> MmioBus<R> {
        Self {
            inner: RwLock::new(Addressable::new()),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    pub fn add(&self, addr: usize, range: R) -> Result<()> {
        let mut inner = self.inner.write();
        inner.add(addr, range)?;
        Ok(())
    }

    pub(super) fn remove(&self, addr: usize) -> Result<R> {
        let mut inner = self.inner.write();
        inner.remove(addr)
    }

    pub fn read(&self, addr: usize, size: u8) -> Result<u64> {
        let inner = self.inner.read();
        match inner.search(addr) {
            Some((start, dev)) => dev.read(addr - start, size),
            None => Ok(0),
        }
    }

    pub fn write(&self, addr: usize, size: u8, val: u64) -> Result<()> {
        let inner = self.inner.read();
        match inner.search(addr) {
            Some((start, dev)) => dev.write(addr - start, size, val),
            None => Ok(()),
        }
    }
}
