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
use crate::mem::{Memory, Result};
use parking_lot::RwLock;

pub trait ChangeLayout: Debug + Send + Sync + 'static {
    fn change(&self, memory: &Memory) -> Result<()>;
}

#[derive(Debug)]
pub enum Action {
    None,
    Shutdown,
    Reset,
    ChangeLayout { callback: Box<dyn ChangeLayout> },
}

pub trait Mmio: Debug + Send + Sync + 'static {
    fn read(&self, offset: u64, size: u8) -> Result<u64>;
    fn write(&self, offset: u64, size: u8, val: u64) -> Result<Action>;
    fn size(&self) -> u64;
}

pub type MmioRange = Arc<dyn Mmio>;

impl Mmio for MmioRange {
    fn read(&self, offset: u64, size: u8) -> Result<u64> {
        Mmio::read(self.as_ref(), offset, size)
    }

    fn write(&self, offset: u64, size: u8, val: u64) -> Result<Action> {
        Mmio::write(self.as_ref(), offset, size, val)
    }

    fn size(&self) -> u64 {
        Mmio::size(self.as_ref())
    }
}

impl SlotBackend for MmioRange {
    fn size(&self) -> u64 {
        Mmio::size(self.as_ref())
    }
}

#[macro_export]
macro_rules! impl_mmio_for_zerocopy {
    ($ty:ident) => {
        impl $crate::mem::emulated::Mmio for $ty {
            fn size(&self) -> u64 {
                ::core::mem::size_of::<Self>() as u64
            }

            fn read(&self, offset: u64, size: u8) -> $crate::mem::Result<u64> {
                let bytes = AsBytes::as_bytes(self);
                let offset = offset as usize;
                let val = match size {
                    1 => bytes.get(offset).map(|b| *b as u64),
                    2 => u16::read_from_prefix(&bytes[offset..]).map(|w| w as u64),
                    4 => u32::read_from_prefix(&bytes[offset..]).map(|d| d as u64),
                    8 => u64::read_from_prefix(&bytes[offset..]),
                    _ => ::core::option::Option::None,
                };
                if let ::core::option::Option::Some(val) = val {
                    ::core::result::Result::Ok(val)
                } else {
                    ::log::error!(
                        "{}: invalid read access, offset = {offset:#x}, size = {size}.",
                        ::core::any::type_name::<Self>()
                    );
                    ::core::result::Result::Ok(0)
                }
            }

            fn write(
                &self,
                offset: u64,
                size: u8,
                val: u64,
            ) -> $crate::mem::Result<$crate::mem::emulated::Action> {
                ::log::error!(
                    "{}: write 0x{val:0width$x} to readonly offset 0x{offset:x}.",
                    ::core::any::type_name::<Self>(),
                    width = 2 * size as usize
                );
                Ok($crate::mem::emulated::Action::None)
            }
        }
    };
}

#[derive(Debug)]
pub struct MmioBus<R = MmioRange>
where
    R: Debug + SlotBackend,
{
    pub(crate) inner: RwLock<Addressable<R>>,
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

    pub fn add(&self, addr: u64, range: R) -> Result<()> {
        let mut inner = self.inner.write();
        inner.add(addr, range)?;
        Ok(())
    }

    pub(super) fn remove(&self, addr: u64) -> Result<R> {
        let mut inner = self.inner.write();
        inner.remove(addr)
    }

    pub fn read(&self, addr: u64, size: u8) -> Result<u64> {
        let inner = self.inner.read();
        match inner.search(addr) {
            Some((start, dev)) => dev.read(addr - start, size),
            None => Ok(0),
        }
    }

    pub fn write(&self, addr: u64, size: u8, val: u64) -> Result<Action> {
        let inner = self.inner.read();
        match inner.search(addr) {
            Some((start, dev)) => dev.write(addr - start, size, val),
            None => Ok(Action::None),
        }
    }
}
