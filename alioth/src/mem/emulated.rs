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

use std::cmp::min;
use std::fmt::Debug;
use std::sync::Arc;

use crate::mem::addressable::{Addressable, SlotBackend};
use crate::mem::{Memory, Result};
use crate::utils::truncate_u64;

#[cfg(not(test))]
pub trait ChangeLayout: Debug + Send + Sync + 'static {
    fn change(&self, memory: &Memory) -> Result<()>;
}
#[cfg(test)]
pub trait ChangeLayout: Debug + Send + Sync + std::any::Any + 'static {
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

impl Mmio for Arc<dyn Mmio> {
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

impl SlotBackend for Arc<dyn Mmio> {
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
                fn read_from_prefix<T: ::zerocopy::FromBytes + Into<u64>>(
                    bytes: &[u8],
                ) -> ::core::option::Option<u64> {
                    let (n, _) = T::read_from_prefix(bytes).ok()?;
                    Some(n.into())
                }

                let bytes = ::zerocopy::IntoBytes::as_bytes(self);
                let offset = offset as usize;
                let val = match size {
                    1 => bytes.get(offset).map(|b| *b as u64),
                    2 => bytes.get(offset..).and_then(read_from_prefix::<u16>),
                    4 => bytes.get(offset..).and_then(read_from_prefix::<u32>),
                    8 => bytes.get(offset..).and_then(read_from_prefix::<u64>),
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
pub struct MmioBus<R = Arc<dyn Mmio>>
where
    R: Debug + SlotBackend,
{
    pub(crate) inner: Addressable<R>,
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
            inner: Addressable::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn add(&mut self, addr: u64, range: R) -> Result<()> {
        self.inner.add(addr, range)?;
        Ok(())
    }

    pub(super) fn remove(&mut self, addr: u64) -> Result<R> {
        self.inner.remove(addr)
    }

    pub fn read(&self, addr: u64, size: u8) -> Result<u64> {
        let mut count = 0;
        let mut val = 0;
        let size = size as u64;
        while count < size {
            let base_addr = addr + count;
            let Some((start, dev)) = self.inner.search_next(base_addr) else {
                break;
            };
            count += start.saturating_sub(base_addr);
            let offset = base_addr.saturating_sub(start);
            let mut read_size = min(Mmio::size(dev) - offset, size.saturating_sub(count));
            if read_size == 0 {
                break;
            }
            read_size = min(read_size, 1 << read_size.trailing_zeros());
            if offset > 0 {
                read_size = min(read_size, 1 << offset.trailing_zeros());
            }
            val |= truncate_u64(dev.read(offset, read_size as u8)?, read_size) << (count << 3);
            count += read_size;
        }
        Ok(val)
    }

    pub fn write(&self, addr: u64, size: u8, val: u64) -> Result<Action> {
        let mut count = 0;
        let size = size as u64;
        let mut action = Action::None;
        while count < size {
            let base_addr = addr + count;
            let Some((start, dev)) = self.inner.search_next(base_addr) else {
                break;
            };
            count += start.saturating_sub(base_addr);
            let offset = base_addr.saturating_sub(start);
            let mut write_size = min(Mmio::size(dev) - offset, size.saturating_sub(count));
            if write_size == 0 {
                break;
            }
            write_size = min(write_size, 1 << write_size.trailing_zeros());
            if offset > 0 {
                write_size = min(write_size, 1 << offset.trailing_zeros());
            }
            let write_val = truncate_u64(val >> (count << 3), write_size);
            let r = dev.write(offset, write_size as u8, write_val)?;
            if matches!(action, Action::None) {
                action = r
            } else {
                // TODO: handle multiple side effects caused by a single write
                log::error!(
                    "Write {write_val:#x} to {:#x}: dropped: {action:#x?}",
                    start + offset
                );
            }
            count += write_size;
        }
        Ok(action)
    }
}

#[cfg(test)]
#[path = "emulated_test.rs"]
mod tests;
