// Copyright 2025 Google LLC
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

use std::marker::PhantomData;
use std::sync::atomic::Ordering;

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::consts;
use crate::mem::mapped::Ram;
use crate::virtio::Result;
use crate::virtio::queue::{DescChain, DescFlag, QueueReg, VirtQueue};

#[repr(C, align(16))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
struct Desc {
    pub addr: u64,
    pub len: u32,
    pub id: u16,
    pub flag: u16,
}

bitfield! {
    #[derive(Copy, Clone, Default, PartialEq, Eq, Hash)]
    pub struct WrappedIndex(u16);
    impl Debug;
    pub u16, offset, set_offset : 14, 0;
    pub wrap_counter, set_warp_counter: 15;
}

impl WrappedIndex {
    const INIT: WrappedIndex = WrappedIndex(1 << 15);

    fn wrapping_add(&self, delta: u16, size: u16) -> WrappedIndex {
        let mut offset = self.offset() + delta;
        let mut wrap_counter = self.wrap_counter();
        if offset >= size {
            offset -= size;
            wrap_counter = !wrap_counter;
        }
        let mut r = WrappedIndex(offset);
        r.set_warp_counter(wrap_counter);
        r
    }

    fn wrapping_sub(&self, delta: u16, size: u16) -> WrappedIndex {
        let mut offset = self.offset();
        let mut wrap_counter = self.wrap_counter();
        if offset >= delta {
            offset -= delta;
        } else {
            offset += size - delta;
            wrap_counter = !wrap_counter;
        }
        let mut r = WrappedIndex(offset);
        r.set_warp_counter(wrap_counter);
        r
    }
}

consts! {
    struct EventFlag(u16) {
        ENABLE = 0;
        DISABLE = 1;
        DESC = 2;
    }
}

struct DescEvent {
    index: WrappedIndex,
    flag: EventFlag,
}

#[derive(Debug)]
pub struct PackedQueue<'m> {
    size: u16,
    desc: *mut Desc,
    enable_event_idx: bool,
    notification: *mut DescEvent,
    interrupt: *mut DescEvent,
    _phantom: PhantomData<&'m ()>,
}

impl<'m> PackedQueue<'m> {
    pub fn new(reg: &QueueReg, ram: &'m Ram, event_idx: bool) -> Result<Option<PackedQueue<'m>>> {
        if !reg.enabled.load(Ordering::Acquire) {
            return Ok(None);
        }
        let size = reg.size.load(Ordering::Acquire);
        let desc = reg.desc.load(Ordering::Acquire);
        let notification: *mut DescEvent = ram.get_ptr(reg.device.load(Ordering::Acquire))?;
        Ok(Some(PackedQueue {
            size,
            desc: ram.get_ptr(desc)?,
            enable_event_idx: event_idx,
            notification,
            interrupt: ram.get_ptr(reg.driver.load(Ordering::Acquire))?,
            _phantom: PhantomData,
        }))
    }

    fn flag_is_avail(&self, flag: DescFlag, wrap_counter: bool) -> bool {
        flag.contains(DescFlag::AVAIL) == wrap_counter
            && flag.contains(DescFlag::USED) != wrap_counter
    }

    fn set_flag_used(&self, flag: &mut DescFlag, wrap_counter: bool) {
        if wrap_counter {
            flag.insert(DescFlag::USED | DescFlag::AVAIL);
        } else {
            flag.remove(DescFlag::USED | DescFlag::AVAIL);
        }
    }
}

impl<'m> VirtQueue<'m> for PackedQueue<'m> {
    type Index = WrappedIndex;

    const INIT_INDEX: WrappedIndex = WrappedIndex::INIT;

    fn desc_avail(&self, index: WrappedIndex) -> bool {
        self.flag_is_avail(
            DescFlag::from_bits_retain(unsafe { &*self.desc.offset(index.offset() as isize) }.flag),
            index.wrap_counter(),
        )
    }

    fn get_avail(&self, index: Self::Index, ram: &'m Ram) -> Result<Option<DescChain<'m>>> {
        if !self.desc_avail(index) {
            return Ok(None);
        }
        let mut readable = Vec::new();
        let mut writeable = Vec::new();
        let mut delta = 0;
        let mut offset = index.offset();
        let id = loop {
            let desc = unsafe { &*self.desc.offset(offset as isize) };
            let flag = DescFlag::from_bits_retain(desc.flag);
            if flag.contains(DescFlag::INDIRECT) {
                for i in 0..(desc.len as usize / size_of::<Desc>()) {
                    let addr = desc.addr + (i * size_of::<Desc>()) as u64;
                    let desc: Desc = ram.read_t(addr)?;
                    let flag = DescFlag::from_bits_retain(desc.flag);
                    if flag.contains(DescFlag::WRITE) {
                        writeable.push((desc.addr, desc.len as u64));
                    } else {
                        readable.push((desc.addr, desc.len as u64));
                    }
                }
            } else if flag.contains(DescFlag::WRITE) {
                writeable.push((desc.addr, desc.len as u64));
            } else {
                readable.push((desc.addr, desc.len as u64));
            }
            delta += 1;
            if !flag.contains(DescFlag::NEXT) {
                break desc.id;
            }
            offset = (offset + 1) % self.size;
        };
        Ok(Some(DescChain {
            id,
            delta,
            readable: ram.translate_iov(&readable)?,
            writable: ram.translate_iov_mut(&writeable)?,
        }))
    }

    fn set_used(&self, index: Self::Index, id: u16, len: u32) {
        let first = unsafe { &mut *self.desc.offset(index.offset() as isize) };
        first.id = id;
        first.len = len;
        let mut flag = DescFlag::from_bits_retain(first.flag);
        self.set_flag_used(&mut flag, index.wrap_counter());
        first.flag = flag.bits();
    }

    fn enable_notification(&self, enabled: bool) {
        unsafe {
            (&mut *self.notification).flag = if enabled {
                EventFlag::ENABLE
            } else {
                EventFlag::DISABLE
            };
        }
    }

    fn interrupt_enabled(&self, index: Self::Index, delta: u16) -> bool {
        let interrupt = unsafe { &*self.interrupt };
        if self.enable_event_idx && interrupt.flag == EventFlag::DESC {
            let prev_used_index = index.wrapping_sub(delta, self.size);
            let base = prev_used_index.offset();
            let end = base + delta;
            let mut offset = interrupt.index.offset();
            if interrupt.index.wrap_counter() != prev_used_index.wrap_counter() {
                offset += self.size;
            }
            base <= offset && offset < end
        } else {
            interrupt.flag == EventFlag::ENABLE
        }
    }

    fn index_add(&self, index: Self::Index, delta: u16) -> Self::Index {
        index.wrapping_add(delta, self.size)
    }
}

#[cfg(test)]
#[path = "packed_test.rs"]
mod tests;
