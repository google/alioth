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
use std::sync::atomic::{AtomicU16, Ordering};

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::consts;
use crate::mem::mapped::Ram;
use crate::virtio::queue::{DescChain, DescFlag, QueueReg, VirtQueue};
use crate::virtio::{Result, error};

#[repr(C, align(16))]
#[derive(Debug, Copy, Clone, Default, FromBytes, Immutable, IntoBytes)]
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

#[repr(C)]
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
        let device = reg.device.load(Ordering::Acquire);
        let driver = reg.driver.load(Ordering::Acquire);
        // The registers may be cleared by a concurrent reset, which disables
        // the queue first.
        if !reg.enabled.load(Ordering::Acquire) {
            return Ok(None);
        }
        if size == 0 {
            return error::InvalidQueueSize { size }.fail();
        }
        let notification: *mut DescEvent = ram.get_ptr(device)?;
        Ok(Some(PackedQueue {
            size,
            desc: ram.get_ptr(desc)?,
            enable_event_idx: event_idx,
            notification,
            interrupt: ram.get_ptr(driver)?,
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
        let flag = unsafe {
            AtomicU16::from_ptr(&raw mut (*self.desc.offset(index.offset() as isize)).flag)
                .load(Ordering::Acquire)
        };
        self.flag_is_avail(DescFlag::from_bits_retain(flag), index.wrap_counter())
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
            let desc = unsafe { self.desc.offset(offset as isize).read_volatile() };
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
        unsafe {
            let first = self.desc.offset(index.offset() as isize);
            (&raw mut (*first).id).write_volatile(id);
            (&raw mut (*first).len).write_volatile(len);
            let flag_ptr = AtomicU16::from_ptr(&raw mut (*first).flag);
            let mut flag = DescFlag::from_bits_retain(flag_ptr.load(Ordering::Relaxed));
            self.set_flag_used(&mut flag, index.wrap_counter());
            flag_ptr.store(flag.bits(), Ordering::Release);
        }
    }

    fn enable_notification(&self, enabled: bool) {
        let flag = if enabled {
            EventFlag::ENABLE
        } else {
            EventFlag::DISABLE
        };
        unsafe {
            AtomicU16::from_ptr(&raw mut (*self.notification).flag.0)
                .store(flag.raw(), Ordering::Relaxed);
        }
    }

    fn interrupt_enabled(&self, index: Self::Index, delta: u16) -> bool {
        let flag = EventFlag(unsafe {
            AtomicU16::from_ptr(&raw mut (*self.interrupt).flag.0).load(Ordering::Acquire)
        });
        if self.enable_event_idx && flag == EventFlag::DESC {
            let event_index = WrappedIndex(unsafe {
                AtomicU16::from_ptr(&raw mut (*self.interrupt).index.0).load(Ordering::Relaxed)
            });
            let prev_used_index = index.wrapping_sub(delta, self.size);
            let base = prev_used_index.offset();
            let end = base + delta;
            let mut offset = event_index.offset();
            if event_index.wrap_counter() != prev_used_index.wrap_counter() {
                offset += self.size;
            }
            base <= offset && offset < end
        } else {
            flag == EventFlag::ENABLE
        }
    }

    fn index_add(&self, index: Self::Index, delta: u16) -> Self::Index {
        index.wrapping_add(delta, self.size)
    }
}

#[cfg(test)]
#[path = "packed_test.rs"]
mod tests;
