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

use std::mem::size_of;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering, fence};

use alioth_macros::Layout;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::bitflags;
use crate::mem::mapped::Ram;
use crate::virtio::queue::{DescChain, DescFlag, QueueReg, RingAddrs, VirtQueue};
use crate::virtio::{Result, error};

#[repr(C, align(16))]
#[derive(Debug, Copy, Clone, Default, FromBytes, Immutable, IntoBytes)]
pub struct Desc {
    pub addr: u64,
    pub len: u32,
    pub flag: u16,
    pub next: u16,
}

bitflags! {
    pub struct AvailFlag(u16) {
        NO_INTERRUPT = 1 << 0;
    }
}

#[repr(C, align(2))]
#[derive(Debug, Layout)]
pub struct AvailHeader {
    flags: AtomicU16,
    idx: AtomicU16,
}

bitflags! {
    pub struct UsedFlag(u16) {
        NO_NOTIFY = 1 << 0;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Layout)]
pub struct UsedHeader {
    flags: AtomicU16,
    idx: AtomicU16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct UsedElem {
    id: u32,
    len: u32,
}

#[derive(Debug)]
pub struct SplitQueue {
    size: u16,
    avail_hdr: *mut AvailHeader,
    avail_ring: *mut u16,
    used_event: Option<*mut AtomicU16>,
    used_hdr: *mut UsedHeader,
    used_ring: *mut UsedElem,
    avail_event: Option<*mut AtomicU16>,
    desc: *mut Desc,
    /// The snapshot the pointers above point into.
    ram: Arc<Ram>,
}

impl SplitQueue {
    pub fn avail_index(&self) -> u16 {
        unsafe { &*self.avail_hdr }.idx.load(Ordering::Acquire)
    }

    pub fn set_used_index(&self, val: u16) {
        unsafe { &*self.used_hdr }.idx.store(val, Ordering::Release)
    }

    pub fn used_event(&self) -> Option<u16> {
        self.used_event
            .map(|event| unsafe { &*event }.load(Ordering::Relaxed))
    }

    pub fn set_avail_event(&self, op: impl FnOnce(&AtomicU16)) -> bool {
        match self.avail_event {
            Some(avail_event) => {
                op(unsafe { &*avail_event });
                true
            }
            None => false,
        }
    }

    pub fn set_flag_notification(&self, enabled: bool) {
        unsafe { &*self.used_hdr }
            .flags
            .store(!enabled as u16, Ordering::Relaxed);
    }

    pub fn flag_interrupt_enabled(&self) -> bool {
        unsafe { &*self.avail_hdr }.flags.load(Ordering::Relaxed) == 0
    }

    fn get_desc(&self, id: u16) -> Result<Desc> {
        if id < self.size {
            Ok(unsafe { self.desc.offset(id as isize).read_volatile() })
        } else {
            error::InvalidDescriptor { id }.fail()
        }
    }

    /// Returns descriptor `id` in the table that `indirect` refers to.
    fn get_indirect_desc(ram: &Ram, indirect: &Desc, id: u16) -> Result<Desc> {
        if (id as u32) < indirect.len / size_of::<Desc>() as u32 {
            let addr = indirect.addr + id as u64 * size_of::<Desc>() as u64;
            Ok(ram.read_t(addr)?)
        } else {
            error::InvalidDescriptor { id }.fail()
        }
    }
}

impl SplitQueue {
    /// Creates the queue from its registers, or returns `None` if the queue
    /// is disabled.
    pub fn new(reg: &QueueReg, ram: &Arc<Ram>, event_idx: bool) -> Result<Option<SplitQueue>> {
        let Some(addrs) = RingAddrs::load(reg) else {
            return Ok(None);
        };
        <SplitQueue as VirtQueue>::new(&addrs, ram, event_idx).map(Some)
    }
}

impl VirtQueue for SplitQueue {
    type Index = u16;

    const INIT_INDEX: u16 = 0;

    fn new(addrs: &RingAddrs, ram: &Arc<Ram>, event_idx: bool) -> Result<Self> {
        let size = addrs.size as u64;
        if size == 0 || !size.is_power_of_two() {
            return error::InvalidQueueSize { size: addrs.size }.fail();
        }
        let used = addrs.device;
        let avail = addrs.driver;
        let mut avail_event = None;
        let mut used_event = None;
        if event_idx {
            let avail_event_gpa =
                used + size_of::<UsedHeader>() as u64 + size * size_of::<UsedElem>() as u64;
            avail_event = Some(ram.get_ptr(avail_event_gpa)?);
            let used_event_gpa =
                avail + size_of::<AvailHeader>() as u64 + size * size_of::<u16>() as u64;
            used_event = Some(ram.get_ptr(used_event_gpa)?);
        }
        let used_hdr = ram.get_ptr::<UsedHeader>(used)?;
        let avail_ring_gpa = avail + size_of::<AvailHeader>() as u64;
        let used_ring_gpa = used + size_of::<UsedHeader>() as u64;
        // The queue accesses entries up to the queue size through the ring
        // pointers, so the whole rings must be in guest memory.
        Ok(SplitQueue {
            size: addrs.size,
            avail_hdr: ram.get_ptr(avail)?,
            avail_ring: ram.get_array_ptr(avail_ring_gpa, size)?,
            used_event,
            used_hdr,
            used_ring: ram.get_array_ptr(used_ring_gpa, size)?,
            avail_event,
            desc: ram.get_array_ptr(addrs.desc, size)?,
            ram: ram.clone(),
        })
    }

    fn ram(&self) -> &Arc<Ram> {
        &self.ram
    }

    fn desc_avail(&self, index: u16) -> bool {
        let avail_index = self.avail_index();
        index < avail_index || index - avail_index >= !(self.size - 1)
    }

    fn get_avail<'m>(&self, index: Self::Index, ram: &'m Ram) -> Result<Option<DescChain<'m>>> {
        if !self.desc_avail(index) {
            return Ok(None);
        }
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        let wrapped_index = index & (self.size - 1);
        let head_id = unsafe {
            self.avail_ring
                .offset(wrapped_index as isize)
                .read_volatile()
        };
        let mut id = head_id;
        // After an indirect descriptor, `id` indexes the table it refers to.
        let mut indirect: Option<Desc> = None;
        loop {
            let desc = match &indirect {
                None => self.get_desc(id)?,
                Some(indirect) => Self::get_indirect_desc(ram, indirect, id)?,
            };
            let flag = DescFlag::from_bits_retain(desc.flag);
            if flag.contains(DescFlag::INDIRECT) {
                // An indirect descriptor ends a chain in the descriptor
                // table, and an indirect table cannot refer to another one
                // (VirtIO spec 1.4, Sec 2.7.5.3.1).
                if flag.contains(DescFlag::NEXT) || indirect.is_some() {
                    return error::UnexpectedIndirectDesc.fail();
                }
                indirect = Some(desc);
                id = 0;
                continue;
            }
            // A chain cannot be longer than the queue size, counting the
            // descriptors in an indirect table (VirtIO spec 1.4, Sec
            // 2.7.5.3.1). This also catches loops in the chain.
            if readable.len() + writable.len() >= self.size as usize {
                return error::DescChainTooLong { size: self.size }.fail();
            }
            if flag.contains(DescFlag::WRITE) {
                writable.push((desc.addr, desc.len as u64));
            } else {
                readable.push((desc.addr, desc.len as u64));
            }
            if !flag.contains(DescFlag::NEXT) {
                break;
            }
            id = desc.next;
        }
        let readable = ram.translate_iov(&readable)?;
        let writable = ram.translate_iov_mut(&writable)?;
        Ok(Some(DescChain {
            id: head_id,
            delta: 1,
            readable,
            writable,
            ram,
        }))
    }

    fn set_used(&self, index: Self::Index, id: u16, len: u32) {
        let used_elem = UsedElem { id: id as u32, len };
        let wrapped_index = index & (self.size - 1);
        unsafe {
            self.used_ring
                .offset(wrapped_index as isize)
                .write_volatile(used_elem);
        }
        self.set_used_index(index.wrapping_add(1));
    }

    fn enable_notification(&self, enabled: bool) {
        if !self.set_avail_event(|event| {
            let mut avail_index = self.avail_index();
            if enabled {
                loop {
                    event.store(avail_index, Ordering::Relaxed);
                    fence(Ordering::SeqCst);
                    let new_avail_index = self.avail_index();
                    if new_avail_index == avail_index {
                        break;
                    } else {
                        avail_index = new_avail_index;
                    }
                }
            } else {
                event.store(avail_index.wrapping_sub(1), Ordering::Relaxed);
            }
        }) {
            self.set_flag_notification(enabled);
        }
    }

    fn interrupt_enabled(&self, index: Self::Index, _: u16) -> bool {
        match self.used_event() {
            Some(used_event) => used_event == index.wrapping_sub(1),
            None => self.flag_interrupt_enabled(),
        }
    }

    fn index_add(&self, index: Self::Index, _: u16) -> Self::Index {
        index.wrapping_add(1)
    }
}

#[cfg(test)]
#[path = "split_test.rs"]
mod tests;
