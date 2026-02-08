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

use std::marker::PhantomData;
use std::mem::size_of;
use std::sync::atomic::{Ordering, fence};

use alioth_macros::Layout;
use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::bitflags;
use crate::mem::mapped::Ram;
use crate::virtio::queue::{DescChain, DescFlag, QueueReg, VirtQueue};
use crate::virtio::{Result, error};

#[repr(C, align(16))]
#[derive(Debug, Clone, Default, FromBytes, Immutable, IntoBytes)]
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
#[derive(Debug, Clone, Layout, Immutable, FromBytes, IntoBytes)]
pub struct AvailHeader {
    flags: u16,
    idx: u16,
}

bitflags! {
    pub struct UsedFlag(u16) {
        NO_NOTIFY = 1 << 0;
    }
}

#[repr(C, align(4))]
#[derive(Debug, Clone, Layout)]
pub struct UsedHeader {
    flags: u16,
    idx: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Default)]
pub struct UsedElem {
    id: u32,
    len: u32,
}

#[derive(Debug)]
pub struct SplitQueue<'m> {
    size: u16,
    avail_hdr: *mut AvailHeader,
    avail_ring: *mut u16,
    used_event: Option<*mut u16>,
    used_hdr: *mut UsedHeader,
    used_ring: *mut UsedElem,
    avail_event: Option<*mut u16>,
    desc: *mut Desc,
    _phantom: PhantomData<&'m ()>,
}

impl SplitQueue<'_> {
    pub fn avail_index(&self) -> u16 {
        unsafe { &*self.avail_hdr }.idx
    }

    pub fn set_used_index(&self, val: u16) {
        unsafe { &mut *self.used_hdr }.idx = val;
    }

    pub fn used_event(&self) -> Option<u16> {
        self.used_event.map(|event| unsafe { *event })
    }

    pub fn set_avail_event(&self, op: impl FnOnce(&mut u16)) -> bool {
        match self.avail_event {
            Some(avail_event) => {
                op(unsafe { &mut *avail_event });
                true
            }
            None => false,
        }
    }

    pub fn set_flag_notification(&self, enabled: bool) {
        unsafe { &mut *self.used_hdr }.flags = (!enabled) as _;
    }

    pub fn flag_interrupt_enabled(&self) -> bool {
        unsafe { &*self.avail_hdr }.flags == 0
    }

    fn get_desc(&self, id: u16) -> Result<&Desc> {
        if id < self.size {
            Ok(unsafe { &*self.desc.offset(id as isize) })
        } else {
            error::InvalidDescriptor { id }.fail()
        }
    }
}

impl<'m> SplitQueue<'m> {
    pub fn new(reg: &QueueReg, ram: &'m Ram, event_idx: bool) -> Result<Option<SplitQueue<'m>>> {
        if !reg.enabled.load(Ordering::Acquire) {
            return Ok(None);
        }
        let size = reg.size.load(Ordering::Acquire) as u64;
        let mut avail_event = None;
        let mut used_event = None;
        let used = reg.device.load(Ordering::Acquire);
        let avail = reg.driver.load(Ordering::Acquire);
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
        let desc = reg.desc.load(Ordering::Acquire);
        Ok(Some(SplitQueue {
            size: size as u16,
            avail_hdr: ram.get_ptr(avail)?,
            avail_ring: ram.get_ptr(avail_ring_gpa)?,
            used_event,
            used_hdr,
            used_ring: ram.get_ptr(used_ring_gpa)?,
            avail_event,
            desc: ram.get_ptr(desc)?,
            _phantom: PhantomData,
        }))
    }
}

impl<'m> VirtQueue<'m> for SplitQueue<'m> {
    type Index = u16;

    const INIT_INDEX: u16 = 0;

    fn desc_avail(&self, index: u16) -> bool {
        let avail_index = self.avail_index();
        index < avail_index || index - avail_index >= !(self.size - 1)
    }

    fn get_avail(&self, index: Self::Index, ram: &'m Ram) -> Result<Option<DescChain<'m>>> {
        if !self.desc_avail(index) {
            return Ok(None);
        }
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        let wrapped_index = index & (self.size - 1);
        let head_id = unsafe { *self.avail_ring.offset(wrapped_index as isize) };
        let mut id = head_id;
        loop {
            let desc = self.get_desc(id)?;
            let flag = DescFlag::from_bits_retain(desc.flag);
            if flag.contains(DescFlag::INDIRECT) {
                let mut id = 0;
                loop {
                    let addr = desc.addr + id as u64 * size_of::<Desc>() as u64;
                    let desc: Desc = ram.read_t(addr)?;
                    let flag = DescFlag::from_bits_retain(desc.flag);
                    assert!(!flag.contains(DescFlag::INDIRECT));
                    if flag.contains(DescFlag::WRITE) {
                        writable.push((desc.addr, desc.len as u64));
                    } else {
                        readable.push((desc.addr, desc.len as u64));
                    }
                    if flag.contains(DescFlag::NEXT) {
                        id = desc.next;
                    } else {
                        break;
                    }
                }
            } else if flag.contains(DescFlag::WRITE) {
                writable.push((desc.addr, desc.len as u64));
            } else {
                readable.push((desc.addr, desc.len as u64));
            }
            if flag.contains(DescFlag::NEXT) {
                id = desc.next;
            } else {
                break;
            }
        }
        let readable = ram.translate_iov(&readable)?;
        let writable = ram.translate_iov_mut(&writable)?;
        Ok(Some(DescChain {
            id: head_id,
            delta: 1,
            readable,
            writable,
        }))
    }

    fn set_used(&self, index: Self::Index, id: u16, len: u32) {
        let used_elem = UsedElem { id: id as u32, len };
        let wrapped_index = index & (self.size - 1);
        unsafe { *self.used_ring.offset(wrapped_index as isize) = used_elem };
        fence(Ordering::SeqCst);
        self.set_used_index(index.wrapping_add(1));
    }

    fn enable_notification(&self, enabled: bool) {
        if !self.set_avail_event(|event| {
            let mut avail_index = self.avail_index();
            if enabled {
                loop {
                    *event = avail_index;
                    fence(Ordering::SeqCst);
                    let new_avail_index = self.avail_index();
                    if new_avail_index == avail_index {
                        break;
                    } else {
                        avail_index = new_avail_index;
                    }
                }
            } else {
                *event = avail_index.wrapping_sub(1);
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
