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
use std::sync::atomic::{fence, Ordering};

use bitflags::bitflags;
use macros::Layout;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::mem::mapped::Ram;
use crate::virtio::queue::{Descriptor, Queue, VirtQueue};
use crate::virtio::{error, Result, VirtioFeature};

#[repr(C, align(16))]
#[derive(Debug, Clone, Default, FromBytes, FromZeroes, AsBytes)]
pub struct Desc {
    pub addr: u64,
    pub len: u32,
    pub flag: u16,
    pub next: u16,
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DescFlag: u16 {
        const NEXT = 1;
        const WRITE = 2;
        const INDIRECT = 4;
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AvailFlag: u16 {
        const NO_INTERRUPT = 1;
    }
}

#[repr(C, align(2))]
#[derive(Debug, Clone, Layout)]
pub struct AvailHeader {
    flags: u16,
    idx: u16,
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct UsedFlag: u16 {
        const NO_NOTIFY = 1;
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
    ram: &'m Ram,

    size: u16,

    avail_hdr: *mut AvailHeader,
    avail_ring: *mut u16,
    used_event: Option<*mut u16>,

    used_hdr: *mut UsedHeader,
    used_ring: *mut UsedElem,
    avail_event: Option<*mut u16>,
    used_index: u16,

    desc: *mut Desc,
}

type DescIov = (Vec<(u64, u64)>, Vec<(u64, u64)>);

impl<'m> SplitQueue<'m> {
    pub fn avail_index(&self) -> u16 {
        unsafe { &*self.avail_hdr }.idx
    }

    pub fn set_used_index(&self) {
        unsafe { &mut *self.used_hdr }.idx = self.used_index
    }

    pub fn used_event(&self) -> Option<u16> {
        self.used_event.map(|event| unsafe { *event })
    }

    pub fn set_avail_event(&self, index: u16) -> Option<()> {
        match self.avail_event {
            Some(avail_event) => {
                unsafe { *avail_event = index };
                Some(())
            }
            None => None,
        }
    }

    pub fn set_flag_notification(&self, enabled: bool) {
        unsafe { &mut *self.used_hdr }.flags = (!enabled) as _;
    }

    pub fn flag_interrupt_enabled(&self) -> bool {
        unsafe { &*self.avail_hdr }.flags == 0
    }

    pub fn read_avail(&self, index: u16) -> u16 {
        let wrapped_index = index & (self.size - 1);
        unsafe { *self.avail_ring.offset(wrapped_index as isize) }
    }

    pub fn get_desc(&self, id: u16) -> Result<&Desc> {
        if id < self.size {
            Ok(unsafe { &*self.desc.offset(id as isize) })
        } else {
            error::InvalidDescriptor { id }.fail()
        }
    }

    fn get_indirect(
        &self,
        addr: u64,
        readable: &mut Vec<(u64, u64)>,
        writeable: &mut Vec<(u64, u64)>,
    ) -> Result<()> {
        let mut id = 0;
        loop {
            let desc: Desc = self.ram.read(addr + id * size_of::<Desc>() as u64)?;
            let flag = DescFlag::from_bits_retain(desc.flag);
            assert!(!flag.contains(DescFlag::INDIRECT));
            if flag.contains(DescFlag::WRITE) {
                writeable.push((desc.addr, desc.len as u64));
            } else {
                readable.push((desc.addr, desc.len as u64));
            }
            if flag.contains(DescFlag::NEXT) {
                id = desc.next as u64;
            } else {
                return Ok(());
            }
        }
    }

    pub fn get_desc_iov(&self, mut id: u16) -> Result<DescIov> {
        let mut readable = Vec::new();
        let mut writeable = Vec::new();
        loop {
            let desc = self.get_desc(id)?;
            let flag = DescFlag::from_bits_retain(desc.flag);
            if flag.contains(DescFlag::INDIRECT) {
                assert_eq!(desc.len & 0xf, 0);
                self.get_indirect(desc.addr, &mut readable, &mut writeable)?;
            } else if flag.contains(DescFlag::WRITE) {
                writeable.push((desc.addr, desc.len as u64));
            } else {
                readable.push((desc.addr, desc.len as u64));
            }
            if flag.contains(DescFlag::NEXT) {
                id = desc.next;
            } else {
                break;
            }
        }
        Ok((readable, writeable))
    }

    fn get_next_desc(&self) -> Result<Option<Descriptor<'m>>> {
        if self.used_index == self.avail_index() {
            return Ok(None);
        }
        let desc_id = self.read_avail(self.used_index);
        let (readable, writable) = self.get_desc_iov(desc_id)?;
        let readable = self.ram.translate_iov(&readable)?;
        let writable = self.ram.translate_iov_mut(&writable)?;
        Ok(Some(Descriptor {
            id: desc_id,
            readable,
            writable,
        }))
    }
}

impl<'m> SplitQueue<'m> {
    pub fn new(reg: &Queue, ram: &'m Ram, feature: u64) -> Result<Option<SplitQueue<'m>>> {
        if !reg.enabled.load(Ordering::Acquire) {
            return Ok(None);
        }
        let size = reg.size.load(Ordering::Acquire) as u64;
        let mut avail_event = None;
        let mut used_event = None;
        let feature = VirtioFeature::from_bits_retain(feature);
        let used = reg.device.load(Ordering::Acquire);
        let avail = reg.driver.load(Ordering::Acquire);
        if feature.contains(VirtioFeature::EVENT_IDX) {
            let avail_event_gpa =
                used + size_of::<UsedHeader>() as u64 + size * size_of::<UsedElem>() as u64;
            avail_event = Some(ram.get_ptr(avail_event_gpa)?);
            let used_event_gpa =
                avail + size_of::<AvailHeader>() as u64 + size * size_of::<u16>() as u64;
            used_event = Some(ram.get_ptr(used_event_gpa)?);
        }
        let used_hdr = ram.get_ptr::<UsedHeader>(used)?;
        let used_index = unsafe { &*used_hdr }.idx;
        let avail_ring_gpa = avail + size_of::<AvailHeader>() as u64;
        let used_ring_gpa = used + size_of::<UsedHeader>() as u64;
        let desc = reg.desc.load(Ordering::Acquire);
        Ok(Some(SplitQueue {
            ram,
            size: size as u16,
            avail_hdr: ram.get_ptr(avail)?,
            avail_ring: ram.get_ptr(avail_ring_gpa)?,
            used_event,
            used_hdr,
            used_ring: ram.get_ptr(used_ring_gpa)?,
            avail_event,
            used_index,
            desc: ram.get_ptr(desc)?,
        }))
    }
}

impl<'m> VirtQueue<'m> for SplitQueue<'m> {
    fn size(&self) -> u16 {
        self.size
    }

    fn next_desc(&self) -> Option<Result<Descriptor<'m>>> {
        self.get_next_desc().transpose()
    }

    fn has_next_desc(&self) -> bool {
        self.used_index != self.avail_index()
    }

    fn push_used(&mut self, desc: Descriptor, len: usize) -> u16 {
        let used_index = self.used_index;
        let used_elem = UsedElem {
            id: desc.id as u32,
            len: len as u32,
        };
        let wrapped_index = used_index & (self.size - 1);
        unsafe { *self.used_ring.offset(wrapped_index as isize) = used_elem };
        fence(Ordering::SeqCst);
        self.used_index = used_index.wrapping_add(1);
        self.set_used_index();
        used_index
    }

    fn enable_notification(&self, enabled: bool) {
        if self.avail_event.is_some() {
            let mut avail_index = self.avail_index();
            if enabled {
                loop {
                    self.set_avail_event(avail_index);
                    fence(Ordering::SeqCst);
                    let new_avail_index = self.avail_index();
                    if new_avail_index == avail_index {
                        break;
                    } else {
                        avail_index = new_avail_index;
                    }
                }
            } else {
                self.set_avail_event(avail_index.wrapping_sub(1));
            }
        } else {
            self.set_flag_notification(enabled);
        }
    }

    fn interrupt_enabled(&self) -> bool {
        match self.used_event() {
            Some(used_event) => used_event == self.used_index.wrapping_sub(1),
            None => self.flag_interrupt_enabled(),
        }
    }
}
