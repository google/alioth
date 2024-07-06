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

use std::cell::UnsafeCell;
use std::mem::size_of;
use std::sync::atomic::{fence, Ordering};
use std::sync::Arc;

use bitflags::bitflags;
use macros::Layout;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::mem::mapped::{RamBus, RamLayoutGuard};
use crate::virtio::queue::{Descriptor, LockedQueue, Queue, QueueGuard, VirtQueue};
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

#[derive(Debug, Clone, Default)]
struct Register {
    pub size: u16,
    pub desc: u64,
    pub avail: u64,
    pub used: u64,
    pub feature: VirtioFeature,
}

#[derive(Debug)]
pub struct SplitQueue {
    pub memory: Arc<RamBus>,
    register: Register,
}

struct SplitQueueGuard<'m, 'q> {
    guard: RamLayoutGuard<'m>,
    register: &'q Register,
}

struct SplitLayout<'g, 'm> {
    guard: &'g RamLayoutGuard<'m>,

    avail: &'g UnsafeCell<AvailHeader>,
    avail_ring: &'g [UnsafeCell<u16>],
    used_event: Option<&'g UnsafeCell<u16>>,

    used: &'g UnsafeCell<UsedHeader>,
    used_ring: &'g [UnsafeCell<UsedElem>],
    avail_event: Option<&'g UnsafeCell<u16>>,
    used_index: u16,

    desc: &'g [UnsafeCell<Desc>],
}

type DescIov = (Vec<(u64, u64)>, Vec<(u64, u64)>);

impl<'g, 'm> SplitLayout<'g, 'm> {
    pub fn avail_index(&self) -> u16 {
        unsafe { &*self.avail.get() }.idx
    }

    pub fn set_used_index(&self) {
        unsafe { &mut *self.used.get() }.idx = self.used_index
    }

    pub fn used_event(&self) -> Option<u16> {
        self.used_event.map(|event| unsafe { *event.get() })
    }

    pub fn set_avail_event(&self, index: u16) -> Option<()> {
        match self.avail_event {
            Some(avail_event) => {
                *unsafe { &mut *avail_event.get() } = index;
                Some(())
            }
            None => None,
        }
    }

    pub fn set_flag_notification(&self, enabled: bool) {
        unsafe { &mut *self.used.get() }.flags = (!enabled) as _;
    }

    pub fn flag_interrupt_enabled(&self) -> bool {
        unsafe { &*self.avail.get() }.flags == 0
    }

    pub fn read_avail(&self, index: u16) -> u16 {
        let wrapped_index = index as usize & (self.avail_ring.len() - 1);
        unsafe { *self.avail_ring.get_unchecked(wrapped_index).get() }
    }

    pub fn get_desc(&self, id: u16) -> Result<&Desc> {
        match self.desc.get(id as usize) {
            Some(desc) => Ok(unsafe { &*desc.get() }),
            None => error::InvalidDescriptor { id }.fail(),
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
            let desc: Desc = self.guard.read(addr + id * size_of::<Desc>() as u64)?;
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

    fn get_next_desc(&self) -> Result<Option<Descriptor<'g>>> {
        if self.used_index == self.avail_index() {
            return Ok(None);
        }
        let desc_id = self.read_avail(self.used_index);
        let (readable, writable) = self.get_desc_iov(desc_id)?;
        let readable = self.guard.translate_iov(&readable)?;
        let writable = self.guard.translate_iov_mut(&writable)?;
        Ok(Some(Descriptor {
            id: desc_id,
            readable,
            writable,
        }))
    }
}

impl<'g, 'm> LockedQueue<'g> for SplitLayout<'g, 'm> {
    fn next_desc(&self) -> Option<Result<Descriptor<'g>>> {
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
        let wrapped_index = used_index as usize & (self.used_ring.len() - 1);
        *unsafe { &mut *self.used_ring.get_unchecked(wrapped_index).get() } = used_elem;
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

impl<'m, 'q> QueueGuard for SplitQueueGuard<'m, 'q> {
    fn queue(&self) -> Result<impl LockedQueue> {
        let mut avail_event = None;
        let mut used_event = None;
        let queue_size = self.register.size as u64;
        if self.register.feature.contains(VirtioFeature::EVENT_IDX) {
            let avail_event_gpa = self.register.used
                + size_of::<UsedHeader>() as u64
                + queue_size * size_of::<UsedElem>() as u64;
            avail_event = Some(self.guard.get_ref(avail_event_gpa)?);
            let used_event_gpa = self.register.avail
                + size_of::<AvailHeader>() as u64
                + queue_size * size_of::<u16>() as u64;
            used_event = Some(self.guard.get_ref(used_event_gpa)?);
        }
        let used = self.guard.get_ref::<UsedHeader>(self.register.used)?;
        let used_index = unsafe { &*used.get() }.idx;
        let avail_ring_gpa = self.register.avail + size_of::<AvailHeader>() as u64;
        let used_ring_gpa = self.register.used + size_of::<UsedHeader>() as u64;
        Ok(SplitLayout {
            guard: &self.guard,
            avail: self.guard.get_ref(self.register.avail)?,
            avail_ring: self.guard.get_slice(avail_ring_gpa, queue_size)?,
            used_event,
            used,
            used_index,
            used_ring: self.guard.get_slice(used_ring_gpa, queue_size)?,
            avail_event,
            desc: self.guard.get_slice(self.register.desc, queue_size)?,
        })
    }
}

impl SplitQueue {
    pub fn new(reg: &Queue, memory: Arc<RamBus>, feature: u64) -> Self {
        let register = if reg.enabled.load(Ordering::Acquire) {
            Register {
                size: reg.size.load(Ordering::Acquire),
                desc: reg.desc.load(Ordering::Acquire),
                avail: reg.driver.load(Ordering::Acquire),
                used: reg.device.load(Ordering::Acquire),
                feature: VirtioFeature::from_bits_retain(feature),
            }
        } else {
            Register::default()
        };
        Self { memory, register }
    }
}

impl VirtQueue for SplitQueue {
    fn size(&self) -> u16 {
        self.register.size
    }

    fn enable_notification(&self, _val: bool) -> Result<()> {
        todo!()
    }

    fn interrupt_enabled(&self) -> Result<bool> {
        todo!()
    }

    fn lock_ram_layout(&self) -> impl QueueGuard {
        let guard = self.memory.lock_layout();
        SplitQueueGuard {
            guard,
            register: &self.register,
        }
    }
}
