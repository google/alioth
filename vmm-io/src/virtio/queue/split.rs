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
use std::sync::atomic::{Ordering, fence};

use bitflags::bitflags;
use derive_layout::Layout;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::host::{GuestMemAccess, VirtioQueueConfig};
use crate::virtio::queue::{Descriptor, LockedQueue, QueueGuard, VirtQueue};
use crate::virtio::{Error, Result, VirtioFeature};

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
#[derive(Debug, Clone, Default, Layout, FromBytes, FromZeroes, AsBytes)]
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
#[derive(Debug, Clone, Default, Layout, FromBytes, FromZeroes, AsBytes)]
pub struct UsedHeader {
    flags: u16,
    idx: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Default, FromBytes, FromZeroes, AsBytes)]
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
    pub memory: Arc<dyn GuestMemAccess>,
    register: Register,
}

struct SplitQueueGuard<'q> {
    memory: &'q dyn GuestMemAccess,
    register: &'q Register,
}

struct SplitLayout<'g> {
    memory: &'g dyn GuestMemAccess,
    queue_size: u16,

    avail_gpa: u64,
    avail_ring_gpa: u64,
    used_event_gpa: Option<u64>,

    used_gpa: u64,
    used_ring_gpa: u64,
    avail_event_gpa: Option<u64>,
    used_index: u16,

    desc_gpa: u64,
}

impl<'g> SplitLayout<'g> {
    pub fn avail_index(&self) -> u16 {
        self.memory
            .read::<AvailHeader>(self.avail_gpa)
            .expect("read AvailHeader")
            .idx
    }

    pub fn set_used_index(&self) {
        self.memory
            .write(
                self.used_gpa + UsedHeader::OFFSET_IDX as u64,
                &self.used_index,
            )
            .expect("write UsedHeader.idx");
    }

    pub fn used_event(&self) -> Option<u16> {
        self.used_event_gpa
            .map(|gpa| self.memory.read::<u16>(gpa).expect("read used_event"))
    }

    pub fn set_avail_event(&self, index: u16) -> Option<()> {
        self.avail_event_gpa
            .map(|gpa| self.memory.write(gpa, &index).expect("write avail_event"))
    }

    pub fn set_flag_notification(&self, enabled: bool) {
        let flags: u16 = (!enabled) as u16;
        self.memory
            .write(self.used_gpa + UsedHeader::OFFSET_FLAGS as u64, &flags)
            .expect("write UsedHeader.flags");
    }

    pub fn flag_interrupt_enabled(&self) -> bool {
        self.memory
            .read::<AvailHeader>(self.avail_gpa)
            .expect("read AvailHeader")
            .flags
            == 0
    }

    pub fn read_avail(&self, index: u16) -> u16 {
        let wrapped_index = (index & (self.queue_size - 1)) as usize;
        let gpa = self.avail_ring_gpa + (wrapped_index * size_of::<u16>()) as u64;
        self.memory.read::<u16>(gpa).expect("read avail_ring")
    }

    pub fn get_desc(&self, id: u16) -> Result<Desc> {
        if id >= self.queue_size {
            return Err(Error::InvalidDescriptor(id));
        }
        let gpa = self.desc_gpa + (id as usize * size_of::<Desc>()) as u64;
        Ok(self.memory.read::<Desc>(gpa)?)
    }

    fn get_indirect(
        &self,
        addr: u64,
        readable: &mut Vec<(u64, usize)>,
        writeable: &mut Vec<(u64, usize)>,
    ) -> Result<()> {
        let mut id = 0;
        loop {
            let desc: Desc = self.memory.read(addr + (id * size_of::<Desc>()) as u64)?;
            let flag = DescFlag::from_bits_retain(desc.flag);
            assert!(!flag.contains(DescFlag::INDIRECT));
            if flag.contains(DescFlag::WRITE) {
                writeable.push((desc.addr, desc.len as usize));
            } else {
                readable.push((desc.addr, desc.len as usize));
            }
            if flag.contains(DescFlag::NEXT) {
                id = desc.next as usize;
            } else {
                return Ok(());
            }
        }
    }

    #[allow(clippy::type_complexity)]
    pub fn get_desc_iov(&self, mut id: u16) -> Result<(Vec<(u64, usize)>, Vec<(u64, usize)>)> {
        let mut readable = Vec::new();
        let mut writeable = Vec::new();
        loop {
            let desc = self.get_desc(id)?;
            let flag = DescFlag::from_bits_retain(desc.flag);
            if flag.contains(DescFlag::INDIRECT) {
                assert_eq!(desc.len & 0xf, 0);
                self.get_indirect(desc.addr, &mut readable, &mut writeable)?;
            } else if flag.contains(DescFlag::WRITE) {
                writeable.push((desc.addr, desc.len as usize));
            } else {
                readable.push((desc.addr, desc.len as usize));
            }
            if flag.contains(DescFlag::NEXT) {
                id = desc.next;
            } else {
                break;
            }
        }
        Ok((readable, writeable))
    }

    fn get_next_desc(&self) -> Result<Option<Descriptor>> {
        if self.used_index == self.avail_index() {
            return Ok(None);
        }
        let desc_id = self.read_avail(self.used_index);
        let (readable_gpas, writable_gpas) = self.get_desc_iov(desc_id)?;
        let mut readable = Vec::with_capacity(readable_gpas.len());
        for (gpa, len) in readable_gpas {
            let mut buf = vec![0u8; len];
            self.memory.read_bytes(gpa, &mut buf)?;
            readable.push(buf);
        }
        let mut writable = Vec::with_capacity(writable_gpas.len());
        for &(_gpa, len) in &writable_gpas {
            writable.push(vec![0u8; len]);
        }
        Ok(Some(Descriptor {
            id: desc_id,
            readable,
            writable,
            writable_gpas,
        }))
    }
}

impl<'g> LockedQueue<'g> for SplitLayout<'g> {
    fn next_desc(&self) -> Option<Result<Descriptor>> {
        self.get_next_desc().transpose()
    }

    fn has_next_desc(&self) -> bool {
        self.used_index != self.avail_index()
    }

    fn push_used(&mut self, desc: Descriptor, len: usize) -> u16 {
        if desc.writable.len() == 1 {
            let (gpa, _) = desc.writable_gpas[0];
            let buf = &desc.writable[0];
            let write_len = std::cmp::min(len, buf.len());
            if write_len > 0 {
                self.memory
                    .write_bytes(gpa, &buf[..write_len])
                    .expect("write used descriptor buffer");
            }
        } else {
            for ((gpa, _), buf) in desc.writable_gpas.iter().zip(desc.writable.iter()) {
                self.memory
                    .write_bytes(*gpa, buf)
                    .expect("write used descriptor buffer");
            }
        }
        let used_index = self.used_index;
        let used_elem = UsedElem {
            id: desc.id as u32,
            len: len as u32,
        };
        let wrapped_index = (used_index & (self.queue_size - 1)) as usize;
        let elem_gpa = self.used_ring_gpa + (wrapped_index * size_of::<UsedElem>()) as u64;
        self.memory
            .write(elem_gpa, &used_elem)
            .expect("write UsedElem");
        fence(Ordering::SeqCst);
        self.used_index = used_index.wrapping_add(1);
        self.set_used_index();
        used_index
    }

    fn enable_notification(&self, enabled: bool) {
        if self.avail_event_gpa.is_some() {
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

impl<'q> QueueGuard for SplitQueueGuard<'q> {
    fn queue(&self) -> Result<impl LockedQueue<'_>> {
        let mut avail_event_gpa = None;
        let mut used_event_gpa = None;
        let queue_size = self.register.size as usize;
        if self.register.feature.contains(VirtioFeature::EVENT_IDX) {
            let avail_ev_gpa = self.register.used
                + (size_of::<UsedHeader>() + queue_size * size_of::<UsedElem>()) as u64;
            avail_event_gpa = Some(avail_ev_gpa);
            let used_ev_gpa = self.register.avail
                + (size_of::<AvailHeader>() + queue_size * size_of::<u16>()) as u64;
            used_event_gpa = Some(used_ev_gpa);
        }
        let used_hdr = self.memory.read::<UsedHeader>(self.register.used)?;
        let used_index = used_hdr.idx;
        let avail_ring_gpa = self.register.avail + size_of::<AvailHeader>() as u64;
        let used_ring_gpa = self.register.used + size_of::<UsedHeader>() as u64;
        Ok(SplitLayout {
            memory: self.memory,
            queue_size: self.register.size,
            avail_gpa: self.register.avail,
            avail_ring_gpa,
            used_event_gpa,
            used_gpa: self.register.used,
            used_index,
            used_ring_gpa,
            avail_event_gpa,
            desc_gpa: self.register.desc,
        })
    }
}

impl SplitQueue {
    pub fn new(
        cfg: &VirtioQueueConfig,
        memory: Arc<dyn GuestMemAccess>,
        feature: u64,
    ) -> Self {
        let register = if cfg.enabled {
            Register {
                size: cfg.size,
                desc: cfg.desc_gpa,
                avail: cfg.avail_gpa,
                used: cfg.used_gpa,
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

    fn lock_ram_layout(&self) -> impl QueueGuard {
        SplitQueueGuard {
            memory: self.memory.as_ref(),
            register: &self.register,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Arc;

    use super::{AvailHeader, Desc, DescFlag, SplitQueue, UsedElem, UsedHeader};
    use crate::host::{GuestMemAccess, VirtioQueueConfig};
    use crate::sync::Mutex;
    use crate::virtio::VirtioFeature;
    use crate::virtio::queue::{LockedQueue, QueueGuard, VirtQueue};

    #[derive(Debug)]
    struct MockGuestMem {
        buf: Mutex<Vec<u8>>,
    }

    impl MockGuestMem {
        fn new(size: usize) -> Self {
            Self {
                buf: Mutex::new(vec![0u8; size]),
            }
        }
    }

    impl GuestMemAccess for MockGuestMem {
        fn read_bytes(&self, gpa: u64, dst: &mut [u8]) -> io::Result<()> {
            let b = self.buf.lock();
            let start = gpa as usize;
            dst.copy_from_slice(&b[start..start + dst.len()]);
            Ok(())
        }

        fn write_bytes(&self, gpa: u64, src: &[u8]) -> io::Result<()> {
            let mut b = self.buf.lock();
            let start = gpa as usize;
            b[start..start + src.len()].copy_from_slice(src);
            Ok(())
        }
    }

    #[test]
    fn test_split_queue_pop_and_push_used() {
        let mem: Arc<dyn GuestMemAccess> = Arc::new(MockGuestMem::new(0x10000));
        let desc_gpa = 0x1000u64;
        let avail_gpa = 0x2000u64;
        let used_gpa = 0x3000u64;

        // Write a 2-descriptor chain (desc 0 -> readable, desc 1 -> writable)
        let d0 = Desc {
            addr: 0x4000,
            len: 16,
            flag: DescFlag::NEXT.bits(),
            next: 1,
        };
        let d1 = Desc {
            addr: 0x5000,
            len: 32,
            flag: DescFlag::WRITE.bits(),
            next: 0,
        };
        mem.write(desc_gpa, &d0).unwrap();
        mem.write(desc_gpa + size_of::<Desc>() as u64, &d1).unwrap();
        mem.write_bytes(0x4000, &[0xabu8; 16]).unwrap();

        // Make descriptor chain 0 available at avail_idx = 1
        mem.write(avail_gpa, &AvailHeader { flags: 0, idx: 1 })
            .unwrap();
        mem.write(avail_gpa + size_of::<AvailHeader>() as u64, &0u16)
            .unwrap();

        let qcfg = VirtioQueueConfig {
            size: 8,
            enabled: true,
            desc_gpa,
            avail_gpa,
            used_gpa,
        };
        let sq = SplitQueue::new(&qcfg, mem.clone(), VirtioFeature::EVENT_IDX.bits());
        let guard = sq.lock_ram_layout();
        let mut q = guard.queue().unwrap();

        let mut desc = q.next_desc().unwrap().unwrap();
        assert_eq!(desc.id, 0);
        assert_eq!(desc.readable.len(), 1);
        assert_eq!(desc.readable[0].as_slice(), &[0xabu8; 16]);
        assert_eq!(desc.writable.len(), 1);
        assert_eq!(desc.writable[0].len(), 32);
        desc.writable[0].fill(0xcd);

        let used_idx = q.push_used(desc, 32);
        assert_eq!(used_idx, 0);

        let used_hdr: UsedHeader = mem.read(used_gpa).unwrap();
        assert_eq!(used_hdr.idx, 1);
        let used_elem: UsedElem = mem.read(used_gpa + size_of::<UsedHeader>() as u64).unwrap();
        assert_eq!(used_elem.id, 0);
        assert_eq!(used_elem.len, 32);

        let mut written = [0u8; 32];
        mem.read_bytes(0x5000, &mut written).unwrap();
        assert_eq!(&written, &[0xcdu8; 32]);
    }
}
