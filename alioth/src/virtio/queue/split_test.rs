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

use std::collections::HashMap;
use std::sync::atomic::Ordering;

use assert_matches::assert_matches;
use rstest::rstest;

use crate::mem::mapped::RamBus;
use crate::virtio::queue::split::{Desc, DescFlag, SplitQueue};
use crate::virtio::queue::tests::{GuestQueue, UsedDesc, VirtQueueGuest};
use crate::virtio::queue::{QueueReg, VirtQueue};
use crate::virtio::tests::{DATA_ADDR, fixture_queue, fixture_ram_bus};

impl<'m> VirtQueueGuest<'m> for SplitQueue<'m> {
    fn add_desc(
        &mut self,
        index: u16,
        ids: &[u16],
        readable: &[(u64, u32)],
        writable: &[(u64, u32)],
    ) -> u16 {
        let writable_count = writable.len();
        let ids_r = ids.iter().rev();
        let mut last_id = 0;
        for (i, ((addr, len), id)) in readable.iter().chain(writable).rev().zip(ids_r).enumerate() {
            let mut flag = DescFlag::empty();
            if i > 0 {
                flag |= DescFlag::NEXT;
            }
            if i < writable_count {
                flag |= DescFlag::WRITE;
            }
            let desc = Desc {
                addr: *addr,
                len: *len,
                flag: flag.bits(),
                next: last_id,
            };
            *unsafe { &mut *self.desc.offset(*id as isize) } = desc;
            last_id = *id;
        }
        let avail_idx = self.avail_index();
        assert_eq!(index, avail_idx);
        *unsafe { &mut *self.avail_ring.offset((avail_idx % self.size) as isize) } = last_id;
        unsafe { &mut *self.avail_hdr }.idx = avail_idx.wrapping_add(1);
        1
    }

    fn get_used(&mut self, index: u16, _: &HashMap<u16, Vec<u16>>) -> Option<UsedDesc> {
        let used_idx = unsafe { &mut *self.avail_hdr }.idx;
        if !(index < used_idx || index - used_idx >= !(self.size - 1)) {
            return None;
        }
        let desc = unsafe { &mut *self.used_ring.offset((index % self.size) as isize) };
        let id = desc.id as u16;
        let len = desc.len;
        Some(UsedDesc { id, len, delta: 1 })
    }
}

#[rstest]
fn disabled_queue(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    fixture_queue.enabled.store(false, Ordering::Relaxed);
    let split_queue = SplitQueue::new(&fixture_queue, &*ram, false);
    assert_matches!(split_queue, Ok(None));
}

#[rstest]
fn enabled_queue(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    let q = SplitQueue::new(&fixture_queue, &*ram, false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(
        SplitQueue::new(&fixture_queue, &*ram, false)
            .unwrap()
            .unwrap(),
        &fixture_queue,
    );

    let str_0 = "Hello, World!";
    let str_1 = "Goodbye, World!";
    let str_2 = "Bose-Einstein condensate";
    let addr_0 = DATA_ADDR;
    let addr_1 = addr_0 + str_0.len() as u64;
    let addr_2 = addr_1 + str_1.len() as u64;
    ram.write(addr_0, str_0.as_bytes()).unwrap();
    ram.write(addr_1, str_1.as_bytes()).unwrap();

    let id = guest_q.add_desc(
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );
    assert_eq!(q.avail_index(), 1);
    assert!(q.desc_avail(0));
    let chain = q.get_avail(0, &ram).unwrap().unwrap();
    assert_eq!(chain.id, 0);
    assert_eq!(&*chain.readable[0], str_0.as_bytes());
    assert_eq!(&*chain.readable[1], str_1.as_bytes());
    assert_eq!(chain.writable.len(), 0);
    q.set_used(0, chain.id, 0);
    assert!(!q.desc_avail(1));
    let used = guest_q.get_used().unwrap();
    assert_eq!(used.id, id);
    assert_eq!(used.delta, 1);
    assert_eq!(used.len, 0);

    let id = guest_q.add_desc(&[], &[(addr_2, str_2.len() as u32)]);
    let mut chain = q.get_avail(1, &ram).unwrap().unwrap();
    assert_eq!(chain.id, 2);
    assert_eq!(chain.readable.len(), 0);
    let buffer = chain.writable[0].as_mut();
    buffer.copy_from_slice(str_2.as_bytes());
    q.set_used(1, chain.id, str_2.len() as u32);
    let mut b = vec![0u8; str_2.len()];
    ram.read(addr_2, b.as_mut()).unwrap();
    assert_eq!(&b, str_2.as_bytes());
    let used = guest_q.get_used().unwrap();
    assert_eq!(used.id, id);
    assert_eq!(used.delta, 1);
    assert_eq!(used.len, str_2.len() as u32);
}

#[rstest]
fn event_idx_enabled(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    let q = SplitQueue::new(&fixture_queue, &*ram, true)
        .unwrap()
        .unwrap();
    unsafe { *q.used_event.unwrap() = 1 };
    assert_eq!(q.used_event(), Some(1));

    assert!(q.set_avail_event(|event| *event = 12));
    assert_eq!(unsafe { *q.avail_event.unwrap() }, 12);
}
