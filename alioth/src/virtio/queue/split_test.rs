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

use std::ptr::eq as ptr_eq;
use std::sync::atomic::Ordering;

use assert_matches::assert_matches;
use rstest::rstest;

use crate::mem::mapped::RamBus;
use crate::virtio::VirtioFeature;
use crate::virtio::queue::split::{Desc, DescFlag, SplitQueue};
use crate::virtio::queue::{QueueReg, VirtQueue};

use crate::virtio::queue::tests::{DATA_ADDR, QUEUE_SIZE, fixture_queue, fixture_ram_bus};

impl<'r, 'm> SplitQueue<'r, 'm> {
    pub fn add_desc(&mut self, id: u16, readable: &[(u64, u32)], writable: &[(u64, u32)]) {
        let readable_count = readable.len();
        let total_count = readable.len() + writable.len();
        for (i, (addr, len)) in readable.iter().chain(writable.iter()).enumerate() {
            let mut flag = DescFlag::empty();
            if i < total_count - 1 {
                flag |= DescFlag::NEXT;
            }
            if i >= readable_count {
                flag |= DescFlag::WRITE;
            }
            let desc = Desc {
                addr: *addr,
                len: *len,
                flag: flag.bits(),
                next: id + i as u16 + 1,
            };
            *unsafe { &mut *self.desc.offset((id + i as u16) as isize) } = desc;
        }
        let avail_idx = self.avail_index();
        *unsafe { &mut *self.avail_ring.offset((avail_idx % self.size) as isize) } = id;
        unsafe { &mut *self.avail_hdr }.idx = avail_idx.wrapping_add(1);
    }
}

#[rstest]
fn disabled_queue(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    fixture_queue.enabled.store(false, Ordering::Relaxed);
    let split_queue = SplitQueue::new(&fixture_queue, &*ram, 0);
    assert_matches!(split_queue, Ok(None));
}

#[rstest]
fn enabled_queue(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    let mut q = SplitQueue::new(&fixture_queue, &*ram, 0).unwrap().unwrap();
    assert!(ptr_eq(q.reg(), &fixture_queue));
    assert_eq!(q.size(), QUEUE_SIZE);

    let str_0 = "Hello, World!";
    let str_1 = "Goodbye, World!";
    let str_2 = "Bose-Einstein condensate";
    let addr_0 = DATA_ADDR;
    let addr_1 = addr_0 + str_0.len() as u64;
    let addr_2 = addr_1 + str_1.len() as u64;
    ram.write(addr_0, str_0.as_bytes()).unwrap();
    ram.write(addr_1, str_1.as_bytes()).unwrap();

    q.add_desc(
        0,
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );

    assert_eq!(q.avail_index(), 1);
    assert_eq!(q.read_avail(0), 0);
    assert!(q.has_next_desc());
    let chain = q.next_desc_chain().unwrap().unwrap();
    assert_eq!(chain.id, 0);
    assert_eq!(&*chain.readable[0], str_0.as_bytes());
    assert_eq!(&*chain.readable[1], str_1.as_bytes());
    assert_eq!(chain.writable.len(), 0);
    q.push_used(chain, 0);
    assert!(!q.has_next_desc());

    q.add_desc(2, &[], &[(addr_2, str_2.len() as u32)]);
    let mut chain = q.next_desc_chain().unwrap().unwrap();
    assert_eq!(chain.id, 2);
    assert_eq!(chain.readable.len(), 0);
    let buffer = chain.writable[0].as_mut();
    buffer.copy_from_slice(str_2.as_bytes());
    q.push_used(chain, str_2.len());
    let mut b = vec![0u8; str_2.len()];
    ram.read(addr_2, b.as_mut()).unwrap();
    assert_eq!(&b, str_2.as_bytes());
}

#[rstest]
fn event_idx_enabled(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    let q = SplitQueue::new(&fixture_queue, &*ram, VirtioFeature::EVENT_IDX.bits())
        .unwrap()
        .unwrap();
    unsafe { *q.used_event.unwrap() = 1 };
    assert_eq!(q.used_event(), Some(1));

    assert_eq!(q.set_avail_event(12), Some(()));
    assert_eq!(unsafe { *q.avail_event.unwrap() }, 12);
}
