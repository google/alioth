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
use crate::virtio::queue::packed::{DescEvent, EventFlag, PackedQueue, WrappedIndex};
use crate::virtio::queue::private::VirtQueuePrivate;
use crate::virtio::queue::tests::VirtQueueGuest;
use crate::virtio::queue::{DescFlag, QueueReg, VirtQueue};
use crate::virtio::tests::{DATA_ADDR, QUEUE_SIZE, fixture_queue, fixture_ram_bus};

const WRAP_COUNTER: u16 = 1 << 15;

#[rstest]
#[case(3, 0, 1, 1)]
#[case(5, 4, 4, WRAP_COUNTER | 3)]
#[case(3, WRAP_COUNTER | 0, 1, WRAP_COUNTER | 1)]
#[case(5, WRAP_COUNTER | 4, 1, 0)]
fn index_wrapping_add(
    #[case] size: u16,
    #[case] index: u16,
    #[case] delta: u16,
    #[case] expected: u16,
) {
    assert_eq!(
        WrappedIndex(index).wrapping_add(delta, size),
        WrappedIndex(expected)
    );
}

#[rstest]
#[case(3, 1, 1, 0)]
#[case(5, WRAP_COUNTER | 3, 4, 4)]
#[case(3, WRAP_COUNTER | 1, 1, WRAP_COUNTER | 0)]
#[case(5, 0, 1, WRAP_COUNTER | 4)]
fn index_wrapping_sub(
    #[case] size: u16,
    #[case] index: u16,
    #[case] delta: u16,
    #[case] expected: u16,
) {
    assert_eq!(
        WrappedIndex(index).wrapping_sub(delta, size),
        WrappedIndex(expected)
    );
}

impl<'r, 'm> VirtQueueGuest<'m> for PackedQueue<'r, 'm> {
    fn add_desc(
        &mut self,
        index: WrappedIndex,
        id: u16,
        readable: &[(u64, u32)],
        writable: &[(u64, u32)],
    ) {
        let writable_count = writable.len();
        let total_count = readable.len() + writable.len();
        for (i, (addr, len)) in readable.iter().chain(writable).rev().enumerate() {
            let index = index.wrapping_add((total_count - 1 - i) as u16, self.size);
            let mut flag = if index.wrap_counter() {
                DescFlag::AVAIL
            } else {
                DescFlag::USED
            };
            if i > 0 {
                flag |= DescFlag::NEXT;
            }
            if i < writable_count {
                flag |= DescFlag::WRITE;
            }
            let desc = unsafe { &mut *self.desc.offset(index.offset() as isize) };
            desc.addr = *addr;
            desc.len = *len;
            desc.id = id;
            desc.flag = flag.bits();
        }
    }
}

#[rstest]
fn disabled_queue(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    fixture_queue.enabled.store(false, Ordering::Relaxed);
    let split_queue = PackedQueue::new(&fixture_queue, &*ram, false);
    assert_matches!(split_queue, Ok(None));
}

#[rstest]
fn enabled_queue(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    let mut q = PackedQueue::new(&fixture_queue, &*ram, false)
        .unwrap()
        .unwrap();
    assert!(ptr_eq(q.reg(), &fixture_queue));

    let str_0 = "Hello, World!";
    let str_1 = "Goodbye, World!";
    let str_2 = "Bose-Einstein condensate";
    let addr_0 = DATA_ADDR;
    let addr_1 = addr_0 + str_0.len() as u64;
    let addr_2 = addr_1 + str_1.len() as u64;
    ram.write(addr_0, str_0.as_bytes()).unwrap();
    ram.write(addr_1, str_1.as_bytes()).unwrap();

    let mut avail_index = WrappedIndex::INIT;
    q.add_desc(
        avail_index,
        0,
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );
    assert!(q.desc_avail(avail_index));

    let chain = q.get_desc_chain(avail_index).unwrap().unwrap();
    assert_eq!(chain.id, 0);
    assert_eq!(&*chain.readable[0], str_0.as_bytes());
    assert_eq!(&*chain.readable[1], str_1.as_bytes());
    assert_eq!(chain.writable.len(), 0);
    let next_avail_index = q.next_index(&chain);
    q.push_used(chain, 0);

    assert_eq!(next_avail_index, WrappedIndex(WRAP_COUNTER | 2));
    avail_index = next_avail_index;
    assert_matches!(q.get_desc_chain(avail_index), Ok(None));

    q.add_desc(avail_index, 1, &[], &[(addr_2, str_2.len() as u32)]);
    let mut chain = q.get_desc_chain(avail_index).unwrap().unwrap();
    assert_eq!(chain.id, 1);
    assert_eq!(chain.readable.len(), 0);
    let buffer = chain.writable[0].as_mut();
    buffer.copy_from_slice(str_2.as_bytes());
    q.push_used(chain, str_2.len() as u32);
    let mut b = vec![0u8; str_2.len()];
    ram.read(addr_2, b.as_mut()).unwrap();
    assert_eq!(&b, str_2.as_bytes());
}

#[rstest]
fn enable_notification(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    let q = PackedQueue::new(&fixture_queue, &*ram, false)
        .unwrap()
        .unwrap();

    q.enable_notification(false);
    assert_eq!(unsafe { &*q.notification }.flag, EventFlag::DISABLE);
    q.enable_notification(true);
    assert_eq!(unsafe { &*q.notification }.flag, EventFlag::ENABLE);
}

#[rstest]
#[case(false, EventFlag::DISABLE, 0, 1, 1, false)]
#[case(false, EventFlag::ENABLE, 0, 1, 1, true)]
#[case(false, EventFlag::DESC, 0, 1, 1, false)]
#[case(true, EventFlag::ENABLE, 0, 1, 1, true)]
#[case(true, EventFlag::DISABLE, 0, 1, 1, false)]
#[case(true, EventFlag::DESC, 0, 2, 1, false)]
#[case(true, EventFlag::DESC, 0, 2, 2, true)]
#[case(true, EventFlag::DESC, 0, 2, 3, true)]
#[case(true, EventFlag::DESC, WRAP_COUNTER | 0, 2, 3, false)]
#[case(true, EventFlag::DESC, WRAP_COUNTER | (QUEUE_SIZE - 1), 2, 2, false)]
#[case(true, EventFlag::DESC, WRAP_COUNTER | (QUEUE_SIZE - 1), 2, 3, true)]
#[case(true, EventFlag::DESC, QUEUE_SIZE - 1, WRAP_COUNTER | 1, 1, false)]
#[case(true, EventFlag::DESC, QUEUE_SIZE - 1, WRAP_COUNTER | 1, 2, true)]
fn is_interrupt_enabled(
    fixture_ram_bus: RamBus,
    fixture_queue: QueueReg,
    #[case] enable_event_idx: bool,
    #[case] event_flag: EventFlag,
    #[case] event_index: u16,
    #[case] used_index: u16,
    #[case] delta: u16,
    #[case] expected: bool,
) {
    let ram = fixture_ram_bus.lock_layout();
    let mut q = PackedQueue::new(&fixture_queue, &*ram, enable_event_idx)
        .unwrap()
        .unwrap();
    q.used_index = WrappedIndex(used_index);

    *unsafe { &mut *q.interrupt } = DescEvent {
        index: WrappedIndex(event_index),
        flag: event_flag,
    };

    assert_eq!(q.interrupt_enabled(delta), expected);
}
