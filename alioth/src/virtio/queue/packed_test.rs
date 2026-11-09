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
use std::mem::size_of;
use std::sync::atomic::{AtomicU16, Ordering};

use assert_matches::assert_matches;
use rstest::rstest;

use crate::mem;
use crate::mem::mapped::Ram;
use crate::virtio::Error;
use crate::virtio::queue::packed::{Desc, DescEvent, EventFlag, PackedQueue, WrappedIndex};
use crate::virtio::queue::tests::{GuestQueue, UsedDesc, VirtQueueGuest};
use crate::virtio::queue::{DescFlag, VirtQueue};
use crate::virtio::tests::{DATA_ADDR, MEM_SIZE, QUEUE_SIZE, fixture_queues, fixture_ram_bus};

const WRAP_COUNTER: u16 = 1 << 15;

#[rstest]
#[case(3, 0, 1, 1)]
#[case(5, 4, 4, WRAP_COUNTER | 3)]
#[case(3, WRAP_COUNTER, 1, WRAP_COUNTER | 1)]
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
#[case(3, WRAP_COUNTER | 1, 1, WRAP_COUNTER)]
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

impl<'m> PackedQueue<'m> {
    fn flag_is_used(&self, flag: DescFlag, wrap_counter: bool) -> bool {
        flag.contains(DescFlag::AVAIL) == wrap_counter
            && flag.contains(DescFlag::USED) == wrap_counter
    }
}

impl<'m> VirtQueueGuest<'m> for PackedQueue<'m> {
    fn add_desc(
        &mut self,
        index: WrappedIndex,
        ids: &[u16],
        readable: &[(u64, u32)],
        writable: &[(u64, u32)],
    ) -> u16 {
        let writable_count = writable.len();
        let total_count = readable.len() + writable.len();
        let id = ids[0];
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
            desc.flag.store(flag.bits(), Ordering::Release);
        }
        ids.len() as u16
    }

    fn get_used(
        &mut self,
        index: Self::Index,
        chains: &HashMap<u16, Vec<u16>>,
    ) -> Option<UsedDesc> {
        let desc = unsafe { &*self.desc.offset(index.offset() as isize) };
        let flag = DescFlag::from_bits_retain(desc.flag.load(Ordering::Acquire));
        if !self.flag_is_used(flag, index.wrap_counter()) {
            return None;
        }
        Some(UsedDesc {
            id: desc.id,
            len: desc.len,
            delta: chains[&desc.id].len() as u16,
        })
    }

    fn notification_enabled(&self) -> bool {
        let flag = EventFlag(unsafe { &*self.notification }.flag.load(Ordering::Relaxed));
        flag != EventFlag::DISABLE
    }

    fn enable_interrupt(&mut self, enabled: bool, index: Self::Index) {
        let flag = if !enabled {
            EventFlag::DISABLE
        } else if self.enable_event_idx {
            EventFlag::DESC
        } else {
            EventFlag::ENABLE
        };
        let interrupt = unsafe { &*self.interrupt };
        interrupt.index.store(index.0, Ordering::Relaxed);
        interrupt.flag.store(flag.raw(), Ordering::Release);
    }
}

#[test]
fn disabled_queue() {
    let ram_bus = fixture_ram_bus();
    let queues = fixture_queues(1);
    let ram = ram_bus.lock_layout();
    let reg = &queues[0];
    reg.enabled.store(false, Ordering::Relaxed);
    let split_queue = PackedQueue::new(reg, &ram, false);
    assert_matches!(split_queue, Ok(None));
}

#[rstest]
#[case(0, false)]
#[case(1 << 15, true)]
#[case((1 << 15) + 1, false)]
#[case(u16::MAX, false)]
fn queue_size(#[case] size: u16, #[case] valid: bool) {
    let ram_bus = fixture_ram_bus();
    let queues = fixture_queues(1);
    let ram = ram_bus.lock_layout();
    let reg = &queues[0];

    reg.size.store(size, Ordering::Relaxed);
    let packed_queue = PackedQueue::new(reg, &ram, false);
    if valid {
        assert_matches!(packed_queue, Ok(Some(_)));
    } else {
        assert_matches!(packed_queue, Err(Error::InvalidQueueSize { size: s, .. }) if s == size);
    }
}

#[rstest]
#[case(QUEUE_SIZE, true)]
#[case(QUEUE_SIZE - 1, false)]
#[case(1, false)]
fn ring_at_end_of_memory(#[case] entries: u16, #[case] valid: bool) {
    let ram_bus = fixture_ram_bus();
    let queues = fixture_queues(1);
    let ram = ram_bus.lock_layout();
    let reg = &queues[0];

    // Place the ring so that only its first `entries` descriptors are in
    // guest memory.
    let ring_size = entries as u64 * size_of::<Desc>() as u64;
    reg.desc
        .store(MEM_SIZE as u64 - ring_size, Ordering::Relaxed);

    let packed_queue = PackedQueue::new(reg, &ram, false);
    if valid {
        assert_matches!(packed_queue, Ok(Some(_)));
    } else {
        assert_matches!(
            packed_queue,
            Err(Error::Memory { source, .. }) if matches!(*source, mem::Error::NotContinuous { .. })
        );
    }
}

#[test]
fn chain_longer_than_ring() {
    let ram_bus = fixture_ram_bus();
    let queues = fixture_queues(1);
    let ram = ram_bus.lock_layout();
    let reg = &queues[0];
    reg.size.store(4, Ordering::Relaxed);
    let q = PackedQueue::new(reg, &ram, false).unwrap().unwrap();

    // Every descriptor is available and links to the next one, so the chain
    // never ends.
    for offset in 0..4 {
        let desc = unsafe { &*q.desc.offset(offset) };
        let flag = DescFlag::AVAIL | DescFlag::NEXT;
        desc.flag.store(flag.bits(), Ordering::Release);
    }
    assert_matches!(
        q.get_avail(WrappedIndex::INIT, &ram),
        Err(Error::DescChainTooLong { size: 4, .. })
    );
}

const TABLE_ADDR: u64 = DATA_ADDR + 0x1000;

/// Makes descriptor `offset` of the ring available.
fn set_avail_desc(q: &PackedQueue, offset: u16, addr: u64, len: u32, flag: DescFlag) {
    let desc = unsafe { &mut *q.desc.offset(offset as isize) };
    desc.addr = addr;
    desc.len = len;
    desc.flag
        .store((flag | DescFlag::AVAIL).bits(), Ordering::Release);
}

/// Writes an indirect table of `num` readable descriptors.
fn write_indirect_table(ram: &Ram, num: u16) {
    let table = ram.get_array_ptr::<Desc>(TABLE_ADDR, num as u64).unwrap();
    for i in 0..num as usize {
        let desc = Desc {
            addr: DATA_ADDR,
            len: 1,
            ..Default::default()
        };
        unsafe { table.add(i).write(desc) };
    }
}

#[rstest]
#[case::with_next(DescFlag::INDIRECT | DescFlag::NEXT, DescFlag::empty())]
#[case::after_next(DescFlag::NEXT, DescFlag::INDIRECT)]
fn unexpected_indirect_desc(#[case] flag_0: DescFlag, #[case] flag_1: DescFlag) {
    let ram_bus = fixture_ram_bus();
    let queues = fixture_queues(1);
    let ram = ram_bus.lock_layout();
    let q = PackedQueue::new(&queues[0], &ram, false).unwrap().unwrap();

    write_indirect_table(&ram, 1);
    // Descriptors 0 and 1 form a list, which has an indirect descriptor.
    for (offset, flag) in [(0, flag_0), (1, flag_1)] {
        let (addr, len) = if flag.contains(DescFlag::INDIRECT) {
            (TABLE_ADDR, size_of::<Desc>() as u32)
        } else {
            (DATA_ADDR, 1)
        };
        set_avail_desc(&q, offset, addr, len, flag);
    }
    assert_matches!(
        q.get_avail(WrappedIndex::INIT, &ram),
        Err(Error::UnexpectedIndirectDesc { .. })
    );
}

#[rstest]
#[case(4, true)]
#[case(5, false)]
#[case(u32::MAX / size_of::<Desc>() as u32, false)]
fn indirect_table_len(#[case] num: u32, #[case] valid: bool) {
    let ram_bus = fixture_ram_bus();
    let queues = fixture_queues(1);
    let ram = ram_bus.lock_layout();
    let reg = &queues[0];
    reg.size.store(4, Ordering::Relaxed);
    let q = PackedQueue::new(reg, &ram, false).unwrap().unwrap();

    write_indirect_table(&ram, 5);
    let len = num * size_of::<Desc>() as u32;
    set_avail_desc(&q, 0, TABLE_ADDR, len, DescFlag::INDIRECT);
    let chain = q.get_avail(WrappedIndex::INIT, &ram);
    if valid {
        assert_matches!(chain, Ok(Some(c)) if c.readable.len() == num as usize);
    } else {
        assert_matches!(chain, Err(Error::DescChainTooLong { size: 4, .. }));
    }
}

#[test]
fn enabled_queue() {
    let ram_bus = fixture_ram_bus();
    let queues = fixture_queues(1);
    let ram = ram_bus.lock_layout();
    let reg = &queues[0];
    let q = PackedQueue::new(reg, &ram, false).unwrap().unwrap();
    let mut guest_q = GuestQueue::new(PackedQueue::new(reg, &ram, false).unwrap().unwrap(), reg);

    let str_0 = "Hello, World!";
    let str_1 = "Goodbye, World!";
    let str_2 = "Bose-Einstein condensate";
    let addr_0 = DATA_ADDR;
    let addr_1 = addr_0 + str_0.len() as u64;
    let addr_2 = addr_1 + str_1.len() as u64;
    ram.write(addr_0, str_0.as_bytes()).unwrap();
    ram.write(addr_1, str_1.as_bytes()).unwrap();

    let mut avail_index = WrappedIndex::INIT;
    let mut used_index = WrappedIndex::INIT;

    let id = guest_q.add_desc(
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );
    assert!(q.desc_avail(avail_index));
    let chain = q.get_avail(avail_index, &ram).unwrap().unwrap();
    avail_index = q.index_add(avail_index, chain.delta);
    assert_eq!(chain.id, 0);
    assert_eq!(&*chain.readable[0], str_0.as_bytes());
    assert_eq!(&*chain.readable[1], str_1.as_bytes());
    assert_eq!(chain.writable.len(), 0);

    q.set_used(used_index, chain.id, 0);
    used_index = q.index_add(used_index, chain.delta);

    assert_eq!(avail_index, WrappedIndex(WRAP_COUNTER | 2));
    assert_matches!(q.get_avail(avail_index, &ram), Ok(None));
    let used = guest_q.get_used().unwrap();
    assert_eq!(used.id, id);
    assert_eq!(used.delta, 2);
    assert_eq!(used.len, 0);

    let id = guest_q.add_desc(&[], &[(addr_2, str_2.len() as u32)]);
    let mut chain = q.get_avail(avail_index, &ram).unwrap().unwrap();
    assert_eq!(chain.id, 2);
    assert_eq!(chain.readable.len(), 0);
    let buffer = chain.writable[0].as_mut();
    buffer.copy_from_slice(str_2.as_bytes());
    q.set_used(used_index, chain.id, str_2.len() as u32);

    let used = guest_q.get_used().unwrap();
    assert_eq!(used.id, id);
    assert_eq!(used.delta, 1);
    assert_eq!(used.len, str_2.len() as u32);

    let mut b = vec![0u8; str_2.len()];
    ram.read(addr_2, b.as_mut()).unwrap();
    assert_eq!(&b, str_2.as_bytes());
}

#[test]
fn enable_notification() {
    let ram_bus = fixture_ram_bus();
    let queues = fixture_queues(1);
    let ram = ram_bus.lock_layout();
    let reg = &queues[0];
    let q = PackedQueue::new(reg, &ram, false).unwrap().unwrap();

    q.enable_notification(false);
    assert_eq!(
        unsafe { &*q.notification }.flag.load(Ordering::Acquire),
        EventFlag::DISABLE.raw()
    );
    q.enable_notification(true);
    assert_eq!(
        unsafe { &*q.notification }.flag.load(Ordering::Acquire),
        EventFlag::ENABLE.raw()
    );
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
#[case(true, EventFlag::DESC, WRAP_COUNTER, 2, 3, false)]
#[case(true, EventFlag::DESC, WRAP_COUNTER | (QUEUE_SIZE - 1), 2, 2, false)]
#[case(true, EventFlag::DESC, WRAP_COUNTER | (QUEUE_SIZE - 1), 2, 3, true)]
#[case(true, EventFlag::DESC, QUEUE_SIZE - 1, WRAP_COUNTER | 1, 1, false)]
#[case(true, EventFlag::DESC, QUEUE_SIZE - 1, WRAP_COUNTER | 1, 2, true)]
fn is_interrupt_enabled(
    #[case] enable_event_idx: bool,
    #[case] event_flag: EventFlag,
    #[case] event_index: u16,
    #[case] used_index: u16,
    #[case] delta: u16,
    #[case] expected: bool,
) {
    let ram_bus = fixture_ram_bus();
    let queues = fixture_queues(1);
    let ram = ram_bus.lock_layout();
    let reg = &queues[0];
    let q = PackedQueue::new(reg, &ram, enable_event_idx)
        .unwrap()
        .unwrap();

    *unsafe { &mut *q.interrupt } = DescEvent {
        index: AtomicU16::new(event_index),
        flag: AtomicU16::new(event_flag.raw()),
    };

    assert_eq!(
        q.interrupt_enabled(WrappedIndex(used_index), delta),
        expected
    );
}
