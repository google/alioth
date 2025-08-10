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
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};

use assert_matches::assert_matches;
use rstest::{fixture, rstest};

use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::virtio::VirtioFeature;
use crate::virtio::queue::split::{AvailHeader, Desc, DescFlag, SplitQueue};
use crate::virtio::queue::{QUEUE_SIZE_MAX, Queue, VirtQueue};

const MEM_SIZE: usize = 2 << 20;
const QUEUE_SIZE: u16 = QUEUE_SIZE_MAX;
const DESC_ADDR: u64 = 0x1000;
const AVAIL_ADDR: u64 = 0x2000;
const USED_ADDR: u64 = 0x3000;
const DATA_ADDR: u64 = 0x4000;

#[fixture]
fn fixutre_ram_bus() -> RamBus {
    let host_pages = ArcMemPages::from_anonymous(MEM_SIZE, None, None).unwrap();
    let ram_bus = RamBus::new();
    ram_bus.add(0, host_pages).unwrap();
    ram_bus
}

#[fixture]
fn fixture_queue() -> Queue {
    Queue {
        size: AtomicU16::new(QUEUE_SIZE),
        desc: AtomicU64::new(DESC_ADDR),
        driver: AtomicU64::new(AVAIL_ADDR),
        device: AtomicU64::new(USED_ADDR),
        enabled: AtomicBool::new(true),
    }
}

#[rstest]
fn disabled_queue(fixutre_ram_bus: RamBus, fixture_queue: Queue) {
    let ram = fixutre_ram_bus.lock_layout();
    fixture_queue.enabled.store(false, Ordering::Relaxed);
    let split_queue = SplitQueue::new(&fixture_queue, &*ram, 0);
    assert_matches!(split_queue, Ok(None));
}

#[rstest]
fn enabled_queue(fixutre_ram_bus: RamBus, fixture_queue: Queue) {
    let ram = fixutre_ram_bus.lock_layout();
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
    let descs = [
        Desc {
            addr: addr_0,
            len: str_0.len() as u32,
            flag: DescFlag::NEXT.bits(),
            next: 1,
        },
        Desc {
            addr: addr_1,
            len: str_1.len() as u32,
            flag: 0,
            next: 0,
        },
        Desc {
            addr: addr_2,
            len: str_2.len() as u32,
            flag: DescFlag::WRITE.bits(),
            next: 0,
        },
    ];
    for (idx, desc) in descs.iter().enumerate() {
        ram.write_t(DESC_ADDR + (idx * size_of::<Desc>()) as u64, desc)
            .unwrap();
    }
    for (idx, id) in [0u16, 2u16].iter().enumerate() {
        let addr = AVAIL_ADDR + (size_of::<AvailHeader>() + idx * size_of::<u16>()) as u64;
        ram.write_t(addr, id).unwrap();
    }
    let avail_header = AvailHeader { flags: 0, idx: 1 };
    ram.write_t(AVAIL_ADDR, &avail_header).unwrap();

    assert_eq!(q.avail_index(), 1);
    assert_eq!(q.read_avail(0), 0);
    assert!(q.has_next_desc());
    let desc = q.next_desc().unwrap().unwrap();
    assert_eq!(desc.id, 0);
    assert_eq!(&*desc.readable[0], str_0.as_bytes());
    assert_eq!(&*desc.readable[1], str_1.as_bytes());
    assert_eq!(desc.writable.len(), 0);
    q.push_used(desc, 0);
    assert!(!q.has_next_desc());

    let avail_header = AvailHeader { flags: 0, idx: 2 };
    ram.write_t(AVAIL_ADDR, &avail_header).unwrap();
    let mut desc = q.next_desc().unwrap().unwrap();
    assert_eq!(desc.id, 2);
    assert_eq!(desc.readable.len(), 0);
    let buffer = desc.writable[0].as_mut();
    buffer.copy_from_slice(str_2.as_bytes());
    q.push_used(desc, str_2.len());
    let mut b = vec![0u8; str_2.len()];
    ram.read(addr_2, b.as_mut()).unwrap();
    assert_eq!(&b, str_2.as_bytes());
}

#[rstest]
fn event_idx_enabled(fixutre_ram_bus: RamBus, fixture_queue: Queue) {
    let ram = fixutre_ram_bus.lock_layout();
    let q = SplitQueue::new(&fixture_queue, &*ram, VirtioFeature::EVENT_IDX.bits())
        .unwrap()
        .unwrap();
    unsafe { *q.used_event.unwrap() = 1 };
    assert_eq!(q.used_event(), Some(1));

    assert_eq!(q.set_avail_event(12), Some(()));
    assert_eq!(unsafe { *q.avail_event.unwrap() }, 12);
}
