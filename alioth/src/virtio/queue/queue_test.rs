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

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
use std::sync::mpsc::{self, TryRecvError};

use rstest::{fixture, rstest};

use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::{QUEUE_SIZE_MAX, Queue, VirtQueue};
use crate::virtio::tests::FakeIrqSender;

pub const MEM_SIZE: usize = 2 << 20;
pub const QUEUE_SIZE: u16 = QUEUE_SIZE_MAX;
pub const DESC_ADDR: u64 = 0x1000;
pub const AVAIL_ADDR: u64 = 0x2000;
pub const USED_ADDR: u64 = 0x3000;
pub const DATA_ADDR: u64 = 0x4000;

#[fixture]
pub fn fixture_ram_bus() -> RamBus {
    let host_pages = ArcMemPages::from_anonymous(MEM_SIZE, None, None).unwrap();
    let ram_bus = RamBus::new();
    ram_bus.add(0, host_pages).unwrap();
    ram_bus
}

#[fixture]
pub fn fixture_queue() -> Queue {
    Queue {
        size: AtomicU16::new(QUEUE_SIZE),
        desc: AtomicU64::new(DESC_ADDR),
        driver: AtomicU64::new(AVAIL_ADDR),
        device: AtomicU64::new(USED_ADDR),
        enabled: AtomicBool::new(true),
    }
}

#[rstest]
fn test_copy_from_reader(fixture_ram_bus: RamBus, fixture_queue: Queue) {
    let ram = fixture_ram_bus.lock_layout();
    let mut q = SplitQueue::new(&fixture_queue, &*ram, 0).unwrap().unwrap();

    let (irq_tx, irq_rx) = mpsc::channel();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    let str_0 = "Hello, World!";
    let str_1 = "Goodbye, World!";
    let str_2 = "Bose-Einstein condensate";
    let addr_0 = DATA_ADDR;
    let addr_1 = addr_0 + str_0.len() as u64;
    let addr_2 = addr_1 + str_1.len() as u64;
    let addr_3 = addr_2 + str_2.len() as u64;

    let s = format!("{str_0}{str_1}{str_2}");
    let mut reader = s.as_bytes();

    q.copy_from_reader(0, "test", &irq_sender, &mut reader)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    q.add_desc(
        0,
        &[],
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
    );
    q.copy_from_reader(0, "test", &irq_sender, &mut reader)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    q.copy_from_reader(0, "test", &irq_sender, &mut reader)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    q.add_desc(2, &[], &[(addr_2, str_2.len() as u32)]);
    q.copy_from_reader(0, "test", &irq_sender, &mut reader)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    q.add_desc(3, &[], &[(addr_3, 12)]);
    q.copy_from_reader(0, "test", &irq_sender, &mut reader)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    for (s, addr) in [(str_0, addr_0), (str_1, addr_1), (str_2, addr_2)] {
        let mut buf = vec![0u8; s.len()];
        ram.read(addr, &mut buf).unwrap();
        assert_eq!(String::from_utf8_lossy(buf.as_slice()), s);
    }
}

#[rstest]
fn test_copy_to_writer(fixture_ram_bus: RamBus, fixture_queue: Queue) {
    let ram = fixture_ram_bus.lock_layout();
    let mut q = SplitQueue::new(&fixture_queue, &*ram, 0).unwrap().unwrap();

    let (irq_tx, irq_rx) = mpsc::channel();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    let str_0 = "Hello, World!";
    let str_1 = "Goodbye, World!";
    let str_2 = "Bose-Einstein condensate";
    let addr_0 = DATA_ADDR;
    let addr_1 = addr_0 + str_0.len() as u64;
    let addr_2 = addr_1 + str_1.len() as u64;
    let addr_3 = addr_2 + str_2.len() as u64;
    for (s, addr) in [(str_0, addr_0), (str_1, addr_1), (str_2, addr_2)] {
        ram.write(addr, s.as_bytes()).unwrap();
    }

    let mut b = vec![0u8; str_0.len() + str_1.len() + str_2.len()];
    let mut writer = b.as_mut_slice();

    q.copy_to_writer(0, "test", &irq_sender, &mut writer)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    q.add_desc(
        0,
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );
    q.copy_to_writer(0, "test", &irq_sender, &mut writer)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    q.copy_to_writer(0, "test", &irq_sender, &mut writer)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    q.add_desc(2, &[(addr_2, str_2.len() as u32)], &[]);
    q.copy_to_writer(0, "test", &irq_sender, &mut writer)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    q.add_desc(3, &[(addr_3, 12)], &[]);
    q.copy_to_writer(0, "test", &irq_sender, &mut writer)
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    assert_eq!(
        String::from_utf8_lossy(b.as_slice()),
        format!("{str_0}{str_1}{str_2}")
    )
}
