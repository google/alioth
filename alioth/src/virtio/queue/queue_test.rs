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
use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::ptr::eq as ptr_eq;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use assert_matches::assert_matches;
use flume::TryRecvError;
use rstest::rstest;

use crate::mem::mapped::{ArcMemPages, Ram};
use crate::virtio::Error;
use crate::virtio::queue::packed::PackedQueue;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::{
    DescChain, Queue, QueueReg, RingAddrs, Status, VirtQueue, copy_from_reader, copy_to_writer,
};
use crate::virtio::tests::{DATA_ADDR, FakeIrqSender, fixture_queues, fixture_ram_bus};

/// Guest memory plugged by tests, beyond the fixture memory.
const EXTRA_GPA: u64 = 4 << 20;
const EXTRA_SIZE: usize = 1 << 20;

#[derive(Debug)]
pub struct UsedDesc {
    pub id: u16,
    pub delta: u16,
    pub len: u32,
}

pub trait VirtQueueGuest: VirtQueue {
    fn add_desc(
        &mut self,
        index: Self::Index,
        ids: &[u16],
        readable: &[(u64, u32)],
        writable: &[(u64, u32)],
    ) -> u16;

    fn get_used(&mut self, index: Self::Index, chains: &HashMap<u16, Vec<u16>>)
    -> Option<UsedDesc>;

    fn notification_enabled(&self) -> bool;

    fn enable_interrupt(&mut self, enabled: bool, index: Self::Index);
}

pub struct GuestQueue<Q>
where
    Q: VirtQueueGuest,
{
    q: Q,
    avail: Q::Index,
    used: Q::Index,
    ids: Vec<bool>,
    chains: HashMap<u16, Vec<u16>>,
    next_id: u16,
}

impl<Q> GuestQueue<Q>
where
    Q: VirtQueueGuest,
{
    pub fn new(q: Q, reg: &QueueReg) -> Self {
        let size = reg.size.load(Ordering::Acquire);
        Self {
            q,
            avail: Q::INIT_INDEX,
            used: Q::INIT_INDEX,
            ids: vec![false; size as usize],
            chains: HashMap::new(),
            next_id: 0,
        }
    }
}

impl<Q> GuestQueue<Q>
where
    Q: VirtQueueGuest,
{
    pub fn add_desc(&mut self, readable: &[(u64, u32)], writable: &[(u64, u32)]) -> u16 {
        let mut ids = vec![];
        let total = readable.len() + writable.len();
        for _ in 0..self.ids.len() {
            if !self.ids[self.next_id as usize] {
                ids.push(self.next_id);
                self.ids[self.next_id as usize] = true;
            }
            self.next_id = self.next_id.wrapping_add(1) % self.ids.len() as u16;
            if ids.len() == total {
                break;
            }
        }
        assert_eq!(ids.len(), total);
        let delta = self.q.add_desc(self.avail, &ids, readable, writable);
        self.avail = self.q.index_add(self.avail, delta);
        let head_id = ids[0];
        self.chains.insert(head_id, ids);
        head_id
    }

    pub fn get_used(&mut self) -> Option<UsedDesc> {
        let used = self.q.get_used(self.used, &self.chains)?;
        let ids = self.chains.remove(&used.id).unwrap();
        for id in ids {
            self.ids[id as usize] = false;
        }
        self.used = self.q.index_add(self.used, used.delta);
        Some(used)
    }

    pub fn notification_enabled(&self) -> bool {
        self.q.notification_enabled()
    }

    pub fn enable_interrupt(&mut self, enabled: bool) {
        self.q.enable_interrupt(enabled, self.used);
    }
}

#[derive(Debug)]
enum ReaderData<'a> {
    Buf(&'a [u8]),
    Err(ErrorKind),
}

#[derive(Debug)]
struct Reader<'a> {
    data: &'a [ReaderData<'a>],
    index: usize,
    pos: usize,
}

impl<'a> Read for Reader<'a> {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        unreachable!()
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> std::io::Result<usize> {
        let mut count = 0;
        let mut buf_iter = bufs.iter_mut();
        let Some(s) = buf_iter.next() else {
            return Ok(0);
        };
        let mut buf = s.as_mut();
        while let Some(data) = self.data.get(self.index) {
            match data {
                ReaderData::Buf(data) => {
                    let c = buf.write(&data[self.pos..]).unwrap();
                    self.pos += c;
                    if self.pos == data.len() {
                        self.index += 1;
                        self.pos = 0;
                    }
                    count += c;
                    if buf.is_empty() {
                        let Some(s) = buf_iter.next() else {
                            break;
                        };
                        buf = s.as_mut();
                    }
                }
                ReaderData::Err(kind) => {
                    if count > 0 {
                        break;
                    }
                    self.index += 1;
                    return Err((*kind).into());
                }
            }
        }
        Ok(count)
    }
}

#[test]
fn test_copy_from_reader() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let queues = fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &queues[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
    assert_eq!(host_q.addrs(), &RingAddrs::load(reg).unwrap());
    assert!(ptr_eq(host_q.ram(), &*ram));

    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    let str_0 = "Hello, World!";
    let str_1 = "Goodbye, World!";
    let str_2 = "Bose-Einstein condensate";
    let addr_0 = DATA_ADDR;
    let addr_1 = addr_0 + str_0.len() as u64;
    let addr_2 = addr_1 + str_1.len() as u64;
    let addr_3 = addr_2 + str_2.len() as u64;

    let mut reader = Reader {
        data: &[
            ReaderData::Buf(str_0.as_bytes()),
            ReaderData::Buf(str_1.as_bytes()),
            ReaderData::Err(ErrorKind::WouldBlock),
            ReaderData::Buf(str_2.as_bytes()),
            ReaderData::Err(ErrorKind::Interrupted),
        ],
        pos: 0,
        index: 0,
    };

    // no writable descriptors
    host_q
        .handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    // empty writable descripter
    guest_q.add_desc(&[], &[(addr_0, 0)]);
    host_q
        .handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    guest_q.add_desc(
        &[],
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
    );
    host_q
        .handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    // no writable descriptors
    host_q
        .handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    guest_q.add_desc(&[], &[(addr_2, str_2.len() as u32)]);
    // will hit ErrorKind::WouldBlock
    host_q
        .handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert!(!guest_q.notification_enabled());
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    host_q
        .handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert!(guest_q.notification_enabled());
    assert_eq!(irq_rx.try_recv(), Ok(0));

    guest_q.add_desc(&[], &[(addr_3, 12)]);

    // will hit ErrorKind::Interrupted
    assert_matches!(
        host_q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader)),
        Err(Error::System { error, .. }) if error.kind() == ErrorKind::Interrupted
    );
    assert!(guest_q.notification_enabled());

    host_q
        .handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    for (s, addr) in [(str_0, addr_0), (str_1, addr_1), (str_2, addr_2)] {
        let mut buf = vec![0u8; s.len()];
        ram.read(addr, &mut buf).unwrap();
        assert_eq!(String::from_utf8_lossy(buf.as_slice()), s);
    }
}

#[derive(Debug)]
enum WriterData<'a> {
    Buf(&'a mut [u8]),
    Err(ErrorKind),
}

#[derive(Debug)]
struct Writer<'a> {
    data: &'a mut [WriterData<'a>],
    index: usize,
    pos: usize,
}

impl<'a> Write for Writer<'a> {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        unreachable!()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> std::io::Result<usize> {
        let mut count = 0;
        let mut buf_iter = bufs.iter();
        let Some(s) = buf_iter.next() else {
            return Ok(0);
        };
        let mut buf = s.as_ref();
        while let Some(data) = self.data.get_mut(self.index) {
            match data {
                WriterData::Buf(data) => {
                    let c = buf.read(&mut data[self.pos..]).unwrap();
                    self.pos += c;
                    if self.pos == data.len() {
                        self.index += 1;
                        self.pos = 0;
                    }
                    count += c;
                    if buf.is_empty() {
                        let Some(s) = buf_iter.next() else {
                            break;
                        };
                        buf = s.as_ref();
                    }
                }
                WriterData::Err(kind) => {
                    if count > 0 {
                        break;
                    }
                    self.index += 1;
                    return Err((*kind).into());
                }
            }
        }
        Ok(count)
    }
}

#[test]
fn test_copy_to_writer() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let queues = fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &queues[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
    let (irq_tx, irq_rx) = flume::unbounded();
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

    let mut buf_0 = vec![0u8; str_0.len()];
    let mut buf_1 = vec![0u8; str_1.len()];
    let mut buf_2 = vec![0u8; str_2.len()];
    let mut writer = Writer {
        data: &mut [
            WriterData::Buf(buf_0.as_mut_slice()),
            WriterData::Buf(buf_1.as_mut_slice()),
            WriterData::Err(ErrorKind::WouldBlock),
            WriterData::Buf(buf_2.as_mut_slice()),
            WriterData::Err(ErrorKind::Interrupted),
        ],
        pos: 0,
        index: 0,
    };

    // no readable descriptors
    host_q
        .handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    // empty readble descripter
    guest_q.add_desc(&[(addr_0, 0)], &[]);
    host_q
        .handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    guest_q.add_desc(
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );
    host_q
        .handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    // no readable descriptors
    host_q
        .handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    guest_q.add_desc(&[(addr_2, str_2.len() as u32)], &[]);
    // will hit ErrorKind::WouldBlock
    host_q
        .handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert!(!guest_q.notification_enabled());
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    host_q
        .handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert!(guest_q.notification_enabled());
    assert_eq!(irq_rx.try_recv(), Ok(0));

    guest_q.add_desc(&[(addr_3, 12)], &[]);

    // will hit ErrorKind::Interrupted
    assert_matches!(
        host_q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer)),
        Err(Error::System { error, .. }) if error.kind() == ErrorKind::Interrupted
    );
    assert!(guest_q.notification_enabled());

    host_q
        .handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    for (buf, s) in [(buf_0, str_0), (buf_1, str_1), (buf_2, str_2)] {
        assert_eq!(String::from_utf8_lossy(buf.as_slice()), s)
    }
}

#[test]
fn test_written_bytes() {
    let str_0 = "Hello, World!";
    let str_1 = "Goodbye, World!";

    let ram = Ram::default();
    let mut buf = vec![0u8; str_0.len()];
    let mut chain = DescChain {
        id: 0,
        delta: 1,
        readable: vec![],
        writable: vec![IoSliceMut::new(buf.as_mut_slice())],
        ram: &ram,
    };
    let reader = str_0.as_bytes();
    assert_matches!(
        copy_from_reader(reader)(&mut chain),
        Ok(Status::Done { len: 13 })
    );
    assert_eq!(buf.as_slice(), str_0.as_bytes());

    let mut buf = vec![];
    let mut chain = DescChain {
        id: 1,
        delta: 1,
        readable: vec![IoSlice::new(str_1.as_bytes())],
        writable: vec![],
        ram: &ram,
    };
    assert_matches!(
        copy_to_writer(&mut buf)(&mut chain),
        Ok(Status::Done { len: 0 })
    );
    assert_eq!(buf.as_slice(), str_1.as_bytes());
}

fn check_handle_deferred<Q>(mut host_q: Queue<Q>, mut guest_q: GuestQueue<Q>, ram: &Ram)
where
    Q: VirtQueueGuest,
{
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    let str_0 = "Hello, World!";
    let str_1 = "Goodbye, World!";
    let str_2 = "Bose-Einstein condensate";
    let addr_0 = DATA_ADDR;
    let addr_1 = addr_0 + str_0.len() as u64;
    let addr_2 = addr_1 + str_1.len() as u64;
    for (s, addr) in [(str_0, addr_0), (str_1, addr_1), (str_2, addr_2)] {
        ram.write(addr, s.as_bytes()).unwrap();
    }

    guest_q.enable_interrupt(true);
    guest_q.add_desc(
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );
    guest_q.add_desc(&[(addr_2, str_2.len() as u32)], &[]);

    let mut ids = vec![];
    host_q
        .handle_desc(0, &irq_sender, |chain| {
            ids.push(chain.id());
            Ok(Status::Break)
        })
        .unwrap();
    assert!(!guest_q.notification_enabled());
    assert_eq!(ids, [0]);

    ids.clear();
    host_q
        .handle_desc(0, &irq_sender, |chain| {
            ids.push(chain.id());
            Ok(Status::Deferred)
        })
        .unwrap();
    assert!(guest_q.notification_enabled());
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(ids, [0, 2]);

    host_q
        .handle_deferred(0, 0, &irq_sender, |chain| {
            assert_eq!(chain.id, 0);
            assert_eq!(&*chain.readable[0], str_0.as_bytes());
            assert_eq!(&*chain.readable[1], str_1.as_bytes());
            assert_eq!(chain.writable.len(), 0);
            Ok(0)
        })
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));
    let used = guest_q.get_used().unwrap();
    assert_eq!(used.id, 0);

    assert_matches!(
        host_q.handle_deferred(1, 0, &irq_sender, |_| Ok(0)),
        Err(Error::InvalidDescriptor { id: 1, .. })
    );

    guest_q.enable_interrupt(false);
    host_q
        .handle_deferred(2, 0, &irq_sender, |chain| {
            assert_eq!(chain.id, 2);
            assert_eq!(&*chain.readable[0], str_2.as_bytes());
            assert_eq!(chain.writable.len(), 0);
            Ok(0)
        })
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));
    let used = guest_q.get_used().unwrap();
    assert_eq!(used.id, 2);
}

#[rstest]
#[case(false, false)]
#[case(false, true)]
#[case(true, false)]
#[case(true, true)]
fn test_handle_deferred(#[case] packed: bool, #[case] event_idx: bool) {
    let ram_bus = Arc::new(fixture_ram_bus());
    let queues = fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &queues[0];
    if packed {
        let host_q = Queue::<PackedQueue>::new(reg, ram_bus.clone(), event_idx)
            .unwrap()
            .unwrap();
        let guest_q = GuestQueue::new(
            PackedQueue::new(reg, &ram, event_idx).unwrap().unwrap(),
            reg,
        );
        check_handle_deferred(host_q, guest_q, &ram);
    } else {
        let host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), event_idx)
            .unwrap()
            .unwrap();
        let guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, event_idx).unwrap().unwrap(), reg);
        check_handle_deferred(host_q, guest_q, &ram);
    }
}

#[test]
fn test_handle_desc_chain_in_flight() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let queues = fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &queues[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    let id = guest_q.add_desc(&[], &[(DATA_ADDR, 16)]);
    host_q
        .handle_desc(0, &irq_sender, |_| Ok(Status::Deferred))
        .unwrap();

    // A buggy driver makes the chain available again while it is in flight.
    let delta = guest_q
        .q
        .add_desc(guest_q.avail, &[id], &[], &[(DATA_ADDR, 16)]);
    guest_q.avail = guest_q.q.index_add(guest_q.avail, delta);
    let mut seen = false;
    let ret = host_q.handle_desc(0, &irq_sender, |_| {
        seen = true;
        Ok(Status::Deferred)
    });
    assert_matches!(ret, Err(Error::InvalidDescriptor { id: i, .. }) if i == id);

    // The device never sees the chain, and the one in flight is kept.
    assert!(!seen);
    host_q
        .handle_deferred(id, 0, &irq_sender, |chain| {
            Ok(chain.writable[0].len() as u32)
        })
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));
    assert_matches!(guest_q.get_used(), Some(UsedDesc { id: i, len: 16, .. }) if i == id);
}

#[rstest]
#[case(false)]
#[case(true)]
fn test_leak_deferred(#[case] leak: bool) {
    let ram_bus = Arc::new(fixture_ram_bus());
    let queues = fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &queues[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
    let (irq_tx, _irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    // The chain stays in flight, e.g. as an io_uring request.
    guest_q.add_desc(&[], &[(DATA_ADDR, 16)]);
    host_q
        .handle_desc(0, &irq_sender, |_| Ok(Status::Deferred))
        .unwrap();
    assert_eq!(host_q.deferred.len(), 1);

    let snapshot = Arc::downgrade(&ram);
    drop(ram);
    drop(guest_q);
    if leak {
        host_q.leak_deferred();
        assert!(host_q.deferred.is_empty());
    }
    drop(host_q);
    drop(ram_bus);
    // Only a leaked chain keeps its snapshot after the queues and the bus
    // are gone.
    assert_eq!(snapshot.upgrade().is_some(), leak);
}

#[test]
fn test_sync_ram() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let queues = fixture_queues(1);
    let reg = &queues[0];
    let fixture_ram = ram_bus.load();
    let mut guest_q = GuestQueue::new(
        SplitQueue::new(reg, &fixture_ram, false).unwrap().unwrap(),
        reg,
    );
    let extra = ArcMemPages::from_anonymous(EXTRA_SIZE, None, None).unwrap();
    ram_bus.update(|ram| ram.add(EXTRA_GPA, extra)).unwrap();
    let ram = ram_bus.load();
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    // A chain in the extra memory stays in flight.
    let str_0 = "in flight across a layout change";
    ram.write(EXTRA_GPA, str_0.as_bytes()).unwrap();
    let id_0 = guest_q.add_desc(&[(EXTRA_GPA, str_0.len() as u32)], &[]);
    host_q
        .handle_desc(0, &irq_sender, |_| Ok(Status::Deferred))
        .unwrap();

    // The extra memory is unplugged, and the queue moves to the new layout.
    ram_bus.update(|ram| ram.remove(EXTRA_GPA)).unwrap();
    let old_ram = Arc::downgrade(&ram);
    drop(ram);
    assert_matches!(host_q.sync_ram(), Ok(true));
    let new_ram = ram_bus.load();
    assert!(ptr_eq(host_q.ram(), &*new_ram));
    assert_matches!(host_q.sync_ram(), Ok(false));
    // The deferred chain still holds the old snapshot.
    assert!(old_ram.upgrade().is_some());

    // The queue continues at the same ring index.
    let str_1 = "after the layout change";
    new_ram.write(DATA_ADDR, str_1.as_bytes()).unwrap();
    let id_1 = guest_q.add_desc(&[(DATA_ADDR, str_1.len() as u32)], &[]);
    let mut ids = vec![];
    host_q
        .handle_desc(0, &irq_sender, |chain| {
            ids.push(chain.id());
            assert_eq!(&*chain.readable[0], str_1.as_bytes());
            Ok(Status::Done { len: 0 })
        })
        .unwrap();
    assert_eq!(ids, [id_1]);
    assert_eq!(irq_rx.try_recv(), Ok(0));
    assert_matches!(guest_q.get_used(), Some(UsedDesc { id, .. }) if id == id_1);

    // The buffer of the chain in flight is still accessible, and completing
    // the chain releases the old snapshot.
    host_q
        .handle_deferred(id_0, 0, &irq_sender, |chain| {
            assert_eq!(&*chain.readable[0], str_0.as_bytes());
            Ok(0)
        })
        .unwrap();
    assert_matches!(guest_q.get_used(), Some(UsedDesc { id, .. }) if id == id_0);
    assert!(old_ram.upgrade().is_none());
}

#[test]
fn test_sync_ram_without_rings() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let queues = fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &queues[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();

    // The driver takes away the memory of the rings while the queue runs.
    ram_bus.update(|ram| ram.remove(0)).unwrap();
    assert_matches!(host_q.sync_ram(), Err(Error::Memory { .. }));
    assert!(ptr_eq(host_q.ram(), &*ram));
}

#[test]
fn test_handle_desc_catches_up_with_ram_bus() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let queues = fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &queues[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    // The driver posts a buffer in memory plugged after the queue moved to
    // its snapshot, e.g. while the worker is handling an earlier event.
    let extra = ArcMemPages::from_anonymous(EXTRA_SIZE, None, None).unwrap();
    ram_bus.update(|ram| ram.add(EXTRA_GPA, extra)).unwrap();
    let s = "in plugged memory";
    ram_bus.write(EXTRA_GPA, s.as_bytes()).unwrap();
    let id = guest_q.add_desc(&[(EXTRA_GPA, s.len() as u32)], &[]);
    assert!(ptr_eq(host_q.ram(), &*ram));

    // The queue moves to the latest layout and retries.
    host_q
        .handle_desc(0, &irq_sender, |chain| {
            assert_eq!(&*chain.readable[0], s.as_bytes());
            assert_eq!(chain.ram().generation(), ram_bus.generation());
            Ok(Status::Done { len: 0 })
        })
        .unwrap();
    assert_eq!(host_q.ram().generation(), ram_bus.generation());
    assert_eq!(irq_rx.try_recv(), Ok(0));
    assert_matches!(guest_q.get_used(), Some(UsedDesc { id: used, .. }) if used == id);
}

#[test]
fn test_handle_desc_irq_before_invalid_chain() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let queues = fixture_queues(1);
    let ram = ram_bus.load();
    let reg = &queues[0];
    let mut host_q = Queue::<SplitQueue>::new(reg, ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    // A valid chain followed by one outside guest memory.
    let s = "valid";
    ram.write(DATA_ADDR, s.as_bytes()).unwrap();
    let id = guest_q.add_desc(&[(DATA_ADDR, s.len() as u32)], &[]);
    guest_q.add_desc(&[(1 << 40, 16)], &[]);

    let ret = host_q.handle_desc(0, &irq_sender, |_| Ok(Status::Done { len: 0 }));
    assert_matches!(ret, Err(Error::Memory { .. }));
    // The driver is still told about the chain completed before the error.
    assert_eq!(irq_rx.try_recv(), Ok(0));
    assert_matches!(guest_q.get_used(), Some(UsedDesc { id: used, .. }) if used == id);
    assert!(guest_q.notification_enabled());
}
