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
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, TryRecvError};

use assert_matches::assert_matches;
use rstest::rstest;

use crate::mem::mapped::RamBus;
use crate::virtio::Error;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::{
    DescChain, Queue, QueueReg, Status, VirtQueue, copy_from_reader, copy_to_writer,
};
use crate::virtio::tests::{DATA_ADDR, FakeIrqSender, fixture_queues, fixture_ram_bus};

pub struct UsedDesc {
    pub id: u16,
    pub delta: u16,
    pub len: u32,
}

pub trait VirtQueueGuest<'m>: VirtQueue<'m> {
    fn add_desc(
        &mut self,
        index: Self::Index,
        ids: &[u16],
        readable: &[(u64, u32)],
        writable: &[(u64, u32)],
    ) -> u16;

    fn get_used(&mut self, index: Self::Index, chains: &HashMap<u16, Vec<u16>>)
    -> Option<UsedDesc>;
}

pub struct GuestQueue<'m, Q>
where
    Q: VirtQueueGuest<'m>,
{
    q: Q,
    avail: Q::Index,
    used: Q::Index,
    ids: Vec<bool>,
    chains: HashMap<u16, Vec<u16>>,
    next_id: u16,
}

impl<'m, Q> GuestQueue<'m, Q>
where
    Q: VirtQueueGuest<'m>,
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

impl<'m, Q> GuestQueue<'m, Q>
where
    Q: VirtQueueGuest<'m>,
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
        loop {
            let Some(data) = self.data.get(self.index) else {
                break;
            };
            match data {
                ReaderData::Buf(data) => {
                    let c = buf.write(&data[self.pos..]).unwrap();
                    self.pos += c;
                    if self.pos == data.len() {
                        self.index += 1;
                        self.pos = 0;
                    }
                    count += c;
                    if buf.len() == 0 {
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

#[rstest]
fn test_copy_from_reader(fixture_ram_bus: RamBus, fixture_queues: Box<[QueueReg]>) {
    let ram = fixture_ram_bus.lock_layout();
    let reg = &fixture_queues[0];
    let mut host_q = Queue::new(
        SplitQueue::new(reg, &*ram, false).unwrap().unwrap(),
        reg,
        &ram,
    );
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &*ram, false).unwrap().unwrap(), reg);
    assert!(ptr_eq(host_q.reg(), reg));

    let (irq_tx, irq_rx) = mpsc::channel();
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
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    host_q
        .handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    guest_q.add_desc(&[], &[(addr_3, 12)]);

    // will hit ErrorKind::Interrupted
    assert_matches!(
        host_q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader)),
        Err(Error::System { error, .. }) if error.kind() == ErrorKind::Interrupted
    );

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
        loop {
            let Some(data) = self.data.get_mut(self.index) else {
                break;
            };
            match data {
                WriterData::Buf(data) => {
                    let c = buf.read(&mut data[self.pos..]).unwrap();
                    self.pos += c;
                    if self.pos == data.len() {
                        self.index += 1;
                        self.pos = 0;
                    }
                    count += c;
                    if buf.len() == 0 {
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

#[rstest]
fn test_copy_to_writer(fixture_ram_bus: RamBus, fixture_queues: Box<[QueueReg]>) {
    let ram = fixture_ram_bus.lock_layout();
    let reg = &fixture_queues[0];
    let mut host_q = Queue::new(
        SplitQueue::new(reg, &*ram, false).unwrap().unwrap(),
        reg,
        &ram,
    );
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &*ram, false).unwrap().unwrap(), reg);
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
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    host_q
        .handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    guest_q.add_desc(&[(addr_3, 12)], &[]);

    // will hit ErrorKind::Interrupted
    assert_matches!(
        host_q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer)),
        Err(Error::System { error, .. }) if error.kind() == ErrorKind::Interrupted
    );

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

    let mut buf = vec![0u8; str_0.len()];
    let mut chain = DescChain {
        id: 0,
        delta: 1,
        readable: vec![],
        writable: vec![IoSliceMut::new(buf.as_mut_slice())],
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
    };
    assert_matches!(
        copy_to_writer(&mut buf)(&mut chain),
        Ok(Status::Done { len: 0 })
    );
    assert_eq!(buf.as_slice(), str_1.as_bytes());
}

#[rstest]
fn test_handle_deferred(fixture_ram_bus: RamBus, fixture_queues: Box<[QueueReg]>) {
    let ram = fixture_ram_bus.lock_layout();
    let reg = &fixture_queues[0];
    let mut host_q = Queue::new(
        SplitQueue::new(reg, &ram, false).unwrap().unwrap(),
        reg,
        &ram,
    );
    let mut guest_q = GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg);
    let (irq_tx, irq_rx) = mpsc::channel();
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

    guest_q.add_desc(
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );
    guest_q.add_desc(&[(addr_2, str_2.len() as u32)], &[]);

    let mut ids = vec![];
    host_q
        .handle_desc(0, &irq_sender, |chain| {
            ids.push(chain.id());
            Ok(Status::Deferred)
        })
        .unwrap();

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

    assert_matches!(
        host_q.handle_deferred(1, 0, &irq_sender, |_| Ok(0)),
        Err(Error::InvalidDescriptor { id: 1, .. })
    );

    host_q
        .handle_deferred(2, 0, &irq_sender, |chain| {
            assert_eq!(chain.id, 2);
            assert_eq!(&*chain.readable[0], str_2.as_bytes());
            assert_eq!(chain.writable.len(), 0);
            Ok(0)
        })
        .unwrap();
}
