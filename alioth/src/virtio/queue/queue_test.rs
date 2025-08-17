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

use std::io::{ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::ptr::eq as ptr_eq;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
use std::sync::mpsc::{self, TryRecvError};

use assert_matches::assert_matches;
use rstest::{fixture, rstest};

use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::virtio::Error;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::{
    DescChain, QUEUE_SIZE_MAX, Queue, QueueReg, Status, copy_from_reader, copy_to_writer,
};
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
pub fn fixture_queue() -> QueueReg {
    QueueReg {
        size: AtomicU16::new(QUEUE_SIZE),
        desc: AtomicU64::new(DESC_ADDR),
        driver: AtomicU64::new(AVAIL_ADDR),
        device: AtomicU64::new(USED_ADDR),
        enabled: AtomicBool::new(true),
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
fn test_copy_from_reader(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    let mut q = Queue::new(
        SplitQueue::new(&fixture_queue, &*ram, false)
            .unwrap()
            .unwrap(),
    );
    assert!(ptr_eq(q.reg(), &fixture_queue));

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
    q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    // empty writable descripter
    q.add_desc(0, &[], &[(addr_0, 0)]);
    q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    q.add_desc(
        0,
        &[],
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
    );
    q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    // no writable descriptors
    q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    q.add_desc(2, &[], &[(addr_2, str_2.len() as u32)]);
    // will hit ErrorKind::WouldBlock
    q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    q.add_desc(3, &[], &[(addr_3, 12)]);

    // will hit ErrorKind::Interrupted
    assert_matches!(
        q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader)),
        Err(Error::System { error, .. }) if error.kind() == ErrorKind::Interrupted
    );

    q.handle_desc(0, &irq_sender, copy_from_reader(&mut reader))
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
fn test_copy_to_writer(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    let q = SplitQueue::new(&fixture_queue, &*ram, false)
        .unwrap()
        .unwrap();
    let mut q = Queue::new(q);
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
    q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    // empty readble descripter
    q.add_desc(0, &[(addr_0, 0)], &[]);
    q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    q.add_desc(
        0,
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );
    q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    // no readable descriptors
    q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    q.add_desc(2, &[(addr_2, str_2.len() as u32)], &[]);
    // will hit ErrorKind::WouldBlock
    q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
        .unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));

    q.add_desc(3, &[(addr_3, 12)], &[]);

    // will hit ErrorKind::Interrupted
    assert_matches!(
        q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer)),
        Err(Error::System { error, .. }) if error.kind() == ErrorKind::Interrupted
    );

    q.handle_desc(0, &irq_sender, copy_to_writer(&mut writer))
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
        index: 0,
        id: 0,
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
        index: 0,
        id: 1,
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
fn test_handle_deferred(fixture_ram_bus: RamBus, fixture_queue: QueueReg) {
    let ram = fixture_ram_bus.lock_layout();
    let q = SplitQueue::new(&fixture_queue, &*ram, false)
        .unwrap()
        .unwrap();
    let mut q = Queue::new(q);
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

    q.add_desc(
        0,
        &[(addr_0, str_0.len() as u32), (addr_1, str_1.len() as u32)],
        &[],
    );
    q.add_desc(2, &[(addr_2, str_2.len() as u32)], &[]);

    let mut ids = vec![];
    q.handle_desc(0, &irq_sender, |chain| {
        ids.push(chain.id());
        Ok(Status::Deferred)
    })
    .unwrap();

    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(ids, [0, 2]);

    q.handle_deferred(0, 0, &irq_sender, |chain| {
        assert_eq!(chain.id, 0);
        assert_eq!(&*chain.readable[0], str_0.as_bytes());
        assert_eq!(&*chain.readable[1], str_1.as_bytes());
        assert_eq!(chain.writable.len(), 0);
        Ok(0)
    })
    .unwrap();

    assert_matches!(
        q.handle_deferred(1, 0, &irq_sender, |_| Ok(0)),
        Err(Error::InvalidDescriptor { id: 1, .. })
    );

    q.handle_deferred(2, 0, &irq_sender, |chain| {
        assert_eq!(chain.id, 2);
        assert_eq!(&*chain.readable[0], str_2.as_bytes());
        assert_eq!(chain.writable.len(), 0);
        Ok(0)
    })
    .unwrap();
}
