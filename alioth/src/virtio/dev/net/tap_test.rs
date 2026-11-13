// Copyright 2026 Google LLC
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

use std::fs::File;
use std::io::{IoSliceMut, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;

use assert_matches::assert_matches;
use flume::TryRecvError;
use io_uring::IoUring;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use rstest::rstest;
use zerocopy::{FromBytes, IntoBytes};

use crate::mem::mapped::Ram;
use crate::virtio::Error;
use crate::virtio::dev::net::tap::{Net, receive_from_tap, set_num_buffers};
use crate::virtio::dev::net::{NetConfig, NetFeature, VirtioNetHdr};
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::GuestQueue;
use crate::virtio::queue::{Queue, Status, VirtQueue};
use crate::virtio::tests::{self as virtio_tests, DATA_ADDR, FakeIrqSender};
use crate::virtio::worker::WorkerApi;
use crate::virtio::worker::io_uring::{BufferAction, VirtioIoUring};
use crate::virtio::worker::mio::{ActiveMio, VirtioMio};

const SEGMENT_STRIDE: u64 = 0x1000;

fn socket_pair(nonblocking: bool) -> (File, UnixDatagram) {
    let (dev_sock, peer_sock) = UnixDatagram::pair().unwrap();
    dev_sock.set_nonblocking(nonblocking).unwrap();
    peer_sock.set_nonblocking(true).unwrap();
    let file = File::from(OwnedFd::from(dev_sock));
    (file, peer_sock)
}

fn fixture_net(socket: File, api: WorkerApi) -> Net {
    Net {
        name: Arc::from("test-tap"),
        config: Arc::new(NetConfig {
            max_queue_pairs: 1,
            mtu: 1500,
            ..Default::default()
        }),
        tap_sockets: vec![socket],
        feature: NetFeature::MAC | NetFeature::MTU,
        driver_feature: NetFeature::empty(),
        dev_tap: None,
        if_name: None,
        api,
    }
}

fn sample_tap_hdr(num_buffers: u16) -> VirtioNetHdr {
    VirtioNetHdr {
        flags: 1,
        gso_type: 1,
        hdr_len: 54,
        gso_size: 1460,
        csum_start: 34,
        csum_offset: 16,
        num_buffers,
    }
}

fn sample_payload() -> Vec<u8> {
    (0..60u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect()
}

fn build_tap_packet(payload: &[u8]) -> Vec<u8> {
    let hdr = sample_tap_hdr(0);
    let mut pkt = Vec::with_capacity(size_of::<VirtioNetHdr>() + payload.len());
    pkt.extend_from_slice(hdr.as_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

fn prepare_guest_rx_chain(ram: &Ram, seg_lens: &[u32]) -> Vec<(u64, u32)> {
    seg_lens
        .iter()
        .enumerate()
        .map(|(i, &len)| {
            let gpa = DATA_ADDR + (i as u64) * SEGMENT_STRIDE;
            let fill = vec![0xffu8; len as usize];
            ram.write(gpa, &fill).unwrap();
            (gpa, len)
        })
        .collect()
}

fn read_guest_rx_chain(ram: &Ram, segs: &[(u64, u32)], total_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(total_len);
    for &(gpa, len) in segs {
        if out.len() >= total_len {
            break;
        }
        let take = (len as usize).min(total_len - out.len());
        let mut buf = vec![0u8; take];
        ram.read(gpa, &mut buf).unwrap();
        out.extend_from_slice(&buf);
    }
    out
}

#[rstest]
#[case(&[12])]
#[case(&[10, 2])]
#[case(&[11, 1])]
#[case(&[5, 0, 6, 0, 10])]
#[case(&[1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 4])]
fn test_set_num_buffers(#[case] lens: &[usize]) {
    let total: usize = lens.iter().sum();
    let mut backing = vec![0xa5u8; total];
    let mut slices: Vec<IoSliceMut<'_>> = Vec::with_capacity(lens.len());
    let mut rest = backing.as_mut_slice();
    for &len in lens {
        let (head, tail) = rest.split_at_mut(len);
        slices.push(IoSliceMut::new(head));
        rest = tail;
    }

    set_num_buffers(&mut slices, 1);

    assert!(backing[..10].iter().all(|&b| b == 0xa5));
    assert_eq!(&backing[10..12], &1u16.to_le_bytes());
    assert!(backing[12..].iter().all(|&b| b == 0xa5));
}

#[rstest]
#[case(&[1526])]
#[case(&[10, 100])]
#[case(&[11, 100])]
#[case(&[4, 6, 1, 1, 100])]
fn test_mio_rx_sets_num_buffers(#[case] seg_lens: &[u32]) {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let ram = ram_bus.load();
    let regs = virtio_tests::fixture_queues(2);
    let mut guest_rx = GuestQueue::new(
        SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
        &regs[0],
    );
    let mut queues = [
        Queue::<SplitQueue>::new(&regs[0], ram_bus.clone(), false).unwrap(),
        Queue::<SplitQueue>::new(&regs[1], ram_bus.clone(), false).unwrap(),
    ];
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };
    let mut poll = Poll::new().unwrap();
    let mut active_mio = ActiveMio {
        queues: &mut queues,
        irq_sender: &irq_sender,
        notifiers: &[],
        poll: &mut poll,
    };

    let (socket, peer) = socket_pair(true);
    let mut dev = fixture_net(socket, WorkerApi::Mio);

    let payload = sample_payload();
    let pkt = build_tap_packet(&payload);
    peer.send(&pkt).unwrap();

    let segs = prepare_guest_rx_chain(&ram, seg_lens);
    let desc_id = guest_rx.add_desc(&[], &segs);

    VirtioMio::handle_queue(&mut dev, 0, &mut active_mio).unwrap();

    assert_eq!(irq_rx.try_recv(), Ok(0));
    let used = guest_rx.get_used().unwrap();
    assert_eq!(used.id, desc_id);
    assert_eq!(used.len, pkt.len() as u32);

    let received = read_guest_rx_chain(&ram, &segs, pkt.len());
    let rx_hdr = VirtioNetHdr::read_from_bytes(&received[..size_of::<VirtioNetHdr>()]).unwrap();
    assert_eq!(rx_hdr.num_buffers, 1);
    assert_eq!(rx_hdr.as_bytes(), sample_tap_hdr(1).as_bytes());
    assert_eq!(&received[size_of::<VirtioNetHdr>()..], payload.as_slice());
}

#[test]
fn test_mio_rx_handle_event() {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let ram = ram_bus.load();
    let regs = virtio_tests::fixture_queues(2);
    let mut guest_rx = GuestQueue::new(
        SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
        &regs[0],
    );
    let mut queues = [
        Queue::<SplitQueue>::new(&regs[0], ram_bus.clone(), false).unwrap(),
        Queue::<SplitQueue>::new(&regs[1], ram_bus.clone(), false).unwrap(),
    ];
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };
    let mut poll = Poll::new().unwrap();

    let (socket, peer) = socket_pair(true);
    let raw_fd = socket.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&raw_fd), Token(0), Interest::READABLE)
        .unwrap();
    let mut dev = fixture_net(socket, WorkerApi::Mio);

    let payload = sample_payload();
    let pkt = build_tap_packet(&payload);
    peer.send(&pkt).unwrap();

    let segs = prepare_guest_rx_chain(&ram, &[11, 100]);
    let desc_id = guest_rx.add_desc(&[], &segs);

    let mut events = Events::with_capacity(8);
    poll.poll(&mut events, Some(Duration::from_secs(1)))
        .unwrap();
    let event = events.iter().next().unwrap();

    let mut active_mio = ActiveMio {
        queues: &mut queues,
        irq_sender: &irq_sender,
        notifiers: &[],
        poll: &mut poll,
    };
    VirtioMio::handle_event(&mut dev, event, &mut active_mio).unwrap();

    assert_eq!(irq_rx.try_recv(), Ok(0));
    let used = guest_rx.get_used().unwrap();
    assert_eq!((used.id, used.len), (desc_id, pkt.len() as u32));

    let received = read_guest_rx_chain(&ram, &segs, pkt.len());
    let rx_hdr = VirtioNetHdr::read_from_bytes(&received[..size_of::<VirtioNetHdr>()]).unwrap();
    assert_eq!(rx_hdr.num_buffers, 1);
    assert_eq!(rx_hdr.as_bytes(), sample_tap_hdr(1).as_bytes());
    assert_eq!(&received[size_of::<VirtioNetHdr>()..], payload.as_slice());
}

#[test]
fn test_mio_rx_would_block_and_errors() {
    let (socket, peer) = socket_pair(true);
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let ram = ram_bus.load();
    let regs = virtio_tests::fixture_queues(2);
    let host_split = SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap();
    let mut guest_rx = GuestQueue::new(
        SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
        &regs[0],
    );
    let mut queues = [
        Queue::<SplitQueue>::new(&regs[0], ram_bus.clone(), false).unwrap(),
        Queue::<SplitQueue>::new(&regs[1], ram_bus.clone(), false).unwrap(),
    ];
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };
    let mut poll = Poll::new().unwrap();
    let mut active_mio = ActiveMio {
        queues: &mut queues,
        irq_sender: &irq_sender,
        notifiers: &[],
        poll: &mut poll,
    };

    // Empty non-blocking socket returns Status::Break and leaves RX descriptor available.
    let segs_valid = prepare_guest_rx_chain(&ram, &[1526]);
    let valid_id = guest_rx.add_desc(&[], &segs_valid);
    let mut chain = host_split
        .get_avail(SplitQueue::INIT_INDEX, &ram)
        .unwrap()
        .unwrap();
    assert_matches!(
        receive_from_tap("test-tap", &socket, false)(&mut chain),
        Ok(Status::Break)
    );
    drop(chain);

    let mut dev = fixture_net(socket, WorkerApi::Mio);
    VirtioMio::handle_queue(&mut dev, 0, &mut active_mio).unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));
    assert!(guest_rx.get_used().is_none());

    // Short datagram (< 12 bytes) completes safely with len == 0.
    peer.send(&[0xaa; 6]).unwrap();
    VirtioMio::handle_queue(&mut dev, 0, &mut active_mio).unwrap();
    assert_eq!(irq_rx.try_recv(), Ok(0));
    let short_used = guest_rx.get_used().unwrap();
    assert_eq!((short_used.id, short_used.len), (valid_id, 0));

    // Undersized RX descriptor (< 12 bytes) fails before reading from the socket.
    let payload = sample_payload();
    let pkt = build_tap_packet(&payload);
    peer.send(&pkt).unwrap();
    let segs_undersized = prepare_guest_rx_chain(&ram, &[8]);
    guest_rx.add_desc(&[], &segs_undersized);
    assert_matches!(
        VirtioMio::handle_queue(&mut dev, 0, &mut active_mio),
        Err(Error::InvalidBuffer { .. })
    );
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));
    let mut unread = vec![0u8; pkt.len() + 16];
    let unread_len = (&dev.tap_sockets[0]).read(&mut unread).unwrap();
    assert_eq!(&unread[..unread_len], pkt.as_slice());
}

#[rstest]
#[case(&[8])]
#[case(&[5, 6])]
fn test_rx_undersized_split_rejected(#[case] seg_lens: &[u32]) {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let ram = ram_bus.load();
    let regs = virtio_tests::fixture_queues(1);
    let host_split = SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap();
    let mut guest_rx = GuestQueue::new(
        SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
        &regs[0],
    );
    let segs = prepare_guest_rx_chain(&ram, seg_lens);
    guest_rx.add_desc(&[], &segs);
    let mut chain = host_split
        .get_avail(SplitQueue::INIT_INDEX, &ram)
        .unwrap()
        .unwrap();

    let (socket, _peer) = socket_pair(true);
    let mut dev = fixture_net(socket, WorkerApi::IoUring);
    assert_matches!(
        receive_from_tap("test-tap", &dev.tap_sockets[0], false)(&mut chain),
        Err(Error::InvalidBuffer { .. })
    );
    assert_matches!(
        VirtioIoUring::handle_desc(&mut dev, 0, &mut chain).err(),
        Some(Error::InvalidBuffer { .. })
    );
}

#[rstest]
#[case(&[1526])]
#[case(&[10, 100])]
#[case(&[11, 100])]
#[case(&[4, 6, 1, 1, 100])]
fn test_io_uring_rx_sets_num_buffers(#[case] seg_lens: &[u32]) {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let ram = ram_bus.load();
    let regs = virtio_tests::fixture_queues(1);
    let mut guest_rx = GuestQueue::new(
        SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
        &regs[0],
    );
    let mut host_rx = Queue::<SplitQueue>::new(&regs[0], ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    let (socket, peer) = socket_pair(false);
    let mut dev = fixture_net(socket, WorkerApi::IoUring);
    let mut ring = IoUring::new(8).unwrap();

    let segs = prepare_guest_rx_chain(&ram, seg_lens);
    let desc_id = guest_rx.add_desc(&[], &segs);

    host_rx
        .handle_desc(0, &irq_sender, |chain| {
            match VirtioIoUring::handle_desc(&mut dev, 0, chain)? {
                BufferAction::Sqe(sqe) => {
                    let sqe = sqe.user_data(chain.id() as u64);
                    unsafe { ring.submission().push(&sqe) }.unwrap();
                    Ok(Status::Deferred)
                }
                BufferAction::Written(len) => Ok(Status::Done { len }),
            }
        })
        .unwrap();

    let payload = sample_payload();
    let pkt = build_tap_packet(&payload);
    peer.send(&pkt).unwrap();

    ring.submit_and_wait(1).unwrap();
    let cqe = ring.completion().next().unwrap();
    let completed_id = cqe.user_data() as u16;
    assert_eq!(completed_id, desc_id);

    host_rx
        .handle_deferred(completed_id, 0, &irq_sender, |chain| {
            VirtioIoUring::complete_desc(&mut dev, 0, chain, &cqe)
        })
        .unwrap();

    assert_eq!(irq_rx.try_recv(), Ok(0));
    let used = guest_rx.get_used().unwrap();
    assert_eq!((used.id, used.len), (desc_id, pkt.len() as u32));

    let received = read_guest_rx_chain(&ram, &segs, pkt.len());
    let rx_hdr = VirtioNetHdr::read_from_bytes(&received[..size_of::<VirtioNetHdr>()]).unwrap();
    assert_eq!(rx_hdr.num_buffers, 1);
    assert_eq!(rx_hdr.as_bytes(), sample_tap_hdr(1).as_bytes());
    assert_eq!(&received[size_of::<VirtioNetHdr>()..], payload.as_slice());
}

#[test]
fn test_io_uring_rx_short_packet() {
    let ram_bus = Arc::new(virtio_tests::fixture_ram_bus());
    let ram = ram_bus.load();
    let regs = virtio_tests::fixture_queues(1);
    let mut guest_rx = GuestQueue::new(
        SplitQueue::new(&regs[0], &ram, false).unwrap().unwrap(),
        &regs[0],
    );
    let mut host_rx = Queue::<SplitQueue>::new(&regs[0], ram_bus.clone(), false)
        .unwrap()
        .unwrap();
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    let (socket, peer) = socket_pair(false);
    let mut dev = fixture_net(socket, WorkerApi::IoUring);
    let mut ring = IoUring::new(8).unwrap();

    let segs = prepare_guest_rx_chain(&ram, &[64]);
    let desc_id = guest_rx.add_desc(&[], &segs);

    host_rx
        .handle_desc(0, &irq_sender, |chain| {
            match VirtioIoUring::handle_desc(&mut dev, 0, chain)? {
                BufferAction::Sqe(sqe) => {
                    let sqe = sqe.user_data(chain.id() as u64);
                    unsafe { ring.submission().push(&sqe) }.unwrap();
                    Ok(Status::Deferred)
                }
                BufferAction::Written(len) => Ok(Status::Done { len }),
            }
        })
        .unwrap();

    peer.send(&[0xbb; 6]).unwrap();
    ring.submit_and_wait(1).unwrap();
    let cqe = ring.completion().next().unwrap();

    host_rx
        .handle_deferred(cqe.user_data() as u16, 0, &irq_sender, |chain| {
            VirtioIoUring::complete_desc(&mut dev, 0, chain, &cqe)
        })
        .unwrap();

    assert_eq!(irq_rx.try_recv(), Ok(0));
    let used = guest_rx.get_used().unwrap();
    assert_eq!((used.id, used.len), (desc_id, 0));
}
