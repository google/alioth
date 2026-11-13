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
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::time::Duration;

use flume::TryRecvError;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use rstest::rstest;
use zerocopy::IntoBytes;

use crate::device::net::MacAddr;
use crate::mem::mapped::RamBus;
use crate::virtio::dev::net::tap::Net;
use crate::virtio::dev::net::{
    CtrlAck, CtrlClass, CtrlHdr, CtrlMq, CtrlMqParisSet, NetConfig, NetFeature,
};
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::GuestQueue;
use crate::virtio::queue::{Queue, QueueReg, Status};
use crate::virtio::tests::{self, DATA_ADDR, FakeIrqSender};
use crate::virtio::worker::WorkerApi;
use crate::virtio::worker::io_uring::{BufferAction, VirtioIoUring};
use crate::virtio::worker::mio::{ActiveMio, VirtioMio};

fn socket_pair(nonblocking: bool) -> (File, UnixDatagram) {
    let (dev_sock, peer_sock) = UnixDatagram::pair().unwrap();
    dev_sock.set_nonblocking(nonblocking).unwrap();
    peer_sock.set_nonblocking(true).unwrap();
    (File::from(OwnedFd::from(dev_sock)), peer_sock)
}

fn make_net(
    max_queue_pairs: u16,
    driver_feature: NetFeature,
    num_sockets: usize,
    api: WorkerApi,
) -> (Net, Vec<UnixDatagram>) {
    let nonblocking = matches!(api, WorkerApi::Mio);
    let mut tap_sockets = Vec::with_capacity(num_sockets);
    let mut peers = Vec::with_capacity(num_sockets);
    for _ in 0..num_sockets {
        let (sock, peer) = socket_pair(nonblocking);
        tap_sockets.push(sock);
        peers.push(peer);
    }
    let mut feature = NetFeature::MAC | NetFeature::MTU | NetFeature::CTRL_VQ;
    if max_queue_pairs > 1 {
        feature |= NetFeature::MQ;
    }
    let net = Net {
        name: Arc::from("test-net"),
        config: Arc::new(NetConfig {
            mac: MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            max_queue_pairs,
            mtu: 1500,
            ..Default::default()
        }),
        tap_sockets,
        feature,
        driver_feature,
        dev_tap: None,
        if_name: None,
        api,
    };
    (net, peers)
}

struct TestQueues {
    ram_bus: Arc<RamBus>,
    guest_queues: Vec<GuestQueue<SplitQueue>>,
    dev_queues: Vec<Option<Queue<SplitQueue>>>,
}

impl TestQueues {
    fn new(count: u16) -> Self {
        let ram_bus = Arc::new(tests::fixture_ram_bus());
        let ram = ram_bus.load();
        let regs: Box<[QueueReg]> = tests::fixture_queues(count);
        let guest_queues = regs
            .iter()
            .map(|reg| GuestQueue::new(SplitQueue::new(reg, &ram, false).unwrap().unwrap(), reg))
            .collect();
        let dev_queues = regs
            .iter()
            .map(|reg| Queue::new(reg, ram_bus.clone(), false).unwrap())
            .collect();
        Self {
            ram_bus,
            guest_queues,
            dev_queues,
        }
    }
}

fn add_ctrl_cmd(
    ram_bus: &RamBus,
    guest_q: &mut GuestQueue<SplitQueue>,
    base_gpa: u64,
    class: CtrlClass,
    command: u8,
    payload: Option<&[u8]>,
) -> (u16, u64) {
    let hdr = CtrlHdr { class, command };
    ram_bus.write(base_gpa, hdr.as_bytes()).unwrap();
    let mut readable = vec![(base_gpa, size_of::<CtrlHdr>() as u32)];
    let mut offset = size_of::<CtrlHdr>() as u64;
    if let Some(data) = payload {
        let data_gpa = base_gpa + offset;
        ram_bus.write(data_gpa, data).unwrap();
        readable.push((data_gpa, data.len() as u32));
        offset += data.len() as u64;
    }
    let ack_gpa = base_gpa + offset;
    ram_bus.write(ack_gpa, &[0xff]).unwrap();
    let id = guest_q.add_desc(&readable, &[(ack_gpa, 1)]);
    (id, ack_gpa)
}

fn read_ack(ram_bus: &RamBus, ack_gpa: u64) -> u8 {
    let mut ack = [0u8; 1];
    ram_bus.read(ack_gpa, &mut ack).unwrap();
    ack[0]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IoUringAction {
    Sqe,
    Written(u32),
}

fn run_io_uring_desc(
    net: &mut Net,
    dev_queues: &mut [Option<Queue<SplitQueue>>],
    irq_sender: &FakeIrqSender,
    q_index: u16,
) -> Option<IoUringAction> {
    let mut recorded = None;
    let queue = dev_queues[q_index as usize].as_mut().unwrap();
    queue
        .handle_desc(
            q_index,
            irq_sender,
            |chain| match VirtioIoUring::handle_desc(net, q_index, chain)? {
                BufferAction::Sqe(_) => {
                    recorded = Some(IoUringAction::Sqe);
                    Ok(Status::Done { len: 0 })
                }
                BufferAction::Written(len) => {
                    recorded = Some(IoUringAction::Written(len));
                    Ok(Status::Done { len })
                }
            },
        )
        .unwrap();
    recorded
}

#[rstest]
#[case(1, NetFeature::empty(), None, 2)]
#[case(1, NetFeature::CTRL_VQ, Some(2), 2)]
#[case(1, NetFeature::CTRL_VQ | NetFeature::MQ, Some(2), 2)]
#[case(1, NetFeature::CTRL_VQ | NetFeature::RSS, Some(2), 2)]
#[case(1, NetFeature::MQ, None, 2)]
#[case(4, NetFeature::empty(), None, 2)]
#[case(4, NetFeature::CTRL_VQ, Some(2), 2)]
#[case(4, NetFeature::CTRL_VQ | NetFeature::MQ, Some(8), 8)]
#[case(4, NetFeature::CTRL_VQ | NetFeature::RSS, Some(8), 8)]
#[case(4, NetFeature::CTRL_VQ | NetFeature::MQ | NetFeature::RSS, Some(8), 8)]
#[case(4, NetFeature::MQ, None, 8)]
#[case(4, NetFeature::RSS, None, 8)]
fn test_ctrl_queue_index(
    #[case] max_queue_pairs: u16,
    #[case] driver_feature: NetFeature,
    #[case] expected_ctrlq: Option<u16>,
    #[case] expected_max_data_queues: u16,
) {
    let (net, _peers) = make_net(max_queue_pairs, driver_feature, 1, WorkerApi::Mio);
    assert_eq!(net.ctrl_queue_index(), expected_ctrlq);
    assert_eq!(net.max_data_queues(), expected_max_data_queues);
}

#[test]
fn test_mio_ctrl_queue_without_mq() {
    let (mut net, peers) = make_net(4, NetFeature::CTRL_VQ, 2, WorkerApi::Mio);
    let mut tq = TestQueues::new(9);
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };
    let mut poll = Poll::new().unwrap();

    // Without MQ/RSS negotiated, N = 1, so queue 2 is controlq.
    // Unknown control class returns CtrlAck::ERR.
    let (id, ack_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[2],
        DATA_ADDR,
        CtrlClass(0xff),
        0,
        None,
    );
    {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_queue(2, &mut active_mio).unwrap();
    }
    let used = tq.guest_queues[2].get_used().unwrap();
    assert_eq!((used.id, used.len), (id, 1));
    assert_eq!(irq_rx.try_recv(), Ok(2));
    assert_eq!(read_ack(&tq.ram_bus, ack_gpa), CtrlAck::ERR.raw());

    // CtrlClass::MQ on queue 2 is rejected with CtrlAck::ERR when MQ is not negotiated.
    let mq_set = CtrlMqParisSet { virtq_pairs: 1 };
    let (id, ack_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[2],
        DATA_ADDR + 0x100,
        CtrlClass::MQ,
        CtrlMq::VQ_PARIS_SET.raw(),
        Some(mq_set.as_bytes()),
    );
    {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_queue(2, &mut active_mio).unwrap();
    }
    let used = tq.guest_queues[2].get_used().unwrap();
    assert_eq!((used.id, used.len), (id, 1));
    assert_eq!(irq_rx.try_recv(), Ok(2));
    assert_eq!(read_ack(&tq.ram_bus, ack_gpa), CtrlAck::ERR.raw());
    assert_eq!(net.tap_sockets.len(), 2);

    // Queue 8 (max_queue_pairs * 2) is NOT treated as controlq.
    let (_id8, ack8_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[8],
        DATA_ADDR + 0x200,
        CtrlClass(0xff),
        0,
        None,
    );
    {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_queue(8, &mut active_mio).unwrap();
    }
    assert!(tq.guest_queues[8].get_used().is_none());
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(read_ack(&tq.ram_bus, ack8_gpa), 0xff);

    // Queue 3 (transmitq2) is rejected even though tap_sockets[1] exists.
    let tx_gpa = DATA_ADDR + 0x300;
    tq.ram_bus.write(tx_gpa, b"unnegotiated-tx").unwrap();
    tq.guest_queues[3].add_desc(&[(tx_gpa, 15)], &[]);
    {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_queue(3, &mut active_mio).unwrap();
    }
    assert!(tq.guest_queues[3].get_used().is_none());
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));
    let mut peer1_buf = [0u8; 32];
    assert!(peers[1].recv(&mut peer1_buf).is_err());

    // Queue 0 (receiveq1) and queue 1 (transmitq1) operate normally.
    peers[0].send(b"rx-q0").unwrap();
    let rx0_gpa = DATA_ADDR + 0x400;
    let rx0_id = tq.guest_queues[0].add_desc(&[], &[(rx0_gpa, 64)]);
    {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_queue(0, &mut active_mio).unwrap();
    }
    let used0 = tq.guest_queues[0].get_used().unwrap();
    assert_eq!((used0.id, used0.len), (rx0_id, 5));
    assert_eq!(irq_rx.try_recv(), Ok(0));
    let mut rx0_buf = [0u8; 5];
    tq.ram_bus.read(rx0_gpa, &mut rx0_buf).unwrap();
    assert_eq!(&rx0_buf, b"rx-q0");
}

#[test]
fn test_mio_ctrl_queue_with_mq() {
    let (mut net, peers) = make_net(4, NetFeature::CTRL_VQ | NetFeature::MQ, 2, WorkerApi::Mio);
    let mut tq = TestQueues::new(9);
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };
    let mut poll = Poll::new().unwrap();

    // With MQ negotiated, queue 2 is RX data queue receiveq2 (not controlq).
    let pkt = b"packet-from-tap1";
    peers[1].send(pkt).unwrap();
    let rx2_gpa = DATA_ADDR;
    let rx2_id = tq.guest_queues[2].add_desc(&[], &[(rx2_gpa, 64)]);
    {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_queue(2, &mut active_mio).unwrap();
    }
    let used2 = tq.guest_queues[2].get_used().unwrap();
    assert_eq!((used2.id, used2.len), (rx2_id, pkt.len() as u32));
    assert_eq!(irq_rx.try_recv(), Ok(2));
    let mut rx2_buf = [0u8; 16];
    tq.ram_bus.read(rx2_gpa, &mut rx2_buf).unwrap();
    assert_eq!(&rx2_buf, pkt);

    // Invalid virtq_pairs (> max_queue_pairs) on queue 8 returns CtrlAck::ERR.
    let bad_set = CtrlMqParisSet { virtq_pairs: 5 };
    let (bad_id, bad_ack_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[8],
        DATA_ADDR + 0x100,
        CtrlClass::MQ,
        CtrlMq::VQ_PARIS_SET.raw(),
        Some(bad_set.as_bytes()),
    );
    {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_queue(8, &mut active_mio).unwrap();
    }
    let bad_used = tq.guest_queues[8].get_used().unwrap();
    assert_eq!((bad_used.id, bad_used.len), (bad_id, 1));
    assert_eq!(irq_rx.try_recv(), Ok(8));
    assert_eq!(read_ack(&tq.ram_bus, bad_ack_gpa), CtrlAck::ERR.raw());
    assert_eq!(net.tap_sockets.len(), 2);

    // Valid VQ_PARIS_SET (virtq_pairs = 1) on queue 8 succeeds with CtrlAck::OK.
    let ok_set = CtrlMqParisSet { virtq_pairs: 1 };
    let (ok_id, ok_ack_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[8],
        DATA_ADDR + 0x200,
        CtrlClass::MQ,
        CtrlMq::VQ_PARIS_SET.raw(),
        Some(ok_set.as_bytes()),
    );
    {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_queue(8, &mut active_mio).unwrap();
    }
    let ok_used = tq.guest_queues[8].get_used().unwrap();
    assert_eq!((ok_used.id, ok_used.len), (ok_id, 1));
    assert_eq!(irq_rx.try_recv(), Ok(8));
    assert_eq!(read_ack(&tq.ram_bus, ok_ack_gpa), CtrlAck::OK.raw());
    assert_eq!(net.tap_sockets.len(), 1);
}

#[test]
fn test_mio_no_ctrl_vq() {
    let (mut net, peers) = make_net(4, NetFeature::empty(), 2, WorkerApi::Mio);
    let mut tq = TestQueues::new(9);
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };
    let mut poll = Poll::new().unwrap();

    // Even with a packet pending on tap_sockets[1], neither queue 2 nor queue 8
    // is treated as controlq or as a valid data queue.
    peers[1].send(b"unexpected").unwrap();
    let (_id2, ack2_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[2],
        DATA_ADDR,
        CtrlClass(0xff),
        0,
        None,
    );
    let (_id8, ack8_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[8],
        DATA_ADDR + 0x100,
        CtrlClass(0xff),
        0,
        None,
    );
    {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_queue(2, &mut active_mio).unwrap();
        net.handle_queue(8, &mut active_mio).unwrap();
    }
    assert!(tq.guest_queues[2].get_used().is_none());
    assert!(tq.guest_queues[8].get_used().is_none());
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(read_ack(&tq.ram_bus, ack2_gpa), 0xff);
    assert_eq!(read_ack(&tq.ram_bus, ack8_gpa), 0xff);
}

#[test]
fn test_mio_handle_event_ignores_unnegotiated_queue() {
    let (mut net, peers) = make_net(4, NetFeature::CTRL_VQ, 2, WorkerApi::Mio);
    let mut tq = TestQueues::new(9);
    let (irq_tx, irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };
    let mut poll = Poll::new().unwrap();

    poll.registry()
        .register(
            &mut SourceFd(&net.tap_sockets[1].as_raw_fd()),
            Token(1),
            Interest::READABLE | Interest::WRITABLE,
        )
        .unwrap();
    peers[1].send(b"spurious").unwrap();

    let (_id, ack_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[2],
        DATA_ADDR,
        CtrlClass(0xff),
        0,
        None,
    );

    let mut events = Events::with_capacity(8);
    poll.poll(&mut events, Some(Duration::from_secs(1)))
        .unwrap();
    assert!(!events.is_empty());
    for event in events.iter() {
        let mut active_mio = ActiveMio {
            queues: &mut tq.dev_queues,
            irq_sender: &irq_sender,
            notifiers: &[],
            poll: &mut poll,
        };
        net.handle_event(event, &mut active_mio).unwrap();
    }

    // Token(1) maps to queue 2/3, which must not corrupt controlq at index 2.
    assert!(tq.guest_queues[2].get_used().is_none());
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));
    assert_eq!(read_ack(&tq.ram_bus, ack_gpa), 0xff);
}

#[test]
fn test_io_uring_ctrl_queue_without_mq() {
    let (mut net, _peers) = make_net(4, NetFeature::CTRL_VQ, 2, WorkerApi::IoUring);
    let mut tq = TestQueues::new(9);
    let (irq_tx, _irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    // Queue 2 is controlq: unknown class -> CtrlAck::ERR.
    let (_id, ack_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[2],
        DATA_ADDR,
        CtrlClass(0xff),
        0,
        None,
    );
    let action = run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 2);
    assert_eq!(action, Some(IoUringAction::Written(1)));
    assert_eq!(read_ack(&tq.ram_bus, ack_gpa), CtrlAck::ERR.raw());

    // CtrlClass::MQ on queue 2 -> CtrlAck::ERR when MQ is not negotiated.
    let mq_set = CtrlMqParisSet { virtq_pairs: 1 };
    let (_id, ack_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[2],
        DATA_ADDR + 0x100,
        CtrlClass::MQ,
        CtrlMq::VQ_PARIS_SET.raw(),
        Some(mq_set.as_bytes()),
    );
    let action = run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 2);
    assert_eq!(action, Some(IoUringAction::Written(1)));
    assert_eq!(read_ack(&tq.ram_bus, ack_gpa), CtrlAck::ERR.raw());
    assert_eq!(net.tap_sockets.len(), 2);

    // Queue 8 is NOT treated as controlq.
    let (_id8, ack8_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[8],
        DATA_ADDR + 0x200,
        CtrlClass(0xff),
        0,
        None,
    );
    let action8 = run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 8);
    assert_eq!(action8, Some(IoUringAction::Written(0)));
    assert_eq!(read_ack(&tq.ram_bus, ack8_gpa), 0xff);

    // Queue 3 (transmitq2) is rejected even though tap_sockets[1] exists.
    tq.guest_queues[3].add_desc(&[(DATA_ADDR + 0x300, 16)], &[]);
    let action3 = run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 3);
    assert_eq!(action3, Some(IoUringAction::Written(0)));

    // Queue 0 (receiveq1) and queue 1 (transmitq1) produce SQEs.
    tq.guest_queues[0].add_desc(&[], &[(DATA_ADDR + 0x400, 64)]);
    assert_eq!(
        run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 0),
        Some(IoUringAction::Sqe)
    );
    tq.guest_queues[1].add_desc(&[(DATA_ADDR + 0x500, 64)], &[]);
    assert_eq!(
        run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 1),
        Some(IoUringAction::Sqe)
    );
}

#[test]
fn test_io_uring_ctrl_queue_with_mq() {
    let (mut net, _peers) = make_net(
        4,
        NetFeature::CTRL_VQ | NetFeature::MQ,
        2,
        WorkerApi::IoUring,
    );
    let mut tq = TestQueues::new(9);
    let (irq_tx, _irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    // With MQ negotiated, queue 2 is RX data queue receiveq2 -> Sqe.
    tq.guest_queues[2].add_desc(&[], &[(DATA_ADDR, 64)]);
    let action2 = run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 2);
    assert_eq!(action2, Some(IoUringAction::Sqe));

    // Queue 8 is controlq: VQ_PARIS_SET with virtq_pairs = 1 -> Written(1) & CtrlAck::OK.
    let ok_set = CtrlMqParisSet { virtq_pairs: 1 };
    let (_id8, ack8_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[8],
        DATA_ADDR + 0x100,
        CtrlClass::MQ,
        CtrlMq::VQ_PARIS_SET.raw(),
        Some(ok_set.as_bytes()),
    );
    let action8 = run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 8);
    assert_eq!(action8, Some(IoUringAction::Written(1)));
    assert_eq!(read_ack(&tq.ram_bus, ack8_gpa), CtrlAck::OK.raw());
    assert_eq!(net.tap_sockets.len(), 1);
}

#[test]
fn test_io_uring_no_ctrl_vq() {
    let (mut net, _peers) = make_net(4, NetFeature::empty(), 2, WorkerApi::IoUring);
    let mut tq = TestQueues::new(9);
    let (irq_tx, _irq_rx) = flume::unbounded();
    let irq_sender = FakeIrqSender { q_tx: irq_tx };

    let (_id2, ack2_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[2],
        DATA_ADDR,
        CtrlClass(0xff),
        0,
        None,
    );
    let (_id8, ack8_gpa) = add_ctrl_cmd(
        &tq.ram_bus,
        &mut tq.guest_queues[8],
        DATA_ADDR + 0x100,
        CtrlClass(0xff),
        0,
        None,
    );

    assert_eq!(
        run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 2),
        Some(IoUringAction::Written(0))
    );
    assert_eq!(
        run_io_uring_desc(&mut net, &mut tq.dev_queues, &irq_sender, 8),
        Some(IoUringAction::Written(0))
    );
    assert_eq!(read_ack(&tq.ram_bus, ack2_gpa), 0xff);
    assert_eq!(read_ack(&tq.ram_bus, ack8_gpa), 0xff);
}
