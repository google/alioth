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

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::mem::size_of;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use assert_matches::assert_matches;
use rstest::rstest;
use tempfile::TempDir;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::{Ram, RamBus};
use crate::sync::notifier::Notifier;
use crate::virtio::dev::vsock::{
    ShutdownFlag, UdsVsockParam, VSOCK_CID_HOST, VsockConfig, VsockFeature, VsockHeader, VsockOp,
    VsockType, VsockVirtq,
};
use crate::virtio::dev::{DevParam, StartParam, Virtio, WakeEvent};
use crate::virtio::queue::QueueReg;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::{GuestQueue, VirtQueueGuest};
use crate::virtio::tests::{
    DATA_ADDR, FakeIoeventFd, FakeIrqSender, fixture_queues, fixture_ram_bus,
};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, VirtioFeature};

#[test]
fn vsock_config_test() {
    let config = VsockConfig {
        guest_cid: 5,
        ..Default::default()
    };
    assert_eq!(config.size(), 8);
    assert_matches!(config.read(0, 8), Ok(5));
    assert_matches!(config.write(0, 8, 0), Ok(Action::None));
}

fn send_to_tx<'m, Q>(
    hdr: &VsockHeader,
    data: &[u8],
    ram: &'m Ram,
    buf_addr: u64,
    q: &mut GuestQueue<'m, Q>,
    tx: &Sender<WakeEvent<FakeIrqSender, FakeIoeventFd>>,
    notifier: &Notifier,
    irq_rx: &Receiver<u16>,
    expect_rx: bool,
) where
    Q: VirtQueueGuest<'m>,
{
    let hdr_addr = buf_addr;
    let data_addr = hdr_addr + size_of::<VsockHeader>() as u64;
    let hdr_buf = hdr.as_bytes();
    ram.write(hdr_addr, hdr_buf).unwrap();
    if !data.is_empty() {
        ram.write(data_addr, data).unwrap();
    }
    let buf_id = q.add_desc(
        &[
            (hdr_addr, size_of::<VsockHeader>() as u32),
            (data_addr, data.len() as u32),
        ],
        &[],
    );
    tx.send(WakeEvent::Notify {
        q_index: VsockVirtq::TX.raw(),
    })
    .unwrap();
    notifier.notify().unwrap();
    if expect_rx {
        assert_eq!(
            irq_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            VsockVirtq::RX.raw()
        );
    }
    assert_eq!(
        irq_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        VsockVirtq::TX.raw()
    );
    let used = q.get_used().unwrap();
    assert_eq!(used.id, buf_id);
    assert_eq!(used.len, 0);
}

#[rstest]
fn vsock_conn_test(fixture_ram_bus: RamBus, #[with(3)] fixture_queues: Box<[QueueReg]>) {
    let ram_bus = Arc::new(fixture_ram_bus);
    let ram = ram_bus.lock_layout();
    let regs: Arc<[QueueReg]> = Arc::from(fixture_queues);
    let reg_tx = &regs[VsockVirtq::TX.raw() as usize];
    let reg_rx = &regs[VsockVirtq::RX.raw() as usize];
    let mut rx_q = GuestQueue::new(
        SplitQueue::new(reg_rx, &*ram, false).unwrap().unwrap(),
        reg_rx,
    );
    let mut tx_q = GuestQueue::new(
        SplitQueue::new(reg_tx, &*ram, false).unwrap().unwrap(),
        reg_tx,
    );

    let temp_dir = TempDir::new().unwrap();
    let sock_path = temp_dir.path().join("vsock.sock");

    const GUEST_CID: u32 = 3;
    let param = UdsVsockParam {
        cid: GUEST_CID,
        path: sock_path.clone(),
    };
    let dev = param.build("vsock").unwrap();

    assert_matches!(dev.id(), DeviceId::Socket);
    assert_eq!(dev.name(), "vsock");
    assert_eq!(dev.num_queues(), 3);
    assert_eq!(dev.config().guest_cid, GUEST_CID as u32);
    assert_eq!(
        dev.feature(),
        VsockFeature::STREAM.bits() | FEATURE_BUILT_IN
    );

    let (tx, rx) = mpsc::channel();
    let (handle, notifier) = dev.spawn_worker(rx, ram_bus.clone(), regs).unwrap();
    let (irq_tx, irq_rx) = mpsc::channel();
    let irq_sender = Arc::new(FakeIrqSender { q_tx: irq_tx });
    let start_param = StartParam {
        feature: VirtioFeature::VERSION_1.bits(),
        irq_sender,
        ioeventfds: Option::<Arc<[FakeIoeventFd]>>::None,
    };
    tx.send(WakeEvent::Start { param: start_param }).unwrap();

    let rx_buf_addr = DATA_ADDR;
    let tx_buf_addr = DATA_ADDR + 4096;

    // 0. Setup connection
    // 0.1 host-initiated connection
    let mut h2g_stream = UnixStream::connect(&sock_path).unwrap();
    h2g_stream.set_nonblocking(true).unwrap();

    let buf_id = rx_q.add_desc(&[], &[(rx_buf_addr, 4096)]);
    const H2G_GUEST_PORT: u32 = 1025;
    writeln!(h2g_stream, "CONNECT {H2G_GUEST_PORT}").unwrap();
    assert_eq!(
        irq_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        VsockVirtq::RX.raw()
    );
    let used = rx_q.get_used().unwrap();
    assert_eq!(used.id, buf_id);
    assert_eq!(used.len as usize, size_of::<VsockHeader>());

    let mut hdr = VsockHeader::new_zeroed();
    ram.read(rx_buf_addr, hdr.as_mut_bytes()).unwrap();
    assert_eq!(hdr.src_cid, VSOCK_CID_HOST);
    assert_eq!(hdr.dst_cid, GUEST_CID);
    assert_eq!(hdr.dst_port, H2G_GUEST_PORT);
    assert_eq!(hdr.op, VsockOp::REQUEST);
    assert_eq!(hdr.type_, VsockType::STREAM);

    let h2g_host_port = hdr.src_port;
    let resp_hdr = VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: VSOCK_CID_HOST,
        src_port: H2G_GUEST_PORT,
        dst_port: h2g_host_port,
        op: VsockOp::RESPONSE,
        type_: VsockType::STREAM,
        ..Default::default()
    };
    send_to_tx(
        &resp_hdr,
        &[],
        &ram,
        tx_buf_addr,
        &mut tx_q,
        &tx,
        &notifier,
        &irq_rx,
        false,
    );
    let mut reader = BufReader::new(&h2g_stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert_eq!(line, format!("OK {h2g_host_port}\n"));

    // 0.2 guest-initiated connection
    const G2H_HOST_PORT: u32 = 8706;
    const G2H_GUEST_PORT: u32 = 8707;
    let listener_path = format!("{}_{G2H_HOST_PORT}", sock_path.to_string_lossy());
    let listener = UnixListener::bind(&listener_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let rx_buf_id = rx_q.add_desc(&[], &[(rx_buf_addr, 4096)]);
    let request_hdr = VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: VSOCK_CID_HOST,
        src_port: G2H_GUEST_PORT,
        dst_port: G2H_HOST_PORT,
        op: VsockOp::REQUEST,
        len: 0,
        type_: VsockType::STREAM,
        ..Default::default()
    };
    send_to_tx(
        &request_hdr,
        &[],
        &ram,
        tx_buf_addr,
        &mut tx_q,
        &tx,
        &notifier,
        &irq_rx,
        true,
    );
    let used = rx_q.get_used().unwrap();
    assert_eq!(used.id, rx_buf_id);
    assert_eq!(used.len as usize, size_of::<VsockHeader>());

    let mut hdr = VsockHeader::new_zeroed();
    ram.read(rx_buf_addr, hdr.as_mut_bytes()).unwrap();
    assert_eq!(hdr.src_cid, VSOCK_CID_HOST);
    assert_eq!(hdr.dst_cid, GUEST_CID);
    assert_eq!(hdr.src_port, G2H_HOST_PORT);
    assert_eq!(hdr.dst_port, G2H_GUEST_PORT);
    assert_eq!(hdr.op, VsockOp::RESPONSE);
    assert_eq!(hdr.type_, VsockType::STREAM);

    let (mut g2h_stream, _) = listener.accept().unwrap();
    g2h_stream.set_nonblocking(true).unwrap();

    // 1. Host to Guest via guest-initiated connection
    let h2g_data = "hello from host";
    let buf_id = rx_q.add_desc(&[], &[(rx_buf_addr, 4096)]);
    tx.send(WakeEvent::Notify {
        q_index: VsockVirtq::RX.raw(),
    })
    .unwrap();
    notifier.notify().unwrap();
    assert_eq!(irq_rx.try_recv(), Err(TryRecvError::Empty));

    g2h_stream.write_all(h2g_data.as_bytes()).unwrap();
    g2h_stream.flush().unwrap();
    assert_eq!(
        irq_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
        VsockVirtq::RX.raw()
    );
    let used = rx_q.get_used().unwrap();
    assert_eq!(used.id, buf_id);
    let total_len = size_of::<VsockHeader>() + h2g_data.len();
    assert_eq!(used.len, total_len as u32);

    let mut h2g_buf = vec![0; total_len];
    ram.read(rx_buf_addr, &mut h2g_buf).unwrap();
    let (h2g_hdr_buf, h2g_data_buf) = h2g_buf.split_at(size_of::<VsockHeader>());
    let h2g_hdr = VsockHeader::read_from_bytes(h2g_hdr_buf).unwrap();
    assert_eq!(h2g_hdr.src_port, G2H_HOST_PORT);
    assert_eq!(h2g_hdr.dst_port, G2H_GUEST_PORT);
    assert_eq!(h2g_hdr.op, VsockOp::RW);
    assert_eq!(h2g_hdr.len as usize, h2g_data.len());
    assert_eq!(String::from_utf8_lossy(h2g_data_buf), h2g_data);

    // 2. Guest to Host via host-initiated connection
    let g2h_data = "hello from guest";
    let g2h_hdr = VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: VSOCK_CID_HOST,
        src_port: H2G_GUEST_PORT,
        dst_port: h2g_host_port,
        op: VsockOp::RW,
        len: g2h_data.len() as u32,
        type_: VsockType::STREAM,
        ..Default::default()
    };
    send_to_tx(
        &g2h_hdr,
        g2h_data.as_bytes(),
        &ram,
        tx_buf_addr,
        &mut tx_q,
        &tx,
        &notifier,
        &irq_rx,
        false,
    );
    let mut g2h_read_buf = vec![0; g2h_data.len()];
    h2g_stream.read(&mut g2h_read_buf).unwrap();
    assert_eq!(String::from_utf8_lossy(&g2h_read_buf), g2h_data);

    // 3. Shutdown host-initiated connection
    // 3.1 Send ShutdownFlag::RECEIVE
    let shutdown_hdr = VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: VSOCK_CID_HOST,
        src_port: H2G_GUEST_PORT,
        dst_port: h2g_host_port,
        op: VsockOp::SHUTDOWN,
        len: 0,
        type_: VsockType::STREAM,
        flags: ShutdownFlag::RECEIVE.bits(),
        ..Default::default()
    };
    send_to_tx(
        &shutdown_hdr,
        &[],
        &ram,
        tx_buf_addr,
        &mut tx_q,
        &tx,
        &notifier,
        &irq_rx,
        false,
    );
    let mut buf = [0u8; 8];
    assert_matches!(h2g_stream.read(&mut buf), Err(e) if e.kind() == ErrorKind::WouldBlock);
    // 3.2 Send ShutdownFlag::SEND
    let shutdown_hdr = VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: VSOCK_CID_HOST,
        src_port: H2G_GUEST_PORT,
        dst_port: h2g_host_port,
        op: VsockOp::SHUTDOWN,
        len: 0,
        type_: VsockType::STREAM,
        flags: ShutdownFlag::SEND.bits(),
        ..Default::default()
    };
    send_to_tx(
        &shutdown_hdr,
        &[],
        &ram,
        tx_buf_addr,
        &mut tx_q,
        &tx,
        &notifier,
        &irq_rx,
        false,
    );
    assert_matches!(h2g_stream.read(&mut buf), Ok(0));

    // 4. Reset guest-initiated connection
    let reset_hdr = VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: VSOCK_CID_HOST,
        src_port: G2H_GUEST_PORT,
        dst_port: G2H_HOST_PORT,
        op: VsockOp::RST,
        len: 0,
        type_: VsockType::STREAM,
        flags: 0,
        ..Default::default()
    };
    send_to_tx(
        &reset_hdr,
        &[],
        &ram,
        tx_buf_addr,
        &mut tx_q,
        &tx,
        &notifier,
        &irq_rx,
        false,
    );
    assert_matches!(g2h_stream.read(&mut buf), Ok(0));

    tx.send(WakeEvent::Shutdown).unwrap();
    notifier.notify().unwrap();
    handle.join().unwrap();
}
