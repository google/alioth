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
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use assert_matches::assert_matches;
use flume::{Receiver, Sender, TryRecvError};
use tempfile::TempDir;
use zerocopy::{FromBytes, FromZeros, IntoBytes};

use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::{Ram, RamBus};
use crate::sync::notifier::Notifier;
use crate::virtio::dev::vsock::{
    ShutdownFlag, UdsVsockSpec, VSOCK_CID_HOST, VsockConfig, VsockFeature, VsockHeader, VsockOp,
    VsockType, VsockVirtq,
};
use crate::virtio::dev::{DevSpec, StartParam, Virtio, WakeEvent};
use crate::virtio::queue::QueueReg;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::tests::{GuestQueue, UsedDesc};
use crate::virtio::tests::{DATA_ADDR, FakeIrqSender, fixture_queues, fixture_ram_bus};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, VirtioFeature};

const GUEST_CID: u32 = 3;
const HDR_SIZE: usize = size_of::<VsockHeader>();
/// Guest memory used for RX descriptors.
const RX_ADDR: u64 = DATA_ADDR;
const RX_LEN: u32 = 4096;
/// Guest memory used for TX descriptors.
const TX_ADDR: u64 = DATA_ADDR + 4096;
const TIMEOUT: Duration = Duration::from_secs(1);

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

#[test]
fn vsock_dev_test() {
    let temp_dir = TempDir::new().unwrap();
    let param = UdsVsockSpec {
        cid: GUEST_CID,
        path: temp_dir.path().join("vsock.sock").into(),
    };
    let dev = param.build("vsock").unwrap();
    assert_matches!(dev.id(), DeviceId::SOCKET);
    assert_eq!(dev.name(), "vsock");
    assert_eq!(dev.num_queues(), 3);
    assert_eq!(dev.config().guest_cid, GUEST_CID);
    assert_eq!(
        dev.feature(),
        VsockFeature::STREAM.bits() | FEATURE_BUILT_IN
    );
}

/// Builds the header of a message sent by the guest to the host.
fn guest_hdr(op: VsockOp, guest_port: u32, host_port: u32) -> VsockHeader {
    VsockHeader {
        src_cid: GUEST_CID,
        dst_cid: VSOCK_CID_HOST,
        src_port: guest_port,
        dst_port: host_port,
        op,
        type_: VsockType::STREAM,
        ..Default::default()
    }
}

/// A running `UdsVsock` worker together with the guest queues and the host
/// socket path, so that a test can act as both the guest and a host client.
struct VsockTest<'m> {
    ram: &'m Ram,
    sock_path: PathBuf,
    rx_q: GuestQueue<'m, SplitQueue<'m>>,
    tx_q: GuestQueue<'m, SplitQueue<'m>>,
    tx: Sender<WakeEvent<FakeIrqSender>>,
    irq_rx: Receiver<u16>,
    notifier: Arc<Notifier>,
    handle: JoinHandle<()>,
    _temp_dir: TempDir,
}

impl<'m> VsockTest<'m> {
    /// Starts a device worker listening on a socket in a temporary directory.
    fn new(ram_bus: &Arc<RamBus>, ram: &'m Ram) -> Self {
        let regs: Arc<[QueueReg]> = Arc::from(fixture_queues(3));
        let reg_rx = &regs[VsockVirtq::RX.raw() as usize];
        let reg_tx = &regs[VsockVirtq::TX.raw() as usize];
        let rx_q = GuestQueue::new(
            SplitQueue::new(reg_rx, ram, false).unwrap().unwrap(),
            reg_rx,
        );
        let tx_q = GuestQueue::new(
            SplitQueue::new(reg_tx, ram, false).unwrap().unwrap(),
            reg_tx,
        );

        let temp_dir = TempDir::new().unwrap();
        let sock_path = temp_dir.path().join("vsock.sock");
        let param = UdsVsockSpec {
            cid: GUEST_CID,
            path: sock_path.clone().into(),
        };
        let dev = param.build("vsock").unwrap();

        let (tx, rx) = flume::unbounded();
        let (handle, notifier) = dev.spawn_worker(rx, ram_bus.clone(), regs).unwrap();
        let (irq_tx, irq_rx) = flume::unbounded();
        let start_param = StartParam {
            feature: VirtioFeature::VERSION_1.bits(),
            irq_sender: Arc::new(FakeIrqSender { q_tx: irq_tx }),
            notifiers: Option::<Arc<[Notifier]>>::None,
        };
        tx.send(WakeEvent::Start { param: start_param }).unwrap();

        VsockTest {
            ram,
            sock_path,
            rx_q,
            tx_q,
            tx,
            irq_rx,
            notifier,
            handle,
            _temp_dir: temp_dir,
        }
    }

    /// Offers `bufs` as one writable descriptor chain on the RX queue.
    fn add_rx_chain(&mut self, bufs: &[(u64, u32)]) -> u16 {
        self.rx_q.add_desc(&[], bufs)
    }

    /// Offers a single writable RX buffer of `len` bytes at `addr`.
    fn add_rx_desc_at(&mut self, addr: u64, len: u32) -> u16 {
        self.add_rx_chain(&[(addr, len)])
    }

    /// Offers a single writable RX buffer covering the whole RX area.
    fn add_rx_desc(&mut self) -> u16 {
        self.add_rx_desc_at(RX_ADDR, RX_LEN)
    }

    /// Tells the device that RX descriptors became available.
    fn notify_rx(&self) {
        self.tx
            .send(WakeEvent::Notify {
                q_index: VsockVirtq::RX.raw(),
            })
            .unwrap();
        self.notifier.notify().unwrap();
    }

    fn assert_no_irq(&self) {
        assert_eq!(self.irq_rx.try_recv(), Err(TryRecvError::Empty));
    }

    /// Waits for the device to signal the RX queue.
    fn wait_rx_irq(&self) {
        assert_eq!(
            self.irq_rx.recv_timeout(TIMEOUT).unwrap(),
            VsockVirtq::RX.raw()
        );
    }

    /// Waits for the device to signal the RX queue and returns the descriptor
    /// it used.
    fn wait_rx_used(&mut self) -> UsedDesc {
        self.wait_rx_irq();
        self.rx_q.get_used().unwrap()
    }

    /// Takes a header-only message the device already placed in `buf_id`.
    fn take_rx_hdr(&mut self, buf_id: u16) -> VsockHeader {
        let used = self.rx_q.get_used().unwrap();
        assert_eq!(used.id, buf_id);
        assert_eq!(used.len as usize, HDR_SIZE);
        self.read_hdr(RX_ADDR)
    }

    /// Waits for a header-only message in `buf_id` and returns it.
    fn wait_rx_hdr(&mut self, buf_id: u16) -> VsockHeader {
        self.wait_rx_irq();
        self.take_rx_hdr(buf_id)
    }

    fn read_hdr(&self, addr: u64) -> VsockHeader {
        let mut hdr = VsockHeader::new_zeroed();
        self.ram.read(addr, hdr.as_mut_bytes()).unwrap();
        hdr
    }

    /// Sends `hdr` followed by `data` to the device on the TX queue.
    /// `expect_rx` tells whether the device answers on the RX queue while
    /// handling the message.
    fn send_to_tx(&mut self, hdr: &VsockHeader, data: &[u8], expect_rx: bool) {
        let data_addr = TX_ADDR + HDR_SIZE as u64;
        self.ram.write(TX_ADDR, hdr.as_bytes()).unwrap();
        if !data.is_empty() {
            self.ram.write(data_addr, data).unwrap();
        }
        let buf_id = self.tx_q.add_desc(
            &[(TX_ADDR, HDR_SIZE as u32), (data_addr, data.len() as u32)],
            &[],
        );
        self.tx
            .send(WakeEvent::Notify {
                q_index: VsockVirtq::TX.raw(),
            })
            .unwrap();
        self.notifier.notify().unwrap();
        if expect_rx {
            self.wait_rx_irq();
        }
        assert_eq!(
            self.irq_rx.recv_timeout(TIMEOUT).unwrap(),
            VsockVirtq::TX.raw()
        );
        let used = self.tx_q.get_used().unwrap();
        assert_eq!(used.id, buf_id);
        assert_eq!(used.len, 0);
    }

    /// Connects a host client to the device socket.
    fn connect(&self) -> UnixStream {
        let stream = UnixStream::connect(&self.sock_path).unwrap();
        stream.set_nonblocking(true).unwrap();
        stream
    }

    /// Connects a host client asking for `guest_port` and consumes the
    /// REQUEST the device sends to the guest. Returns the client socket and
    /// the host port assigned by the device.
    fn request_conn(&mut self, guest_port: u32) -> (UnixStream, u32) {
        let buf_id = self.add_rx_desc();
        let mut stream = self.connect();
        writeln!(stream, "CONNECT {guest_port}").unwrap();
        let hdr = self.wait_rx_hdr(buf_id);
        assert_eq!(hdr.src_cid, VSOCK_CID_HOST);
        assert_eq!(hdr.dst_cid, GUEST_CID);
        assert_eq!(hdr.dst_port, guest_port);
        assert_eq!(hdr.op, VsockOp::REQUEST);
        assert_eq!(hdr.type_, VsockType::STREAM);
        (stream, hdr.src_port)
    }

    /// Accepts a host-initiated connection on behalf of the guest and checks
    /// the acknowledgement the client receives.
    fn accept_conn(&mut self, stream: &UnixStream, guest_port: u32, host_port: u32) {
        let resp_hdr = guest_hdr(VsockOp::RESPONSE, guest_port, host_port);
        self.send_to_tx(&resp_hdr, &[], false);
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        assert_eq!(line, format!("OK {host_port}\n"));
    }

    /// Stops the worker and waits for it to exit.
    fn shutdown(self) {
        self.tx.send(WakeEvent::Shutdown).unwrap();
        self.notifier.notify().unwrap();
        self.handle.join().unwrap();
    }
}

#[test]
fn vsock_conn_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let ram = ram_bus.lock_layout();
    let mut t = VsockTest::new(&ram_bus, &ram);

    // 0. Setup connection
    // 0.1 host-initiated connection
    const H2G_GUEST_PORT: u32 = 1025;
    let (mut h2g_stream, h2g_host_port) = t.request_conn(H2G_GUEST_PORT);
    t.accept_conn(&h2g_stream, H2G_GUEST_PORT, h2g_host_port);

    // 0.2 guest-initiated connection
    const G2H_HOST_PORT: u32 = 8706;
    const G2H_GUEST_PORT: u32 = 8707;
    let listener_path = format!("{}_{G2H_HOST_PORT}", t.sock_path.to_string_lossy());
    let listener = UnixListener::bind(&listener_path).unwrap();
    listener.set_nonblocking(true).unwrap();
    let rx_buf_id = t.add_rx_desc();
    let request_hdr = guest_hdr(VsockOp::REQUEST, G2H_GUEST_PORT, G2H_HOST_PORT);
    t.send_to_tx(&request_hdr, &[], true);
    let hdr = t.take_rx_hdr(rx_buf_id);
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
    let buf_id = t.add_rx_chain(&[(RX_ADDR, 32), (RX_ADDR + 32, 32), (RX_ADDR + 64, 32)]);
    t.notify_rx();
    t.assert_no_irq();

    g2h_stream.write_all(h2g_data.as_bytes()).unwrap();
    g2h_stream.flush().unwrap();
    let used = t.wait_rx_used();
    assert_eq!(used.id, buf_id);
    let total_len = HDR_SIZE + h2g_data.len();
    assert_eq!(used.len, total_len as u32);

    let mut h2g_buf = vec![0; total_len];
    ram.read(RX_ADDR, &mut h2g_buf).unwrap();
    let (h2g_hdr_buf, h2g_data_buf) = h2g_buf.split_at(HDR_SIZE);
    let h2g_hdr = VsockHeader::read_from_bytes(h2g_hdr_buf).unwrap();
    assert_eq!(h2g_hdr.src_port, G2H_HOST_PORT);
    assert_eq!(h2g_hdr.dst_port, G2H_GUEST_PORT);
    assert_eq!(h2g_hdr.op, VsockOp::RW);
    assert_eq!(h2g_hdr.len as usize, h2g_data.len());
    assert_eq!(String::from_utf8_lossy(h2g_data_buf), h2g_data);

    // 2. Guest to Host via host-initiated connection
    let g2h_data = "hello from guest";
    let g2h_hdr = VsockHeader {
        len: g2h_data.len() as u32,
        ..guest_hdr(VsockOp::RW, H2G_GUEST_PORT, h2g_host_port)
    };
    t.send_to_tx(&g2h_hdr, g2h_data.as_bytes(), false);
    let mut g2h_read_buf = vec![0; g2h_data.len()];
    let _ = h2g_stream.read(&mut g2h_read_buf).unwrap();
    assert_eq!(String::from_utf8_lossy(&g2h_read_buf), g2h_data);

    // 3. Shutdown host-initiated connection
    // 3.1 Send ShutdownFlag::RECEIVE
    let shutdown_hdr = VsockHeader {
        flags: ShutdownFlag::RECEIVE.bits(),
        ..guest_hdr(VsockOp::SHUTDOWN, H2G_GUEST_PORT, h2g_host_port)
    };
    t.send_to_tx(&shutdown_hdr, &[], false);
    let mut buf = [0u8; 8];
    assert_matches!(h2g_stream.read(&mut buf), Err(e) if e.kind() == ErrorKind::WouldBlock);
    // 3.2 Send ShutdownFlag::SEND
    let shutdown_hdr = VsockHeader {
        flags: ShutdownFlag::SEND.bits(),
        ..guest_hdr(VsockOp::SHUTDOWN, H2G_GUEST_PORT, h2g_host_port)
    };
    t.send_to_tx(&shutdown_hdr, &[], false);
    assert_matches!(h2g_stream.read(&mut buf), Ok(0));

    // 4. Reset guest-initiated connection
    let reset_hdr = guest_hdr(VsockOp::RST, G2H_GUEST_PORT, G2H_HOST_PORT);
    t.send_to_tx(&reset_hdr, &[], false);
    assert_matches!(g2h_stream.read(&mut buf), Ok(0));

    t.shutdown();
}

#[test]
fn vsock_host_close_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let ram = ram_bus.lock_layout();
    let mut t = VsockTest::new(&ram_bus, &ram);

    // Establish a host-initiated connection
    const H2G_GUEST_PORT: u32 = 1025;
    let (h2g_stream, h2g_host_port) = t.request_conn(H2G_GUEST_PORT);
    t.accept_conn(&h2g_stream, H2G_GUEST_PORT, h2g_host_port);

    // Provide RX descriptor first, then close host socket
    let rx_buf_id = t.add_rx_desc();
    t.notify_rx();
    drop(h2g_stream); // EOF to alioth

    // Verify guest receives RST
    let hdr = t.wait_rx_hdr(rx_buf_id);
    assert_eq!(hdr.src_cid, VSOCK_CID_HOST);
    assert_eq!(hdr.dst_cid, GUEST_CID);
    assert_eq!(hdr.src_port, h2g_host_port);
    assert_eq!(hdr.dst_port, H2G_GUEST_PORT);
    assert_eq!(hdr.op, VsockOp::RST);
    assert_eq!(hdr.type_, VsockType::STREAM);

    t.shutdown();
}

#[test]
fn vsock_host_close_no_desc_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let ram = ram_bus.lock_layout();
    let mut t = VsockTest::new(&ram_bus, &ram);

    // Establish a host-initiated connection
    const H2G_GUEST_PORT: u32 = 1025;
    let (mut h2g_stream, h2g_host_port) = t.request_conn(H2G_GUEST_PORT);
    t.accept_conn(&h2g_stream, H2G_GUEST_PORT, h2g_host_port);

    // Write data and close the host socket WITHOUT providing an RX descriptor.
    // The data must be delivered before the guest sees the final RST.
    const DATA: &[u8] = b"drain before close";
    h2g_stream.write_all(DATA).unwrap();
    drop(h2g_stream); // EOF to alioth

    // Let the worker observe the socket event before an RX descriptor becomes
    // available.
    thread::sleep(Duration::from_millis(50));

    // The first descriptor drains the host data.
    let data_buf_id = t.add_rx_desc();
    t.notify_rx();
    let used = t.wait_rx_used();
    assert_eq!(used.id, data_buf_id);
    assert_eq!(used.len as usize, HDR_SIZE + DATA.len());
    let hdr = t.read_hdr(RX_ADDR);
    assert_eq!(hdr.op, VsockOp::RW);
    assert_eq!(hdr.len as usize, DATA.len());
    let mut data = vec![0; DATA.len()];
    ram.read(RX_ADDR + HDR_SIZE as u64, &mut data).unwrap();
    assert_eq!(data, DATA);

    // The next descriptor observes EOF and receives the final RST.
    let rst_buf_id = t.add_rx_desc();
    t.notify_rx();
    let hdr = t.wait_rx_hdr(rst_buf_id);
    assert_eq!(hdr.op, VsockOp::RST);

    t.shutdown();
}

#[test]
fn vsock_partial_conn_request_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let ram = ram_bus.lock_layout();
    let mut t = VsockTest::new(&ram_bus, &ram);

    let mut h2g_stream = t.connect();
    let buf_id = t.add_rx_desc();

    // A connection request can be split over multiple writes, e.g. as done by
    // `writeln!()`. The device must wait for the complete line instead of
    // dropping the connection.
    const H2G_GUEST_PORT: u32 = 1025;
    h2g_stream.write_all(b"CONNECT ").unwrap();
    thread::sleep(Duration::from_millis(50));
    h2g_stream
        .write_all(format!("{H2G_GUEST_PORT}\n").as_bytes())
        .unwrap();

    let hdr = t.wait_rx_hdr(buf_id);
    assert_eq!(hdr.src_cid, VSOCK_CID_HOST);
    assert_eq!(hdr.dst_cid, GUEST_CID);
    assert_eq!(hdr.dst_port, H2G_GUEST_PORT);
    assert_eq!(hdr.op, VsockOp::REQUEST);
    assert_eq!(hdr.type_, VsockType::STREAM);

    t.shutdown();
}

#[test]
fn vsock_simultaneous_conn_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let ram = ram_bus.lock_layout();
    let mut t = VsockTest::new(&ram_bus, &ram);

    let buf_addrs = [RX_ADDR, RX_ADDR + 2048];
    let buf_ids = buf_addrs.map(|addr| t.add_rx_desc_at(addr, 2048));

    // Two clients connecting back to back pile up in the listener backlog,
    // and both must be served.
    const GUEST_PORTS: [u32; 2] = [1025, 1026];
    let mut streams = Vec::new();
    for port in GUEST_PORTS {
        let mut stream = t.connect();
        stream
            .write_all(format!("CONNECT {port}\n").as_bytes())
            .unwrap();
        streams.push(stream);
    }

    let mut requests = Vec::new();
    for _ in GUEST_PORTS {
        let used = t.wait_rx_used();
        assert_eq!(used.len as usize, HDR_SIZE);
        let index = buf_ids.iter().position(|id| *id == used.id).unwrap();
        let hdr = t.read_hdr(buf_addrs[index]);
        assert_eq!(hdr.op, VsockOp::REQUEST);
        requests.push(hdr.dst_port);
    }
    requests.sort_unstable();
    assert_eq!(requests, GUEST_PORTS);

    t.shutdown();
}

#[test]
fn vsock_conn_request_eof_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let ram = ram_bus.lock_layout();
    let mut t = VsockTest::new(&ram_bus, &ram);

    // A client that connects and disconnects without saying anything.
    drop(t.connect());

    // A client that disconnects in the middle of a connection request.
    let mut partial = t.connect();
    partial.write_all(b"CONNECT ").unwrap();
    thread::sleep(Duration::from_millis(50));
    drop(partial);
    thread::sleep(Duration::from_millis(50));

    // Neither takes down the device: a well-behaved client still works.
    const H2G_GUEST_PORT: u32 = 1025;
    let (h2g_stream, h2g_host_port) = t.request_conn(H2G_GUEST_PORT);
    t.accept_conn(&h2g_stream, H2G_GUEST_PORT, h2g_host_port);

    t.shutdown();
}

#[test]
fn vsock_conn_request_close_test() {
    let ram_bus = Arc::new(fixture_ram_bus());
    let ram = ram_bus.lock_layout();
    let mut t = VsockTest::new(&ram_bus, &ram);

    // A client that sends a complete request and hangs up before the guest
    // accepts the connection.
    let buf_id = t.add_rx_desc();
    const H2G_GUEST_PORT: u32 = 1025;
    let mut h2g_stream = t.connect();
    h2g_stream
        .write_all(format!("CONNECT {H2G_GUEST_PORT}\n").as_bytes())
        .unwrap();
    drop(h2g_stream);

    let hdr = t.wait_rx_hdr(buf_id);
    assert_eq!(hdr.op, VsockOp::REQUEST);
    let h2g_host_port = hdr.src_port;

    // The guest accepts, but the host side is already gone. The device must
    // report a reset instead of failing.
    let rst_buf_id = t.add_rx_desc();
    let resp_hdr = guest_hdr(VsockOp::RESPONSE, H2G_GUEST_PORT, h2g_host_port);
    t.send_to_tx(&resp_hdr, &[], true);
    let hdr = t.take_rx_hdr(rst_buf_id);
    assert_eq!(hdr.op, VsockOp::RST);
    assert_eq!(hdr.src_port, h2g_host_port);
    assert_eq!(hdr.dst_port, H2G_GUEST_PORT);

    t.shutdown();
}
