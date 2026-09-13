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
use std::fmt::Debug;
use std::fs;
use std::io::{self, BufRead, BufReader, BufWriter, ErrorKind, IoSlice, IoSliceMut, Read, Write};
use std::mem::size_of_val;
use std::num::Wrapping;
use std::os::fd::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;

use flume::Receiver;
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use serde_aco::Help;
use zerocopy::{FromBytes, IntoBytes};

use crate::ffi;
use crate::mem::mapped::RamBus;
use crate::sync::notifier::Notifier;
use crate::virtio::dev::vsock::{
    ShutdownFlag, VSOCK_CID_HOST, VsockConfig, VsockFeature, VsockHeader, VsockOp, VsockType,
    VsockVirtq,
};
use crate::virtio::dev::{DevSpec, Virtio, WakeEvent};
use crate::virtio::queue::{DescChain, Queue, QueueReg, Status, VirtQueue};
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{DeviceId, FEATURE_BUILT_IN, IrqSender, Result, error};

const HEADER_SIZE: usize = size_of::<VsockHeader>();
const SOCKET_TYPE: VsockType = VsockType::STREAM;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Help)]
pub struct UdsVsockSpec {
    /// Vsock context id.
    pub cid: u32,
    /// Host-side Unix domain socket path.
    pub path: Box<Path>,
}

impl DevSpec for UdsVsockSpec {
    type Device = UdsVsock;

    fn build(self, name: impl Into<Arc<str>>) -> Result<UdsVsock> {
        UdsVsock::new(self, name)
    }
}

#[derive(Debug)]
pub struct UdsVsock {
    name: Arc<str>,
    config: Arc<VsockConfig>,
    path: Box<Path>,
    listener: UnixListener,
    connections: HashMap<(u32, u32), Connection>,
    ports: HashMap<Token, (u32, u32)>,
    sockets: HashMap<Token, PendingConn>,
    host_ports: HashMap<u32, u32>,
    next_port: u32,
}

/// An accepted socket whose `CONNECT` request line has not been fully
/// received yet.
#[derive(Debug)]
struct PendingConn {
    reader: BufReader<UnixStream>,
    /// Bytes of the request line received so far.
    msg: String,
}

/// Returns true if `e` means the host side of a connection is gone, which is
/// a normal event that must only affect that single connection.
fn is_conn_lost(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::BrokenPipe | ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
    )
}

fn get_buf_size(stream: &UnixStream) -> Result<usize> {
    let mut buf_size = 0i32;
    let mut arg_size = size_of_val(&buf_size) as libc::socklen_t;
    ffi!(unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &mut buf_size as *mut _ as _,
            &mut arg_size,
        )
    })?;
    Ok(buf_size as usize)
}

impl UdsVsock {
    fn allocate_port(&mut self) -> Option<u32> {
        let mut count: u64 = 0;
        while self.host_ports.contains_key(&self.next_port) && count < u32::MAX as u64 {
            self.next_port = self.next_port.wrapping_add(1);
            count += 1;
        }
        if count == u32::MAX as u64 {
            None
        } else {
            Some(self.next_port)
        }
    }

    fn create_socket(&mut self, registry: &Registry) -> Result<()> {
        // The listener is registered edge-triggered, so drain the backlog.
        // Otherwise a connection that arrives while another one is pending
        // stalls until yet another client shows up.
        loop {
            let stream = match self.listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if is_conn_lost(&e) => {
                    log::debug!("{}: aborted connection: {e:?}", self.name);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            stream.set_nonblocking(true)?;
            let token = Token(stream.as_raw_fd() as usize);
            registry.register(
                &mut SourceFd(&stream.as_raw_fd()),
                token,
                Interest::READABLE,
            )?;
            let pending = PendingConn {
                reader: BufReader::new(stream),
                msg: String::new(),
            };
            self.sockets.insert(token, pending);
        }
        Ok(())
    }

    fn drop_socket(&self, socket: &UnixStream, registry: &Registry) -> Result<()> {
        registry.deregister(&mut SourceFd(&socket.as_raw_fd()))?;
        Ok(())
    }

    fn handle_conn_request<'m, Q, S>(
        &mut self,
        token: Token,
        mut pending: PendingConn,
        registry: &Registry,
        rx_q: &mut Queue<'_, 'm, Q>,
        irq_sender: &S,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        // The socket is non-blocking, so a request line can arrive in pieces.
        // Keep what has been received so far and wait for the next event
        // instead of tearing down the connection.
        match pending.reader.read_line(&mut pending.msg) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                self.sockets.insert(token, pending);
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        }
        if !pending.msg.ends_with('\n') {
            if pending.msg.is_empty() {
                log::debug!("{}: socket closed before any request", self.name);
            } else {
                log::warn!(
                    "{}: socket closed mid-request: {:?}",
                    self.name,
                    pending.msg
                );
            }
            return self.drop_socket(pending.reader.get_ref(), registry);
        }
        let writer = pending.reader.get_ref().try_clone()?;
        let buf_size = get_buf_size(&writer)?;
        let port_str = pending.msg.trim_start_matches("CONNECT ").trim_end();
        let Ok(port) = port_str.parse::<u32>() else {
            log::error!("{}: failed to parse port {port_str}", self.name);
            return self.drop_socket(pending.reader.get_ref(), registry);
        };
        let Some(host_port) = self.allocate_port() else {
            log::error!("{}: failed to allocate port", self.name);
            return self.drop_socket(pending.reader.get_ref(), registry);
        };
        let hdr = VsockHeader {
            src_cid: VSOCK_CID_HOST,
            dst_cid: self.config.guest_cid,
            src_port: host_port,
            dst_port: port,
            type_: SOCKET_TYPE,
            op: VsockOp::REQUEST,
            fwd_cnt: Wrapping(0),
            buf_alloc: buf_size as u32,
            ..Default::default()
        };
        self.respond(&hdr, irq_sender, rx_q)?;
        let conn = Connection {
            state: ConnState::Requested,
            reader: pending.reader,
            writer: BufWriter::new(writer),
            buf_alloc: buf_size as u32,
            eof: false,
        };
        self.connections.insert((host_port, port), conn);
        let count = self.host_ports.entry(host_port).or_default();
        *count += 1;
        log::trace!(
            "{}: host:{host_port}: count incremented to {count}",
            self.name
        );
        self.ports.insert(token, (host_port, port));
        log::trace!("{}: host:{host_port} -> vm:{port}: requested", self.name);
        Ok(())
    }

    fn respond_rst<'m, Q, S>(
        &self,
        hdr: &VsockHeader,
        irq_sender: &S,
        rx_q: &mut Queue<'_, 'm, Q>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        let resp = VsockHeader {
            src_cid: VSOCK_CID_HOST,
            dst_cid: self.config.guest_cid,
            src_port: hdr.dst_port,
            dst_port: hdr.src_port,
            type_: hdr.type_,
            op: VsockOp::RST,
            ..Default::default()
        };
        self.respond(&resp, irq_sender, rx_q)
    }

    fn respond<'m, Q, S>(
        &self,
        hdr: &VsockHeader,
        irq_sender: &S,
        rx_q: &mut Queue<'_, 'm, Q>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        let mut hdr_buf = hdr.as_bytes();
        rx_q.handle_desc(VsockVirtq::RX.raw(), irq_sender, |desc| {
            if hdr_buf.is_empty() {
                return Ok(Status::Break);
            }
            let c = hdr_buf.read_vectored(&mut desc.writable)? as u32;
            Ok(Status::Done { len: c })
        })?;
        if !hdr_buf.is_empty() {
            log::error!(
                "{}: queue RX: no enough writable buffers for {:?}",
                self.name,
                hdr.op
            );
            return error::InvalidBuffer.fail();
        }
        Ok(())
    }

    fn handle_tx_response<'m, Q, S>(
        &mut self,
        hdr: &VsockHeader,
        registry: &Registry,
        rx_q: &mut Queue<'_, 'm, Q>,
        irq_sender: &S,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        let host_port = hdr.dst_port;
        let guest_port = hdr.src_port;
        let Some(conn) = self.connections.get_mut(&(host_port, guest_port)) else {
            log::warn!(
                "{}: vm:{guest_port} -> host:{host_port}: unknown connection",
                self.name
            );
            return Ok(());
        };
        if conn.state != ConnState::Requested {
            log::error!(
                "{}: vm:{guest_port} -> host:{host_port}: found {:?}, expect {:?}",
                self.name,
                conn.state,
                ConnState::Requested
            );
            return Ok(());
        };
        let acked = writeln!(conn.writer, "OK {host_port}").and_then(|_| conn.writer.flush());
        match acked {
            Ok(()) => {}
            // The host hung up before the guest accepted the connection.
            // `process_rx_data()` below turns this into an RST for the guest.
            Err(e) if is_conn_lost(&e) => {
                log::debug!(
                    "{}: host:{host_port} -> vm:{guest_port}: host closed before accept",
                    self.name
                );
                conn.eof = true;
            }
            Err(e) => return Err(e.into()),
        }
        conn.state = ConnState::Established {
            fwd_cnt: Wrapping(0),
        };
        log::trace!(
            "{}: host:{host_port} -> vm:{guest_port}: established",
            self.name
        );
        self.process_rx_data(host_port, guest_port, registry, rx_q, irq_sender)
    }

    fn remove_conn(&mut self, host_port: u32, guest_port: u32, registry: &Registry) -> Result<()> {
        let Some(conn) = self.connections.remove(&(host_port, guest_port)) else {
            log::warn!(
                "{}: vm:{guest_port} -> host:{host_port}: unknown connection",
                self.name
            );
            return Ok(());
        };
        let reader = conn.reader.into_inner();
        let token = Token(reader.as_raw_fd() as usize);
        self.ports.remove(&token);
        if let Some(count) = self.host_ports.get_mut(&host_port) {
            if *count == 1 {
                self.host_ports.remove(&host_port);
                log::trace!("{}: host:{host_port}: free port", self.name);
            } else {
                *count -= 1;
                log::trace!(
                    "{}: host:{host_port}: count decremented to {count}",
                    self.name
                );
            }
        } else {
            log::error!(
                "{}: vm:{guest_port} -> host:{host_port}: unknown host port",
                self.name
            );
        }
        registry.deregister(&mut SourceFd(&reader.as_raw_fd()))?;
        Ok(())
    }

    fn handle_tx_rst(&mut self, hdr: &VsockHeader, registry: &Registry) -> Result<()> {
        let host_port = hdr.dst_port;
        let guest_port = hdr.src_port;
        self.remove_conn(host_port, guest_port, registry)?;
        log::trace!("{}: vm:{guest_port} -> host:{host_port}: reset", self.name);
        Ok(())
    }

    fn handle_tx_shutdown<'m, Q, S>(
        &mut self,
        hdr: &VsockHeader,
        registry: &Registry,
        irq_sender: &S,
        rx_q: &mut Queue<'_, 'm, Q>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        let host_port = hdr.dst_port;
        let guest_port = hdr.src_port;
        let Some(conn) = self.connections.get_mut(&(host_port, guest_port)) else {
            log::warn!(
                "{}: vm:{guest_port} -> host:{host_port}: unknown connection",
                self.name
            );
            return Ok(());
        };
        let mut flags = if let ConnState::Shutdown { flags } = conn.state {
            flags
        } else {
            ShutdownFlag::empty()
        };
        flags |= ShutdownFlag::from_bits_truncate(hdr.flags);
        if flags != ShutdownFlag::all() {
            conn.state = ConnState::Shutdown { flags };
            log::trace!(
                "{}: vm:{guest_port} -> host:{host_port}: {flags:?}",
                self.name
            );
        } else {
            if let Err(e) = self.respond_rst(hdr, irq_sender, rx_q) {
                log::error!("{}: failed to respond to shutdown: {e:?}", self.name);
            }
            self.remove_conn(host_port, guest_port, registry)?;
            log::trace!(
                "{}: vm:{guest_port} -> host:{host_port}: shutdown",
                self.name
            );
        }
        Ok(())
    }

    fn handle_tx_request<'m, Q, S>(
        &mut self,
        hdr: &VsockHeader,
        registry: &Registry,
        irq_sender: &S,
        rx_q: &mut Queue<'_, 'm, Q>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        let host_port = hdr.dst_port;
        let guest_port = hdr.src_port;
        let port_socket = format!("{}_{host_port}", self.path.to_string_lossy());
        let reader = match UnixStream::connect(&port_socket) {
            Ok(reader) => reader,
            Err(e) => {
                log::error!("{}: failed to connect to {port_socket}: {e:?}", self.name);
                return self.respond_rst(hdr, irq_sender, rx_q);
            }
        };
        reader.set_nonblocking(true)?;
        let writer = reader.try_clone()?;
        let token = Token(reader.as_raw_fd() as usize);
        registry.register(
            &mut SourceFd(&reader.as_raw_fd()),
            token,
            Interest::READABLE,
        )?;
        let buf_size = get_buf_size(&writer)?;
        let conn = Connection {
            reader: BufReader::new(reader),
            writer: BufWriter::new(writer),
            buf_alloc: buf_size as u32,
            eof: false,
            state: ConnState::Established {
                fwd_cnt: Wrapping(0),
            },
        };
        let resp = VsockHeader {
            src_cid: VSOCK_CID_HOST,
            dst_cid: self.config.guest_cid,
            src_port: host_port,
            dst_port: guest_port,
            type_: hdr.type_,
            op: VsockOp::RESPONSE,
            fwd_cnt: Wrapping(0),
            buf_alloc: buf_size as u32,
            ..Default::default()
        };
        self.respond(&resp, irq_sender, rx_q)?;
        self.connections.insert((host_port, guest_port), conn);
        let count = self.host_ports.entry(host_port).or_default();
        *count += 1;
        log::trace!(
            "{}: host:{host_port}: count incremented to {count}",
            self.name
        );
        self.ports.insert(token, (host_port, guest_port));
        log::trace!(
            "{}: vm:{guest_port} -> host:{host_port}: established",
            self.name
        );
        Ok(())
    }

    fn handle_tx_desc<'m, Q, S>(
        &mut self,
        desc: &mut DescChain,
        registry: &Registry,
        irq_sender: &S,
        rx_q: &mut Queue<'_, 'm, Q>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        let name = &*self.name;
        let [buf, readable @ ..] = desc.readable.as_slice() else {
            return error::InvalidBuffer.fail();
        };
        let Some((header, body)) = buf.split_first_chunk::<HEADER_SIZE>() else {
            return error::InvalidBuffer.fail();
        };
        let Ok(hdr) = VsockHeader::ref_from_bytes(header) else {
            return error::InvalidBuffer.fail();
        };
        if hdr.src_cid != self.config.guest_cid || hdr.dst_cid != VSOCK_CID_HOST {
            log::warn!(
                "{name}: invalid CID pair: {} -> {}",
                hdr.src_cid,
                hdr.dst_cid
            );
        }
        log::trace!(
            "{name}: vm:{} -> host:{}: {:?}",
            hdr.src_port,
            hdr.dst_port,
            hdr.op
        );
        match hdr.op {
            VsockOp::REQUEST => self.handle_tx_request(hdr, registry, irq_sender, rx_q),
            VsockOp::RESPONSE => self.handle_tx_response(hdr, registry, rx_q, irq_sender),
            VsockOp::RST => self.handle_tx_rst(hdr, registry),
            VsockOp::RW => self.transfer_tx_data(hdr, body, readable, registry, rx_q, irq_sender),
            VsockOp::CREDIT_UPDATE => {
                log::info!(
                    "{name}: CREDIT_UPDATE: fwd_cnt: {}, buf_alloc: {}",
                    hdr.fwd_cnt,
                    hdr.buf_alloc
                );
                Ok(())
            }
            VsockOp::SHUTDOWN => self.handle_tx_shutdown(hdr, registry, irq_sender, rx_q),
            _ => {
                log::error!("{name}: unsupported operation: {:?}", hdr.op);
                Ok(())
            }
        }
    }

    fn handle_tx<'m, Q, S>(&mut self, active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        let [Some(rx_q), Some(tx_q), ..] = active_mio.queues else {
            let tx_index = VsockVirtq::TX.raw();
            return error::InvalidQueueIndex { index: tx_index }.fail();
        };
        let irq_sender = active_mio.irq_sender;
        let registry = active_mio.poll.registry();
        tx_q.handle_desc(VsockVirtq::TX.raw(), irq_sender, |desc| {
            self.handle_tx_desc(desc, registry, irq_sender, rx_q)?;
            Ok(Status::Done { len: 0 })
        })
    }

    fn transfer_rx_data<'m, Q, S>(
        &mut self,
        host_port: u32,
        guest_port: u32,
        rx_q: &mut Queue<'_, 'm, Q>,
        irq_sender: &S,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        fn copy_to_rx(
            hdr: &mut VsockHeader,
            conn: &mut BufReader<UnixStream>,
            buffers: &mut [IoSliceMut],
        ) -> Result<(usize, bool)> {
            let mut nskip = 0;
            let mut nread = 0;
            let mut eof = false;
            for buf in buffers.iter_mut() {
                let r = if HEADER_SIZE > nskip {
                    let Some((_, data)) = buf.split_at_mut_checked(HEADER_SIZE - nskip) else {
                        nskip += buf.len();
                        continue;
                    };
                    nskip = HEADER_SIZE;
                    if data.is_empty() {
                        continue;
                    }
                    conn.read(data)
                } else {
                    conn.read(buf)
                };
                let n = match r {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => n,
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => Err(e)?,
                };
                nread += n;
            }
            if nskip != HEADER_SIZE {
                return error::InvalidBuffer.fail();
            }
            hdr.len = nread as u32;
            let mut hdr_buf = hdr.as_bytes();
            let _ = hdr_buf.read_vectored(buffers);
            Ok((nread, eof))
        }

        let rx_idx = VsockVirtq::RX.raw();
        let Some(conn) = self.connections.get_mut(&(host_port, guest_port)) else {
            log::warn!(
                "{}: vm:{guest_port} -> host:{host_port}: unknown connection",
                self.name
            );
            return Ok(());
        };
        if conn.eof {
            return Ok(());
        }
        let ConnState::Established { fwd_cnt } = conn.state else {
            // Data can arrive before the guest accepts the connection. It
            // stays buffered in the socket until then.
            log::debug!(
                "{}: host:{host_port} -> vm:{guest_port}: not ready, state {:?}",
                self.name,
                conn.state
            );
            return Ok(());
        };
        let mut hdr = VsockHeader {
            src_cid: VSOCK_CID_HOST,
            dst_cid: self.config.guest_cid,
            src_port: host_port,
            dst_port: guest_port,
            type_: SOCKET_TYPE,
            op: VsockOp::RW,
            fwd_cnt,
            buf_alloc: conn.buf_alloc,
            ..Default::default()
        };
        rx_q.handle_desc(rx_idx, irq_sender, |desc| {
            if conn.eof {
                return Ok(Status::Break);
            }
            let (nread, read_eof) = copy_to_rx(&mut hdr, &mut conn.reader, &mut desc.writable)?;
            conn.eof |= read_eof;
            if nread == 0 {
                return Ok(Status::Break);
            }
            log::trace!(
                "{}: host:{host_port} -> vm:{guest_port}: transfered {nread} bytes",
                self.name
            );
            Ok(Status::Done {
                len: (nread + HEADER_SIZE) as u32,
            })
        })?;
        Ok(())
    }

    fn process_rx_data<'m, Q, S>(
        &mut self,
        host_port: u32,
        guest_port: u32,
        registry: &Registry,
        rx_q: &mut Queue<'_, 'm, Q>,
        irq_sender: &S,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        self.transfer_rx_data(host_port, guest_port, rx_q, irq_sender)?;

        let eof = self
            .connections
            .get(&(host_port, guest_port))
            .is_some_and(|conn| conn.eof);
        if eof && rx_q.desc_avail() {
            let hdr = VsockHeader {
                src_cid: self.config.guest_cid,
                dst_cid: VSOCK_CID_HOST,
                src_port: guest_port,
                dst_port: host_port,
                type_: SOCKET_TYPE,
                ..Default::default()
            };
            self.respond_rst(&hdr, irq_sender, rx_q)?;
            self.remove_conn(host_port, guest_port, registry)?;
        }
        Ok(())
    }

    fn flush_rx_data<'m, Q, S>(
        &mut self,
        registry: &Registry,
        rx_q: &mut Queue<'_, 'm, Q>,
        irq_sender: &S,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        if self.connections.is_empty() {
            return Ok(());
        }
        let mut ports: Vec<_> = self
            .connections
            .iter()
            .map(|(ports, conn)| (*ports, conn.eof))
            .collect();
        // Sort connections to process those with EOF first.
        // !eof maps true to false, and false to true. Since false < true,
        // this puts eof=true connections at the front of the list.
        ports.sort_by_key(|(_, eof)| !eof);
        for ((host_port, guest_port), _) in ports {
            if !rx_q.desc_avail() {
                break;
            }
            self.process_rx_data(host_port, guest_port, registry, rx_q, irq_sender)?;
        }
        Ok(())
    }

    fn transfer_tx_data<'m, Q, S>(
        &mut self,
        hdr: &VsockHeader,
        body: &[u8],
        buffers: &[IoSlice],
        registry: &Registry,
        rx_q: &mut Queue<'_, 'm, Q>,
        irq_sender: &S,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        fn copy_to_conn(
            buf: &[u8],
            conn: &mut BufWriter<UnixStream>,
            remain: &mut usize,
        ) -> io::Result<()> {
            if let Some(b) = buf.get(..*remain) {
                conn.write_all(b)?;
                *remain = 0;
            } else {
                conn.write_all(buf)?;
                *remain -= buf.len();
            }
            Ok(())
        }

        /// Writes up to `len` bytes of `body` and `buffers` to `conn`,
        /// returning the number of bytes that were not covered by the input.
        fn write_to_conn(
            conn: &mut BufWriter<UnixStream>,
            body: &[u8],
            buffers: &[IoSlice],
            len: usize,
        ) -> io::Result<usize> {
            let mut remain = len;
            if !body.is_empty() {
                copy_to_conn(body, conn, &mut remain)?;
            }
            for buf in buffers {
                if remain == 0 {
                    break;
                }
                copy_to_conn(buf, conn, &mut remain)?;
            }
            conn.flush()?;
            Ok(remain)
        }

        let host_port = hdr.dst_port;
        let guest_port = hdr.src_port;
        let Some(conn) = self.connections.get_mut(&(host_port, guest_port)) else {
            log::warn!(
                "{}: vm:{guest_port} -> host:{host_port}: unknown connection",
                self.name
            );
            return Ok(());
        };
        let ConnState::Established { fwd_cnt } = &mut conn.state else {
            log::warn!("{}: invalid connection state {:?}", self.name, conn.state);
            return Ok(());
        };
        match write_to_conn(&mut conn.writer, body, buffers, hdr.len as usize) {
            Ok(0) => {}
            Ok(remain) => {
                log::error!("{}: missing {remain} bytes", self.name);
                return error::InvalidBuffer.fail();
            }
            // The host hung up. Reset this connection only, the rest of the
            // device keeps running.
            Err(e) if is_conn_lost(&e) => {
                log::debug!(
                    "{}: vm:{guest_port} -> host:{host_port}: host closed",
                    self.name
                );
                conn.eof = true;
                return self.process_rx_data(host_port, guest_port, registry, rx_q, irq_sender);
            }
            Err(e) => return Err(e.into()),
        }
        *fwd_cnt += hdr.len;
        log::trace!(
            "{}: vm:{guest_port} -> host:{host_port}: transferred {} bytes",
            self.name,
            hdr.len
        );
        Ok(())
    }
}

impl Drop for UdsVsock {
    fn drop(&mut self) {
        let Ok(addr) = self.listener.local_addr() else {
            return;
        };
        let Some(path) = addr.as_pathname() else {
            return;
        };
        if let Err(e) = fs::remove_file(path) {
            log::error!("{}: error removing {path:?}: {e:?}", self.name);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConnState {
    Requested,
    Established { fwd_cnt: Wrapping<u32> },
    Shutdown { flags: ShutdownFlag },
}

#[derive(Debug)]
pub struct Connection {
    state: ConnState,
    reader: BufReader<UnixStream>,
    writer: BufWriter<UnixStream>,
    buf_alloc: u32,
    eof: bool,
}

impl UdsVsock {
    fn new(spec: UdsVsockSpec, name: impl Into<Arc<str>>) -> Result<Self> {
        let name = name.into();
        let listener = UnixListener::bind(&spec.path)?;
        listener.set_nonblocking(true)?;
        let vsock = UdsVsock {
            name,
            path: spec.path,
            config: Arc::new(VsockConfig {
                guest_cid: spec.cid,
                ..Default::default()
            }),
            listener,
            connections: HashMap::new(),
            sockets: HashMap::new(),
            ports: HashMap::new(),
            host_ports: HashMap::new(),
            next_port: 1024,
        };
        Ok(vsock)
    }
}

impl Virtio for UdsVsock {
    type Config = VsockConfig;
    type Feature = VsockFeature;

    fn id(&self) -> DeviceId {
        DeviceId::SOCKET
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn num_queues(&self) -> u16 {
        3
    }

    fn config(&self) -> Arc<VsockConfig> {
        self.config.clone()
    }

    fn feature(&self) -> u128 {
        VsockFeature::STREAM.bits() | FEATURE_BUILT_IN
    }

    fn spawn_worker<S>(
        self,
        event_rx: Receiver<WakeEvent<S>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[QueueReg]>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>
    where
        S: IrqSender,
    {
        Mio::spawn_worker(self, event_rx, memory, queue_regs)
    }
}

impl VirtioMio for UdsVsock {
    fn activate<'m, Q, S>(
        &mut self,
        _feature: u128,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        active_mio.poll.registry().register(
            &mut SourceFd(&self.listener.as_raw_fd()),
            Token(self.listener.as_raw_fd() as usize),
            Interest::READABLE,
        )?;
        Ok(())
    }

    fn handle_event<'m, Q, S>(
        &mut self,
        event: &Event,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        let token = event.token();
        let registry = active_mio.poll.registry();
        let irq_sender = active_mio.irq_sender;
        let rx_index = VsockVirtq::RX.raw();
        let Some(Some(rx_q)) = active_mio.queues.get_mut(rx_index as usize) else {
            return error::InvalidQueueIndex { index: rx_index }.fail();
        };
        if token.0 == self.listener.as_raw_fd() as usize {
            self.create_socket(registry)
        } else if let Some(pending) = self.sockets.remove(&token) {
            self.handle_conn_request(token, pending, registry, rx_q, irq_sender)
        } else if let Some(port_pair) = self.ports.get(&token) {
            let (host_port, guest_port) = port_pair.to_owned();
            self.process_rx_data(host_port, guest_port, registry, rx_q, irq_sender)
        } else {
            log::error!("{}: invalid token: {token:#x?}", self.name);
            Ok(())
        }
    }

    fn handle_queue<'m, Q, S>(
        &mut self,
        index: u16,
        active_mio: &mut ActiveMio<'_, '_, 'm, Q, S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
    {
        let index = VsockVirtq::from(index);
        let name = &self.name;
        match index {
            VsockVirtq::TX => self.handle_tx(active_mio)?,
            VsockVirtq::RX => {
                log::debug!("{name}: queue RX buffer available");
                let registry = active_mio.poll.registry();
                let irq_sender = active_mio.irq_sender;
                let Some(Some(rx_q)) = active_mio.queues.get_mut(VsockVirtq::RX.raw() as usize)
                else {
                    return error::InvalidQueueIndex {
                        index: VsockVirtq::RX.raw(),
                    }
                    .fail();
                };
                self.flush_rx_data(registry, rx_q, irq_sender)?;
            }
            VsockVirtq::EVENT => log::debug!("{name}: queue EVENT buffer available"),
            _ => log::error!("{name}: unknown queue index {index:?}"),
        }
        Ok(())
    }

    fn reset(&mut self, registry: &Registry) {
        for (_, conn) in self.connections.drain() {
            let reader = conn.reader.into_inner();
            if let Err(err) = registry.deregister(&mut SourceFd(&reader.as_raw_fd())) {
                log::error!("{}: failed to deregister socket: {err}", self.name);
            }
        }
        for (_, pending) in self.sockets.drain() {
            let socket = pending.reader.into_inner();
            if let Err(err) = registry.deregister(&mut SourceFd(&socket.as_raw_fd())) {
                log::error!("{}: failed to deregister socket: {err}", self.name);
            }
        }
        if let Err(err) = registry.deregister(&mut SourceFd(&self.listener.as_raw_fd())) {
            log::error!("{}: failed to deregister listener: {err}", self.name);
        }
        self.host_ports.clear();
        self.next_port = 1024;
    }
}

#[cfg(test)]
#[path = "uds_vsock_test.rs"]
mod tests;
