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

//! Motor OS `Tap` backend bridging L2 `virtio-net` Ethernet frames (+ local ARP)
//! to a dedicated L3 `moto_sdk::io::ip_device::IpDevice` registered with `sys-io`.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use moto_sdk::async_runtime::{self, LocalRuntime};
use moto_sdk::io::ip_device::IpDevice;
use moto_sdk::sys_io::api_ip_device::{Cidr, Registration};
use moto_sys::{SysCpu, SysHandle};
use vmm_io::host::{Interest, Token};
use vmm_io::virtio::dev::net::NetFeature;

const VNET_HDR_LEN: usize = 12;
const ETH_HDR_LEN: usize = 14;
const DEFAULT_MTU: u16 = 1500;
const MAX_RX_QUEUE: usize = 256;
const TX_CHANNEL_CAP: usize = 256;

const GATEWAY_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x01];
const DEFAULT_GUEST_MAC: [u8; 6] = [0xa4, 0xa1, 0xc2, 0x00, 0x00, 0x02];

enum WorkerCmd {
    Packet(Vec<u8>),
    Shutdown,
}

struct SharedTapState {
    rx_queue: Mutex<VecDeque<Vec<u8>>>,
    guest_mac: Mutex<[u8; 6]>,
    reg: Mutex<Option<(Token, Interest)>>,
    rx_ready: AtomicBool,
    tx_ready: AtomicBool,
    main_thread: SysHandle,
}

impl SharedTapState {
    fn notify_rx(&self, l2_frame_with_vnet: Vec<u8>) {
        {
            let mut q = self.rx_queue.lock().unwrap();
            if q.len() >= MAX_RX_QUEUE {
                q.pop_front();
            }
            q.push_back(l2_frame_with_vnet);
        }
        self.rx_ready.store(true, Ordering::Release);
        let _ = SysCpu::wake(self.main_thread);
    }
}

pub struct MotorIpTap {
    shared: Arc<SharedTapState>,
    cmd_tx: async_runtime::channel::Sender<WorkerCmd>,
    worker: Mutex<Option<(JoinHandle<()>, std::sync::mpsc::Receiver<()>)>>,
}

fn parse_registration(if_name: Option<&str>, index: usize) -> io::Result<Registration> {
    let raw = if_name.unwrap_or("").trim();
    let (name_part, cidr_part) = match raw.split_once(':') {
        Some((n, c)) => (n.trim(), Some(c.trim())),
        None => (raw, None),
    };

    let dev_name = if name_part.is_empty() {
        format!("vmm{index}")
    } else {
        name_part.to_string()
    };

    let v4_cidr = if let Some(cidr_str) = cidr_part {
        let (ip_s, prefix_s) = cidr_str.split_once('/').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tap CIDR '{cidr_str}', expected A.B.C.D/PREFIX"),
            )
        })?;
        let ip: Ipv4Addr = ip_s.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tap IPv4 '{ip_s}': {e}"),
            )
        })?;
        let prefix_len: u8 = prefix_s.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid tap prefix '{prefix_s}': {e}"),
            )
        })?;
        Cidr {
            address: IpAddr::V4(ip),
            prefix_len,
        }
    } else {
        let subnet_octet = 5u8.saturating_add(index as u8);
        Cidr {
            address: IpAddr::V4(Ipv4Addr::new(192, 168, subnet_octet, 1)),
            prefix_len: 24,
        }
    };

    let net_cidr = v4_cidr.network().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid tap network CIDR: {e:?}"),
        )
    })?;

    Ok(Registration {
        name: dev_name,
        addresses: vec![v4_cidr],
        routes: vec![net_cidr],
        mtu: DEFAULT_MTU,
    })
}

fn finalize_virtio_tx_csum(vnet_hdr: &[u8], eth_frame: &mut [u8]) {
    if (vnet_hdr[0] & 1) == 0 {
        return;
    }
    let csum_start = u16::from_le_bytes([vnet_hdr[6], vnet_hdr[7]]) as usize;
    let csum_offset = u16::from_le_bytes([vnet_hdr[8], vnet_hdr[9]]) as usize;
    let field_pos = csum_start.saturating_add(csum_offset);
    if csum_start >= eth_frame.len() || field_pos.saturating_add(2) > eth_frame.len() {
        return;
    }

    let data = &eth_frame[csum_start..];
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    eth_frame[field_pos..field_pos + 2].copy_from_slice(&csum.to_be_bytes());
}

fn build_arp_reply(
    sender_mac: [u8; 6],
    sender_ip: [u8; 4],
    target_ip: [u8; 4],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(VNET_HDR_LEN + ETH_HDR_LEN + 28);
    out.extend_from_slice(&[0u8; VNET_HDR_LEN]);
    // Ethernet header: dst = guest sender_mac, src = GATEWAY_MAC, ethertype = 0x0806 (ARP)
    out.extend_from_slice(&sender_mac);
    out.extend_from_slice(&GATEWAY_MAC);
    out.extend_from_slice(&0x0806u16.to_be_bytes());
    // ARP payload: htype=1, ptype=0x0800, hlen=6, plen=4, oper=2 (Reply)
    out.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02]);
    out.extend_from_slice(&GATEWAY_MAC);
    out.extend_from_slice(&target_ip);
    out.extend_from_slice(&sender_mac);
    out.extend_from_slice(&sender_ip);
    out
}

fn wrap_ip_in_ethernet(ip_pkt: &[u8], guest_mac: [u8; 6]) -> Option<Vec<u8>> {
    if ip_pkt.is_empty() {
        return None;
    }
    let ethertype: u16 = match ip_pkt[0] >> 4 {
        4 => 0x0800,
        6 => 0x86dd,
        _ => return None,
    };
    let mut frame = Vec::with_capacity(VNET_HDR_LEN + ETH_HDR_LEN + ip_pkt.len());
    frame.extend_from_slice(&[0u8; VNET_HDR_LEN]);
    frame.extend_from_slice(&guest_mac);
    frame.extend_from_slice(&GATEWAY_MAC);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(ip_pkt);
    Some(frame)
}

impl MotorIpTap {
    pub fn open(if_name: Option<&str>, index: usize, main_thread: SysHandle) -> io::Result<Self> {
        let reg = parse_registration(if_name, index)?;
        let shared = Arc::new(SharedTapState {
            rx_queue: Mutex::new(VecDeque::with_capacity(64)),
            guest_mac: Mutex::new(DEFAULT_GUEST_MAC),
            reg: Mutex::new(None),
            rx_ready: AtomicBool::new(false),
            tx_ready: AtomicBool::new(false),
            main_thread,
        });

        let (cmd_tx, mut cmd_rx) = async_runtime::channel(TX_CHANNEL_CAP);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<Result<(), String>>(1);
        let (done_tx, done_rx) = std::sync::mpsc::sync_channel::<()>(1);

        let worker_shared = Arc::clone(&shared);
        let dev_name = reg.name.clone();
        let handle = thread::Builder::new()
            .name(format!("vmm-ip-{dev_name}"))
            .spawn(move || {
                LocalRuntime::new().block_on(async move {
                    let mut device = match IpDevice::register(&reg).await {
                        Ok(dev) => {
                            let _ = ready_tx.send(Ok(()));
                            dev
                        }
                        Err(err) => {
                            let _ = ready_tx.send(Err(format!(
                                "IpDevice::register('{}') failed: {err:?} (ensure CAP_NET and Interactive/System role)",
                                reg.name
                            )));
                            return;
                        }
                    };

                    {
                        let (ip_tx, mut ip_rx) = device.split();
                        let rx_shared = Arc::clone(&worker_shared);

                        let mut rx_fut = pin!(async move {
                            let mut buf = [0u8; 4096];
                            loop {
                                match ip_rx.receive(&mut buf).await {
                                    Ok(len) => {
                                        let gmac = *rx_shared.guest_mac.lock().unwrap();
                                        if let Some(frame) = wrap_ip_in_ethernet(&buf[..len], gmac)
                                        {
                                            rx_shared.notify_rx(frame);
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        });

                        let mut tx_fut = pin!(async move {
                            while let Some(cmd) = cmd_rx.recv().await {
                                match cmd {
                                    WorkerCmd::Packet(pkt) => {
                                        let _ = ip_tx.send(&pkt).await;
                                    }
                                    WorkerCmd::Shutdown => break,
                                }
                            }
                        });

                        core::future::poll_fn(|cx| {
                            if tx_fut.as_mut().poll(cx).is_ready() {
                                return Poll::Ready(());
                            }
                            if rx_fut.as_mut().poll(cx).is_ready() {
                                return Poll::Ready(());
                            }
                            Poll::Pending
                        })
                        .await;
                    }

                    let _ = device.unregister().await;
                });
                let _ = done_tx.send(());
            })
            .map_err(|e| io::Error::other(format!("failed to spawn IpDevice thread: {e}")))?;

        match ready_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(Ok(())) => Ok(Self {
                shared,
                cmd_tx,
                worker: Mutex::new(Some((handle, done_rx))),
            }),
            Ok(Err(msg)) => {
                let _ = handle.join();
                Err(io::Error::new(io::ErrorKind::PermissionDenied, msg))
            }
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "timed out registering IpDevice with sys-io",
            )),
        }
    }

    pub fn detected_offload(&self) -> NetFeature {
        NetFeature::GUEST_CSUM
    }

    pub fn register(&self, token: Token, interests: Interest) -> io::Result<()> {
        *self.shared.reg.lock().unwrap() = Some((token, interests));
        if interests.contains(Interest::READABLE)
            && !self.shared.rx_queue.lock().unwrap().is_empty()
        {
            self.shared.rx_ready.store(true, Ordering::Release);
        }
        if interests.contains(Interest::WRITABLE) {
            self.shared.tx_ready.store(true, Ordering::Release);
        }
        let _ = SysCpu::wake(self.shared.main_thread);
        Ok(())
    }

    pub fn deregister(&self) {
        *self.shared.reg.lock().unwrap() = None;
    }

    pub fn take_poll_event(&self) -> Option<(Token, u8, u8)> {
        let (token, interests) = (*self.shared.reg.lock().unwrap())?;
        let r = interests.contains(Interest::READABLE)
            && self.shared.rx_ready.swap(false, Ordering::AcqRel);
        let w = interests.contains(Interest::WRITABLE)
            && self.shared.tx_ready.swap(false, Ordering::AcqRel);
        if r || w {
            Some((token, u8::from(r), u8::from(w)))
        } else {
            None
        }
    }

    pub fn read_frame(&self, dst: &mut [u8]) -> io::Result<usize> {
        let mut q = self.shared.rx_queue.lock().unwrap();
        let Some(frame) = q.pop_front() else {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        };
        let n = frame.len().min(dst.len());
        dst[..n].copy_from_slice(&frame[..n]);
        Ok(n)
    }

    pub fn write_frame(&self, src: &[u8]) -> io::Result<usize> {
        if src.len() < VNET_HDR_LEN + ETH_HDR_LEN {
            return Ok(src.len());
        }
        let vnet_hdr = &src[..VNET_HDR_LEN];
        let mut eth = src[VNET_HDR_LEN..].to_vec();
        finalize_virtio_tx_csum(vnet_hdr, &mut eth);

        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&eth[6..12]);
        if (src_mac[0] & 1) == 0 && src_mac != [0; 6] {
            *self.shared.guest_mac.lock().unwrap() = src_mac;
        }

        let ethertype = u16::from_be_bytes([eth[12], eth[13]]);
        let payload = &eth[ETH_HDR_LEN..];

        match ethertype {
            0x0806 => {
                // ARP Request -> synthesize immediate local ARP Reply for gateway / routed IPs
                if payload.len() >= 28 {
                    let htype = u16::from_be_bytes([payload[0], payload[1]]);
                    let ptype = u16::from_be_bytes([payload[2], payload[3]]);
                    let oper = u16::from_be_bytes([payload[6], payload[7]]);
                    if htype == 1 && ptype == 0x0800 && payload[4] == 6 && payload[5] == 4 && oper == 1
                    {
                        let mut sha = [0u8; 6];
                        let mut spa = [0u8; 4];
                        let mut tpa = [0u8; 4];
                        sha.copy_from_slice(&payload[8..14]);
                        spa.copy_from_slice(&payload[14..18]);
                        tpa.copy_from_slice(&payload[24..28]);
                        if tpa != spa {
                            let reply = build_arp_reply(sha, spa, tpa);
                            self.shared.notify_rx(reply);
                        }
                    }
                }
                Ok(src.len())
            }
            0x0800 => {
                if payload.len() >= 20 {
                    let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
                    let trimmed = if (20..=payload.len()).contains(&total_len) {
                        &payload[..total_len]
                    } else {
                        payload
                    };
                    if trimmed.len() <= DEFAULT_MTU as usize {
                        let _ = async_runtime::block_on_sync(
                            self.cmd_tx.send(WorkerCmd::Packet(trimmed.to_vec())),
                        );
                    }
                }
                Ok(src.len())
            }
            0x86dd => {
                if payload.len() >= 40 {
                    let payload_len = u16::from_be_bytes([payload[4], payload[5]]) as usize;
                    let total_len = 40usize.saturating_add(payload_len);
                    let trimmed = if total_len <= payload.len() {
                        &payload[..total_len]
                    } else {
                        payload
                    };
                    if trimmed.len() <= DEFAULT_MTU as usize {
                        let _ = async_runtime::block_on_sync(
                            self.cmd_tx.send(WorkerCmd::Packet(trimmed.to_vec())),
                        );
                    }
                }
                Ok(src.len())
            }
            _ => Ok(src.len()),
        }
    }

    pub fn close(&self) {
        if let Some((handle, done_rx)) = self.worker.lock().unwrap().take() {
            let _ = async_runtime::block_on_sync(self.cmd_tx.send(WorkerCmd::Shutdown));
            if done_rx.recv_timeout(Duration::from_secs(2)).is_ok() {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for MotorIpTap {
    fn drop(&mut self) {
        self.close();
    }
}
