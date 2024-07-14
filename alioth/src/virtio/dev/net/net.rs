// Copyright 2024 Google LLC
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

use std::fmt::Debug;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, IoSlice};
use std::mem::MaybeUninit;
use std::num::NonZeroU16;
use std::os::fd::AsRawFd;
use std::os::unix::prelude::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bitflags::bitflags;
use libc::{IFF_MULTI_QUEUE, IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, O_NONBLOCK};
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::mem::mapped::RamBus;
use crate::net::MacAddr;
use crate::virtio::dev::{DevParam, DeviceId, Result, Virtio};
use crate::virtio::queue::handlers::{handle_desc, queue_to_writer, reader_to_queue};
use crate::virtio::queue::{Descriptor, Queue, VirtQueue};
use crate::virtio::{error, IrqSender, FEATURE_BUILT_IN};
use crate::{c_enum, impl_mmio_for_zerocopy};

pub mod tap;

use tap::{tun_set_iff, tun_set_offload, tun_set_vnet_hdr_sz, TunFeature};

#[repr(C, align(8))]
#[derive(Debug, Default, FromBytes, FromZeroes, AsBytes)]
pub struct NetConfig {
    mac: MacAddr,
    status: u16,
    max_queue_pairs: u16,
    mtu: u16,
    speed: u32,
    duplex: u8,
    rss_max_key_size: u8,
    rss_max_indirection_table_length: u16,
    supported_hash_types: u32,
}

impl_mmio_for_zerocopy!(NetConfig);

c_enum! {
    #[derive(FromBytes, FromZeroes)]
    struct CtrlAck(u8);
    {
        OK = 0;
        ERR = 1;
    }
}

c_enum! {
    #[derive(FromBytes, FromZeroes)]
    struct CtrlClass(u8);
    {
        MQ = 4;
    }
}

c_enum! {
    struct CtrlMq(u8);
    {
        VQ_PARIS_SET = 0;
    }
}

#[repr(C)]
#[derive(Debug, FromBytes, FromZeroes)]
struct CtrlMqParisSet {
    virtq_pairs: u16,
}

#[repr(C)]
#[derive(Debug, FromBytes, FromZeroes)]
struct CtrlHdr {
    class: CtrlClass,
    command: u8,
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct NetFeature: u64 {
        const CSUM = 1 << 0;
        const GUEST_CSUM = 1 << 1;
        const CTRL_GUEST_OFFLOADS = 1 << 2;
        const MTU = 1 << 3;
        const MAC = 1 << 5;
        const GUEST_TSO4 = 1 << 7;
        const GUEST_TSO6 = 1 << 8;
        const GUEST_ECN = 1 << 9;
        const GUEST_UFO = 1 << 10;
        const HOST_TSO4 = 1 << 11;
        const HOST_TSO6 = 1 << 12;
        const HOST_ECN = 1 << 13;
        const HOST_UFO = 1 << 14;
        const MRG_RXBUF = 1 << 15;
        const STATUS = 1 << 16;
        const CTRL_VQ = 1 << 17;
        const CTRL_RX = 1 << 18;
        const CTRL_VLAN = 1 << 19;
        const GUEST_ANNOUNCE = 1 << 21;
        const MQ = 1 << 22;
        const CTRL_MAC_ADDR = 1 << 23;
        const GUEST_USO4 = 1 << 54;
        const GUEST_USO6 = 1 << 55;
        const HOST_USO = 1 << 56;
        const HASH_REPORT = 1 << 57;
        const GUEST_HDRLEN = 1 << 59;
        const RSS = 1 << 60;
        const RSC_EXT = 1 << 61;
        const STANDBY = 1 << 62;
        const SPEED_DUPLEX = 1 << 63;
        const INDIRECT_DESC = 1 << 28;
    }
}

#[derive(Debug)]
pub struct Net {
    name: Arc<String>,
    config: Arc<NetConfig>,
    tap_sockets: Vec<File>,
    feature: NetFeature,
    driver_feature: NetFeature,
    dev_tap: Option<PathBuf>,
    if_name: Option<String>,
}

#[derive(Deserialize)]
pub struct NetParam {
    pub mac: MacAddr,
    pub mtu: u16,
    pub queue_pairs: Option<NonZeroU16>,
    pub tap: Option<PathBuf>,
    #[serde(alias = "if")]
    pub if_name: Option<String>,
}

impl DevParam for NetParam {
    type Device = Net;

    fn build(self, name: Arc<String>) -> Result<Net> {
        Net::new(self, name)
    }
}

fn new_socket(dev_tap: Option<&Path>) -> Result<File> {
    let tap_dev = dev_tap.unwrap_or(Path::new("/dev/net/tun"));
    let socket = OpenOptions::new()
        .custom_flags(O_NONBLOCK)
        .read(true)
        .write(true)
        .open(tap_dev)?;
    Ok(socket)
}

impl Net {
    pub fn new(param: NetParam, name: Arc<String>) -> Result<Self> {
        let mut socket = new_socket(param.tap.as_deref())?;
        let mut dev_feat = NetFeature::MAC
            | NetFeature::MTU
            | NetFeature::CSUM
            | NetFeature::HOST_TSO4
            | NetFeature::HOST_TSO6
            | NetFeature::HOST_ECN
            | NetFeature::HOST_UFO
            | NetFeature::HOST_USO
            | NetFeature::CTRL_VQ
            | detect_tap_offload(&socket);
        let max_queue_pairs = param.queue_pairs.map(From::from).unwrap_or(1);
        if max_queue_pairs > 1 {
            dev_feat |= NetFeature::MQ;
        }
        setup_socket(&mut socket, param.if_name.as_deref(), max_queue_pairs > 1)?;
        let net = Net {
            name,
            config: Arc::new(NetConfig {
                mac: param.mac,
                max_queue_pairs,
                mtu: param.mtu,
                ..Default::default()
            }),
            tap_sockets: vec![socket],
            feature: dev_feat,
            driver_feature: NetFeature::empty(),
            dev_tap: param.tap,
            if_name: param.if_name,
        };
        Ok(net)
    }

    fn handle_ctrl_queue(
        &mut self,
        desc: &mut Descriptor,
        registry: &Registry,
    ) -> Result<Option<usize>> {
        let Some(header) = desc.readable.first().and_then(|b| CtrlHdr::ref_from(b)) else {
            return error::InvalidBuffer.fail();
        };
        let Some(ack_byte) = desc.writable.first_mut().and_then(|v| v.first_mut()) else {
            return error::InvalidBuffer.fail();
        };
        let ack = match header.class {
            CtrlClass::MQ => match CtrlMq(header.command) {
                CtrlMq::VQ_PARIS_SET => {
                    let to_set = |b: &IoSlice| CtrlMqParisSet::read_from(b);
                    let Some(data) = desc.readable.get(1).and_then(to_set) else {
                        return error::InvalidBuffer.fail();
                    };
                    let pairs = data.virtq_pairs as usize;
                    self.tap_sockets.truncate(pairs);
                    for index in self.tap_sockets.len()..pairs {
                        let mut socket = new_socket(self.dev_tap.as_deref())?;
                        setup_socket(&mut socket, self.if_name.as_deref(), true)?;
                        enable_tap_offload(&mut socket, self.driver_feature)?;
                        registry.register(
                            &mut SourceFd(&socket.as_raw_fd()),
                            Token(index),
                            Interest::READABLE | Interest::WRITABLE,
                        )?;
                        self.tap_sockets.push(socket);
                    }
                    log::info!("{}: using {pairs} pairs of queues", self.name);
                    CtrlAck::OK
                }
                _ => CtrlAck::ERR,
            },
            _ => CtrlAck::ERR,
        };
        *ack_byte = ack.raw();
        Ok(Some(1))
    }
}

impl Virtio for Net {
    type Config = NetConfig;
    type Feature = NetFeature;

    fn num_queues(&self) -> u16 {
        let data_queues = self.config.max_queue_pairs << 1;
        if self.feature.contains(NetFeature::CTRL_VQ) {
            data_queues + 1
        } else {
            data_queues
        }
    }

    fn config(&self) -> Arc<NetConfig> {
        self.config.clone()
    }

    fn reset(&mut self, registry: &Registry) {
        self.tap_sockets.truncate(1);
        let _ = registry.deregister(&mut SourceFd(&self.tap_sockets[0].as_raw_fd()));
    }

    fn device_id() -> DeviceId {
        DeviceId::Net
    }

    fn feature(&self) -> u64 {
        self.feature.bits() | FEATURE_BUILT_IN
    }

    fn activate(
        &mut self,
        registry: &Registry,
        feature: u64,
        _memory: &RamBus,
        _irq_sender: &impl IrqSender,
        _queues: &[Queue],
    ) -> Result<()> {
        self.driver_feature = NetFeature::from_bits_retain(feature);
        let socket = &mut self.tap_sockets[0];
        enable_tap_offload(socket, self.driver_feature)?;
        registry.register(
            &mut SourceFd(&socket.as_raw_fd()),
            Token(0),
            Interest::READABLE | Interest::WRITABLE,
        )?;
        Ok(())
    }

    fn handle_event(
        &mut self,
        event: &Event,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        let token = event.token().0;
        if event.is_readable() {
            let rx_queue_index = token << 1;
            let Some(queue) = queues.get(rx_queue_index) else {
                log::error!("{}: cannot find rx queue {rx_queue_index}", self.name);
                return Ok(());
            };
            let Some(socket) = self.tap_sockets.get(token) else {
                log::error!("{}: cannot find tap queue {token}", self.name);
                return Ok(());
            };
            reader_to_queue(&self.name, socket, rx_queue_index as u16, queue, irq_sender)?;
        }
        if event.is_writable() {
            let tx_queue_index = (token << 1) + 1;
            let Some(queue) = queues.get(tx_queue_index) else {
                log::error!("{}: cannot find tx queue {tx_queue_index}", self.name);
                return Ok(());
            };
            let Some(socket) = self.tap_sockets.get(token) else {
                log::error!("{}: cannot find tap queue {token}", self.name);
                return Ok(());
            };
            queue_to_writer(&self.name, socket, tx_queue_index as u16, queue, irq_sender)?;
        }
        Ok(())
    }

    fn handle_queue(
        &mut self,
        index: u16,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
        registry: &Registry,
    ) -> Result<()> {
        let Some(queue) = queues.get(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        if index == self.config.max_queue_pairs * 2 {
            let name = self.name.clone();
            return handle_desc(&name, index, queue, irq_sender, |desc| {
                self.handle_ctrl_queue(desc, registry)
            });
        }
        let Some(socket) = self.tap_sockets.get(index as usize >> 1) else {
            log::error!("{}: invalid tap queue {}", self.name, index >> 1);
            return Ok(());
        };
        if index & 1 == 0 {
            reader_to_queue(&self.name, socket, index, queue, irq_sender)
        } else {
            queue_to_writer(&self.name, socket, index, queue, irq_sender)
        }
    }
}

const VNET_HEADER_SIZE: i32 = 12;

fn setup_socket(file: &mut File, if_name: Option<&str>, mq: bool) -> Result<()> {
    let mut tap_ifconfig = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };

    if let Some(name) = if_name {
        let name_len = std::cmp::min(tap_ifconfig.ifr_name.len() - 1, name.len());
        tap_ifconfig.ifr_name.as_bytes_mut()[0..name_len]
            .copy_from_slice(&name.as_bytes()[0..name_len]);
    }

    let mut flags = IFF_TAP | IFF_NO_PI | IFF_VNET_HDR;
    if mq {
        flags |= IFF_MULTI_QUEUE;
    }
    tap_ifconfig.ifr_ifru.ifru_flags = flags as i16;

    unsafe { tun_set_iff(file, &tap_ifconfig) }.or_else(|e| {
        if e.kind() == ErrorKind::InvalidInput && !mq {
            flags |= IFF_MULTI_QUEUE;
            tap_ifconfig.ifr_ifru.ifru_flags = flags as i16;
            unsafe { tun_set_iff(file, &tap_ifconfig) }
        } else {
            Err(e)
        }
    })?;

    unsafe { tun_set_vnet_hdr_sz(file, &VNET_HEADER_SIZE) }?;
    Ok(())
}

fn detect_tap_offload(tap: &impl AsRawFd) -> NetFeature {
    let mut tap_feature = TunFeature::all();
    let mut dev_feat = NetFeature::GUEST_CSUM
        | NetFeature::GUEST_TSO4
        | NetFeature::GUEST_TSO6
        | NetFeature::GUEST_ECN
        | NetFeature::GUEST_UFO
        | NetFeature::GUEST_USO4
        | NetFeature::GUEST_USO6;
    if unsafe { tun_set_offload(tap, tap_feature.bits()) }.is_ok() {
        return dev_feat;
    }
    tap_feature &= !(TunFeature::USO4 | TunFeature::USO6);
    dev_feat &= !(NetFeature::GUEST_USO4 | NetFeature::GUEST_USO6);
    if unsafe { tun_set_offload(tap, tap_feature.bits()) }.is_ok() {
        return dev_feat;
    }
    tap_feature &= !(TunFeature::UFO);
    dev_feat &= !NetFeature::GUEST_UFO;
    if unsafe { tun_set_offload(tap, tap_feature.bits()) }.is_ok() {
        return dev_feat;
    }
    NetFeature::empty()
}

fn enable_tap_offload(tap: &mut File, feature: NetFeature) -> Result<()> {
    let mut tap_feature = TunFeature::empty();
    if feature.contains(NetFeature::GUEST_CSUM) {
        tap_feature |= TunFeature::CSUM;
    }
    if feature.contains(NetFeature::GUEST_TSO4) {
        tap_feature |= TunFeature::TSO4;
    }
    if feature.contains(NetFeature::GUEST_TSO6) {
        tap_feature |= TunFeature::TSO6;
    }
    if feature.contains(NetFeature::GUEST_ECN) {
        tap_feature |= TunFeature::TSO_ECN;
    }
    if feature.contains(NetFeature::GUEST_UFO) {
        tap_feature |= TunFeature::UFO;
    }
    if feature.contains(NetFeature::GUEST_USO4) {
        tap_feature |= TunFeature::USO4;
    }
    if feature.contains(NetFeature::GUEST_USO6) {
        tap_feature |= TunFeature::USO6;
    }
    unsafe { tun_set_offload(tap, tap_feature.bits()) }?;
    Ok(())
}
