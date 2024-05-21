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
use std::fs::{self, File};
use std::io;
use std::iter::zip;
use std::mem::MaybeUninit;
use std::num::NonZeroU16;
use std::os::fd::AsRawFd;
use std::os::unix::prelude::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use bitflags::bitflags;
use libc::{IFF_NO_PI, IFF_TAP, IFF_VNET_HDR, O_NONBLOCK};
use mio::event::Event;
use mio::unix::SourceFd;
use mio::{Interest, Registry, Token};
use serde::Deserialize;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::impl_mmio_for_zerocopy;
use crate::mem::mapped::RamBus;
use crate::net::MacAddr;
use crate::virtio::dev::{DevParam, DeviceId, Result, Virtio};
use crate::virtio::queue::handlers::{queue_to_writer, reader_to_queue};
use crate::virtio::queue::VirtQueue;
use crate::virtio::{IrqSender, VirtioFeature};

pub mod tap;

use tap::{tun_get_iff, tun_set_iff, tun_set_offload, tun_set_vnet_hdr_sz, TunFeature};

const QUEUE_RX: u16 = 0;
const QUEUE_TX: u16 = 1;

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
    tap: File,
    feature: NetFeature,
}

#[derive(Deserialize)]
pub struct NetParam {
    pub mac: MacAddr,
    pub mtu: u16,
    pub queue_pairs: Option<NonZeroU16>,
    pub tap: PathBuf,
    pub if_name: Option<String>,
}

impl DevParam for NetParam {
    type Device = Net;

    fn build(self, name: Arc<String>) -> Result<Net> {
        Net::new(self, name)
    }
}

impl Net {
    pub fn new(param: NetParam, name: Arc<String>) -> Result<Self> {
        let mut file = fs::OpenOptions::new()
            .custom_flags(O_NONBLOCK)
            .read(true)
            .write(true)
            .open(param.tap)?;

        setup_tap(&mut file, param.if_name.as_deref())?;
        let net = Net {
            name,
            config: Arc::new(NetConfig {
                mac: param.mac,
                max_queue_pairs: param.queue_pairs.map(|p| p.into()).unwrap_or(1),
                mtu: param.mtu,
                ..Default::default()
            }),
            tap: file,
            feature: NetFeature::MAC
                | NetFeature::MTU
                | NetFeature::GUEST_CSUM
                | NetFeature::GUEST_TSO4
                | NetFeature::GUEST_TSO6
                | NetFeature::GUEST_ECN
                | NetFeature::GUEST_UFO
                | NetFeature::GUEST_USO4
                | NetFeature::GUEST_USO6
                | NetFeature::CSUM
                | NetFeature::HOST_TSO4
                | NetFeature::HOST_TSO6
                | NetFeature::HOST_ECN
                | NetFeature::HOST_UFO
                | NetFeature::HOST_USO,
        };
        Ok(net)
    }
}

impl Virtio for Net {
    type Config = NetConfig;

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
        let _ = registry.deregister(&mut SourceFd(&self.tap.as_raw_fd()));
    }

    fn device_id() -> DeviceId {
        DeviceId::Net
    }

    fn feature(&self) -> u64 {
        self.feature.bits() | VirtioFeature::EVENT_IDX.bits()
    }

    fn activate(&mut self, registry: &Registry, feature: u64, _memory: &RamBus) -> Result<()> {
        let feature = NetFeature::from_bits_retain(feature);
        log::debug!("{}: net feature: {:?}", self.name, feature);
        enable_tap_offload(&mut self.tap, feature)?;
        registry.register(
            &mut SourceFd(&self.tap.as_raw_fd()),
            TOKEN_TAP,
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
        if event.is_readable() {
            let Some(queue) = queues.get(QUEUE_RX as usize) else {
                log::error!("{}: cannot find rx queue", self.name);
                return Ok(());
            };
            reader_to_queue(&self.name, &self.tap, QUEUE_RX, queue, irq_sender)?;
        }
        if event.is_writable() {
            let Some(queue) = queues.get(QUEUE_TX as usize) else {
                log::error!("{}: cannot find tx queue", self.name);
                return Ok(());
            };
            queue_to_writer(&self.name, &self.tap, QUEUE_TX, queue, irq_sender)?;
        }
        Ok(())
    }

    fn handle_queue(
        &mut self,
        index: u16,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        let Some(queue) = queues.get(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        if index == self.config.max_queue_pairs * 2 {
            unimplemented!()
        } else if index & 1 == 0 {
            reader_to_queue(&self.name, &self.tap, index, queue, irq_sender)
        } else {
            queue_to_writer(&self.name, &self.tap, index, queue, irq_sender)
        }
    }
}

pub const TOKEN_TAP: Token = Token(0);

const VNET_HEADER_SIZE: i32 = 12;

fn setup_tap(file: &mut File, if_name: Option<&str>) -> Result<()> {
    let mut tap_ifconfig = match if_name {
        None => unsafe { tun_get_iff(file) }?,
        Some(name) => {
            let mut tap_ifconfig = unsafe { MaybeUninit::<libc::ifreq>::zeroed().assume_init() };
            for (s, d) in zip(name.as_bytes(), tap_ifconfig.ifr_name.as_mut()) {
                *d = *s as i8;
            }
            tap_ifconfig
        }
    };

    tap_ifconfig.ifr_ifru.ifru_flags = (IFF_TAP | IFF_NO_PI | IFF_VNET_HDR) as i16;
    unsafe { tun_set_iff(file, &tap_ifconfig) }?;
    unsafe { tun_set_vnet_hdr_sz(file, &VNET_HEADER_SIZE) }?;
    Ok(())
}

fn enable_tap_offload(tap: &mut File, feature: NetFeature) -> io::Result<i32> {
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
    unsafe { tun_set_offload(tap, tap_feature.bits()) }
}
