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

#[cfg(target_os = "linux")]
pub mod tap;
#[cfg(target_os = "macos")]
pub mod vmnet;

use std::fmt::Debug;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::device::net::MacAddr;
use crate::{bitflags, consts, impl_mmio_for_zerocopy};

#[repr(C, align(8))]
#[derive(Debug, Default, FromBytes, Immutable, IntoBytes)]
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

consts! {
    #[derive(Default, FromBytes, Immutable, IntoBytes)]
    pub struct CtrlAck(u8) {
        OK = 0;
        ERR = 1;
    }
}

consts! {
    #[derive(Default, FromBytes, Immutable, IntoBytes)]
    pub struct CtrlClass(u8) {
        MQ = 4;
    }
}

consts! {
    #[derive(Default, FromBytes, Immutable, IntoBytes)]
    pub struct CtrlMq(u8) {
        VQ_PARIS_SET = 0;
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, IntoBytes)]
pub struct CtrlMqParisSet {
    virtq_pairs: u16,
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, Immutable, IntoBytes)]
pub struct CtrlHdr {
    class: CtrlClass,
    command: u8,
}

bitflags! {
    pub struct NetFeature(u128) {
        CSUM = 1 << 0;
        GUEST_CSUM = 1 << 1;
        CTRL_GUEST_OFFLOADS = 1 << 2;
        MTU = 1 << 3;
        MAC = 1 << 5;
        GUEST_TSO4 = 1 << 7;
        GUEST_TSO6 = 1 << 8;
        GUEST_ECN = 1 << 9;
        GUEST_UFO = 1 << 10;
        HOST_TSO4 = 1 << 11;
        HOST_TSO6 = 1 << 12;
        HOST_ECN = 1 << 13;
        HOST_UFO = 1 << 14;
        MRG_RXBUF = 1 << 15;
        STATUS = 1 << 16;
        CTRL_VQ = 1 << 17;
        CTRL_RX = 1 << 18;
        CTRL_VLAN = 1 << 19;
        GUEST_ANNOUNCE = 1 << 21;
        MQ = 1 << 22;
        CTRL_MAC_ADDR = 1 << 23;
        GUEST_USO4 = 1 << 54;
        GUEST_USO6 = 1 << 55;
        HOST_USO = 1 << 56;
        HASH_REPORT = 1 << 57;
        GUEST_HDRLEN = 1 << 59;
        RSS = 1 << 60;
        RSC_EXT = 1 << 61;
        STANDBY = 1 << 62;
        SPEED_DUPLEX = 1 << 63;
    }
}

#[repr(C)]
#[derive(Debug, Default, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct VirtioNetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}
