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

mod uds_vsock;
#[cfg(target_os = "linux")]
mod vhost_vsock;

use std::num::Wrapping;

use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout};

use crate::{bitflags, consts, impl_mmio_for_zerocopy};

pub use self::uds_vsock::{UdsVsock, UdsVsockParam};
#[cfg(target_os = "linux")]
pub use self::vhost_vsock::{VhostVsock, VhostVsockParam};

consts! {
    #[derive(Default, FromBytes, Immutable, IntoBytes)]
    pub struct VsockVirtq(u16) {
        RX = 0;
        TX = 1;
        EVENT = 2;
    }
}

pub const VSOCK_CID_HOST: u32 = 2;

#[derive(Debug, Clone, Copy, Default, FromZeros, Immutable, IntoBytes)]
#[repr(C)]
pub struct VsockConfig {
    pub guest_cid: u32,
    pub guest_cid_hi: u32,
}

impl_mmio_for_zerocopy!(VsockConfig);

bitflags! {
    pub struct VsockFeature(u128) {
        STREAM = 1 << 0;
        SEQPACKET = 1 << 1;
    }
}

consts! {
    #[derive(Default, FromBytes, Immutable, IntoBytes)]
    pub struct VsockOp(u16) {
        INVALID = 0;
        REQUEST = 1;
        RESPONSE = 2;
        RST = 3;
        SHUTDOWN = 4;
        RW = 5;
        CREDIT_UPDATE = 6;
        CREDIT_REQUEST = 7;
    }
}

consts! {
    #[derive(Default, FromBytes, Immutable, IntoBytes)]
    pub struct VsockType(u16) {
        STREAM = 1;
        SEQPACKET = 2;
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C, align(4))]
pub struct VsockHeader {
    src_cid: u32,
    src_cid_hi: u32,
    dst_cid: u32,
    dst_cid_hi: u32,
    src_port: u32,
    dst_port: u32,
    len: u32,
    type_: VsockType,
    op: VsockOp,
    flags: u32,
    buf_alloc: u32,
    fwd_cnt: Wrapping<u32>,
}

bitflags! {
    pub struct ShutdownFlag(u32) {
        RECEIVE = 1 << 0;
        SEND = 1 << 1;
    }
}
