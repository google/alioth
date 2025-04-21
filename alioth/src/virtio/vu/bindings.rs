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

use bitfield::bitfield;
use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::c_enum;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(transparent)]
    pub struct VuFeature: u64 {
        const MQ = 1 << 0;
        const LOG_SHMFD = 1 << 1;
        const RARP = 1 << 2;
        const REPLY_ACK = 1 << 3;
        const MTU = 1 << 4;
        const BACKEND_REQ = 1 << 5;
        const CROSS_ENDIAN = 1 << 6;
        const CRYPTO_SESSION = 1 << 7;
        const PAGEFAULT = 1 << 8;
        const CONFIG = 1 << 9;
        const BACKEND_SEND_FD = 1 << 10;
        const HOST_NOTIFIER = 1 << 11;
        const INFLIGHT_SHMFD = 1 << 12;
        const RESET_DEVICE = 1 << 13;
        const INBAND_NOTIFICATIONS = 1 << 14;
        const CONFIGURE_MEM_SLOTS = 1 << 15;
        const STATUS = 1 << 16;
        const XEN_MMAP = 1 << 17;
        const SHARED_OBJECT = 1 << 18;
        const DEVICE_STATE = 1 << 19;
    }
}

c_enum! {
    pub struct VuFrontMsg(u32);
    {
        GET_FEATURES = 1;
        SET_FEATURES = 2;
        SET_OWNER = 3;
        RESET_OWNER = 4;
        SET_MEM_TABLE = 5;
        SET_LOG_BASE = 6;
        SET_LOG_FD = 7;
        SET_VIRTQ_NUM = 8;
        SET_VIRTQ_ADDR = 9;
        SET_VIRTQ_BASE = 10;
        GET_VIRTQ_BASE = 11;
        SET_VIRTQ_KICK = 12;
        SET_VIRTQ_CALL = 13;
        SET_VIRTQ_ERR = 14;
        GET_PROTOCOL_FEATURES = 15;
        SET_PROTOCOL_FEATURES = 16;
        GET_QUEUE_NUM = 17;
        SET_VIRTQ_ENABLE = 18;
        SEND_RARP = 19;
        NET_SET_MTU = 20;
        SET_BACKEND_REQ_FD = 21;
        IOTLB_MSG = 22;
        SET_VIRTQ_ENDIAN = 23;
        GET_CONFIG = 24;
        SET_CONFIG = 25;
        CREATE_CRYPTO_SESSION = 26;
        CLOSE_CRYPTO_SESSION = 27;
        POSTCOPY_ADVISE = 28;
        POSTCOPY_LISTEN = 29;
        POSTCOPY_END = 30;
        GET_INFLIGHT_FD = 31;
        SET_INFLIGHT_FD = 32;
        GPU_SET_SOCKET = 33;
        RESET_DEVICE = 34;
        GET_MAX_MEM_SLOTS = 36;
        ADD_MEM_REG = 37;
        REM_MEM_REG = 38;
        SET_STATUS = 39;
        GET_STATUS = 40;
        GET_SHARED_OBJECT = 41;
        SET_DEVICE_STATE_FD = 42;
        CHECK_DEVICE_STATE = 43;
    }
}

c_enum! {
    pub struct VuFrontMsgSize((u32, usize));
    {
        GET_FEATURES = (0, size_of::<u64>());
    }
}

c_enum! {
    pub struct VuBackMsg(u32);
    {
        IOTLB_MSG = 1;
        CONFIG_CHANGE_MSG = 2;
        VIRTQ_HOST_NOTIFIER_MSG = 3;
        VIRTQ_CALL = 4;
        VIRTQ_ERR = 5;
        SHARED_OBJECT_ADD = 6;
        SHARED_OBJECT_REMOVE = 7;
        SHARED_OBJECT_LOOKUP = 8;
    }
}

bitfield! {
    #[derive(Copy, Clone, Default, IntoBytes, FromBytes, Immutable)]
    #[repr(transparent)]
    pub struct MessageFlag(u32);
    impl Debug;
    pub need_reply, set_need_reply: 3;
    pub reply, set_reply: 2;
    pub version, set_version: 1, 0;
}

impl MessageFlag {
    pub const NEED_REPLY: u32 = 1 << 3;
    pub const REPLY: u32 = 1 << 2;
    pub const VERSION_1: u32 = 0x1;

    pub const fn sender() -> Self {
        MessageFlag(MessageFlag::VERSION_1 | MessageFlag::NEED_REPLY)
    }

    pub const fn receiver() -> Self {
        MessageFlag(MessageFlag::VERSION_1 | MessageFlag::REPLY)
    }
}

#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct VirtqState {
    pub index: u32,
    pub val: u32,
}

#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct VirtqAddr {
    pub index: u32,
    pub flags: u32,
    pub desc_hva: u64,
    pub used_hva: u64,
    pub avail_hva: u64,
    pub log_guest_addr: u64,
}

#[derive(Debug, Clone, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MemoryRegion {
    pub gpa: u64,
    pub size: u64,
    pub hva: u64,
    pub mmap_offset: u64,
}

#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MemorySingleRegion {
    pub _padding: u64,
    pub region: MemoryRegion,
}

#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct MemoryMultipleRegion {
    pub num: u32,
    pub _padding: u32,
    pub regions: [MemoryRegion; 8],
}

#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct DeviceConfig {
    pub offset: u32,
    pub size: u32,
    pub flags: u32,
    pub region: [u8; 256],
}

#[derive(Debug, Clone, FromBytes, Immutable, IntoBytes, KnownLayout)]
#[repr(C)]
pub struct FsMap {
    pub fd_offset: [u64; 8],
    pub cache_offset: [u64; 8],
    pub len: [u64; 8],
    pub flags: [u64; 8],
}

#[derive(Debug, IntoBytes, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct Message {
    pub request: u32,
    pub flag: MessageFlag,
    pub size: u32,
}
