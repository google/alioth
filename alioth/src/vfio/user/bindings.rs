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

use bitfield::bitfield;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::sys::vfio::{VfioDeviceInfoFlag, VfioIrqSetFlag};
use crate::{bitflags, consts};

consts! {
    pub struct VfioUserCmd(u16) {
        VERSION = 1;
        DMA_MAP = 2;
        DMA_UNMAP = 3;
        DEVICE_GET_INFO = 4;
        DEVICE_GET_REGION_INFO = 5;
        DEVICE_GET_REGION_IO_FDS = 6;
        DEVICE_GET_IRQ_INFO = 7;
        DEVICE_SET_IRQS = 8;
        REGION_READ = 9;
        REGION_WRITE = 10;
        DMA_READ = 11;
        DMA_WRITE = 12;
        DEVICE_RESET = 13;
        REGION_WRITE_MULTI = 15;
        DEVICE_FEATURE = 16;
        MIG_DATA_READ = 17;
        MIG_DATA_WRITE = 18;
    }
}

consts! {
    pub struct VfioUserMessageType(u8) {
        COMMAND = 0;
        REPLY = 1;
    }
}

bitfield! {
    #[derive(Copy, Clone, Default, IntoBytes, FromBytes, Immutable, KnownLayout)]
    pub struct VfioUserHeaderFlag(u32);
    impl Debug;
    impl new;
    pub u8, from into VfioUserMessageType, ty, set_ty: 3, 0;
    pub no_reply, set_no_reply: 4;
    pub error, set_error: 5;
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct VfioUserHeader {
    pub msg_id: u16,
    pub cmd: VfioUserCmd,
    pub msg_size: u32,
    pub flags: VfioUserHeaderFlag,
    pub error_no: u32,
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct VfioUserVersion {
    pub major: u16,
    pub minor: u16,
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct VfioUserDeviceInfo {
    pub argsz: u32,
    pub flags: VfioDeviceInfoFlag,
    pub num_regions: u32,
    pub num_irqs: u32,
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct VfioUserIrqSet {
    pub argsz: u32,
    pub flags: VfioIrqSetFlag,
    pub index: u32,
    pub start: u32,
    pub count: u32,
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct VfioUserRegionAccess {
    pub offset: u64,
    pub region: u32,
    pub count: u32,
}

bitflags! {
    pub struct VfioUserDmaMapFlag(u32) {
        READ = 1 << 0;
        WRITE = 1 << 1;
        MMAP = 1 << 2;
        FILE_IO = 1 << 3;
    }
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct VfioUserDmaMap {
    pub argsz: u32,
    pub flags: VfioUserDmaMapFlag,
    pub offset: u64,
    pub addr: u64,
    pub size: u64,
}

#[derive(Debug, Copy, Clone, FromBytes, IntoBytes, Immutable, Default)]
#[repr(C)]
pub struct VfioUserDmaUnmap {
    pub argsz: u32,
    pub flags: u32,
    pub addr: u64,
    pub size: u64,
}
