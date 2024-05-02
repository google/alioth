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

use bitflags::bitflags;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use crate::unsafe_impl_zerocopy;

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Command: u16 {
        const INTX_DISABLE = 1 << 10;
        const SERR = 1 << 8;
        const PARITY_ERR = 1 << 6;
        const BUS_MASTER = 1 << 2;
        const MEM = 1 << 1;
        const IO = 1 << 0;
        const WRITABLE_BITS = Self::INTX_DISABLE.bits()
            | Self::SERR.bits()
            | Self::PARITY_ERR.bits()
            | Self::BUS_MASTER.bits()
            | Self::MEM.bits()
            | Self::IO.bits();
    }
}
unsafe_impl_zerocopy!(Command, FromBytes, FromZeroes, AsBytes);

bitflags! {
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Status: u16 {
        const PARITY_ERR = 1 << 15;
        const SYSTEM_ERR = 1 << 14;
        const RECEIVED_MASTER_ABORT = 1 << 13;
        const RECEIVED_TARGET_ABORT = 1 << 12;
        const SIGNALED_TARGET_ABORT = 1 << 11;
        const MASTER_PARITY_ERR = 1 << 8;
        const CAP = 1 << 4;
        const INTX = 1 << 3;
        const IMMEDIATE_READINESS = 1 << 0;
        const RW1C_BITS = Self::PARITY_ERR.bits()
            | Self::SYSTEM_ERR.bits()
            | Self::RECEIVED_MASTER_ABORT.bits()
            | Self::RECEIVED_TARGET_ABORT.bits()
            | Self::SIGNALED_TARGET_ABORT.bits()
            | Self::MASTER_PARITY_ERR.bits();
    }
}
unsafe_impl_zerocopy!(Status, FromBytes, FromZeroes, AsBytes);

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum HeaderType {
    Device = 0,
    Bridge = 1,
}

#[derive(Debug, Clone, Default, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(8))]
pub struct CommonHeader {
    pub vendor: u16,
    pub device: u16,
    pub command: Command,
    pub status: Status,
    pub revision: u8,
    pub prog_if: u8,
    pub subclass: u8,
    pub class: u8,
    pub cache_line_size: u8,
    pub latency_timer: u8,
    pub header_type: u8,
    pub bist: u8,
}

#[derive(Debug, Clone, Default, FromBytes, FromZeroes, AsBytes)]
#[repr(C, align(8))]
pub struct DeviceHeader {
    pub common: CommonHeader,
    pub bars: [u32; 6],
    pub cardbus_cis_pointer: u32,
    pub subsystem_vendor: u16,
    pub subsystem: u16,
    pub expansion_rom: u32,
    pub capability_pointer: u8,
    pub reserved: [u8; 7],
    pub intx_line: u8,
    pub intx_pin: u8,
    pub min_gnt: u8,
    pub max_lat: u8,
}
