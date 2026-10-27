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
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64};

use bitflags::bitflags;
use thiserror::Error;

use crate::mem;

pub mod pci;

pub const QUEUE_SIZE_MAX: u16 = 256;

#[derive(Debug, Default)]
pub struct Queue {
    pub size: AtomicU16,
    pub desc: AtomicU64,
    pub driver: AtomicU64,
    pub device: AtomicU64,
    pub enabled: AtomicBool,
}

#[derive(Debug, Default)]
pub struct Register {
    pub device_feature: u64,
    pub driver_feature: AtomicU64,
    pub device_feature_sel: AtomicU8,
    pub driver_feature_sel: AtomicU8,
    pub queue_sel: AtomicU16,
    pub status: AtomicU8,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor: {0}")]
    Hv(#[from] crate::host::Error),

    #[error("IO: {0}")]
    Io(#[from] std::io::Error),

    #[error("memory: {0}")]
    Memory(#[from] mem::Error),

    #[error("PCI bus: {0}")]
    PciBus(#[from] crate::hw::pci::Error),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VirtioFeature: u64 {
        const INDIRECT_DESC = 1 << 28;
        const EVENT_IDX = 1 << 29;
        const VERSION_1 = 1 << 32;
        const ACCESS_PLATFORM = 1 << 33;
        const RING_PACKED = 1 << 34;
        const SUPPORTED = Self::VERSION_1.bits() | Self::ACCESS_PLATFORM.bits();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceId {
    Net = 1,
    Block = 2,
    Entropy = 4,
    Socket = 19,
    Iommu = 23,
    Mem = 24,
    FileSystem = 26,
    Pmem = 27,
}

impl DeviceId {
    pub fn from_u16(id: u16) -> Self {
        match id {
            1 => DeviceId::Net,
            2 => DeviceId::Block,
            4 => DeviceId::Entropy,
            19 => DeviceId::Socket,
            23 => DeviceId::Iommu,
            24 => DeviceId::Mem,
            26 => DeviceId::FileSystem,
            _ => DeviceId::Pmem,
        }
    }
}

bitflags! {
    #[derive(Debug, Default, Clone, Copy)]
    pub struct DevStatus: u8 {
        const ACK = 1;
        const DRIVER = 2;
        const DRIVER_OK = 4;
        const FEATURES_OK = 8;
        const NEEDS_RESET = 64;
        const FAILED = 128;
    }
}
