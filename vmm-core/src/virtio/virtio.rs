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

use core::fmt::{self, Debug, Display, Formatter};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU64};

use bitflags::bitflags;

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

#[derive(Debug)]
pub enum Error {
    Hv(crate::host::Error),
    Memory(mem::Error),
    PciBus(crate::hw::pci::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hv(e) => write!(f, "hypervisor: {e}"),
            Self::Memory(e) => write!(f, "memory: {e}"),
            Self::PciBus(e) => write!(f, "PCI bus: {e}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<crate::host::Error> for Error {
    fn from(e: crate::host::Error) -> Self {
        Self::Hv(e)
    }
}

impl From<mem::Error> for Error {
    fn from(e: mem::Error) -> Self {
        Self::Memory(e)
    }
}

impl From<crate::hw::pci::Error> for Error {
    fn from(e: crate::hw::pci::Error) -> Self {
        Self::PciBus(e)
    }
}

pub type Result<T, E = Error> = core::result::Result<T, E>;

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
