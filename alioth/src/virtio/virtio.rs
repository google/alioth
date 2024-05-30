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
use std::os::fd::RawFd;

use bitflags::bitflags;
use thiserror::Error;

use crate::{hv, mem};

#[path = "dev/dev.rs"]
pub mod dev;
pub mod pci;
#[path = "queue/queue.rs"]
pub mod queue;
pub mod vu;

#[derive(Debug, Error)]
pub enum Error {
    #[error("hypervisor: {0}")]
    Hv(#[from] hv::Error),

    #[error("IO: {0}")]
    Io(#[from] std::io::Error),

    #[error("memory: {0}")]
    Memory(#[from] mem::Error),

    #[error("PCI bus: {0}")]
    PciBus(#[from] crate::pci::Error),

    #[error("Invalid descriptor id {0}")]
    InvalidDescriptor(u16),

    #[error("invalid queue index {0}")]
    InvalidQueueIndex(u16),

    #[error("invalid msix vector {0}")]
    InvalidMsixVector(u16),

    #[error("Invalid vhost user response message, want {0}, got {1}")]
    InvalidVhostRespMsg(u32, u32),

    #[error("Invalid vhost user response size, want {0}, get {1}")]
    InvalidVhostRespSize(usize, usize),

    #[error("Invalid vhost user response payload size, want {0}, got {1}")]
    InvalidVhostRespPayloadSize(usize, u32),

    #[error("vhost-user backend replied error code {0:#x} to request {1:#x}")]
    VuRequestErr(u64, u32),

    #[error("vhost-user backend signals an error of queue {0:#x}")]
    VuQueueErr(u16),
}

type Result<T, E = Error> = std::result::Result<T, E>;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VirtioFeature: u64 {
        const INDIRECT_DESC = 1 << 28;
        const EVENT_IDX = 1 << 29;
        const VHOST_PROTOCOL = 1 << 30;
        const VERSION_1 = 1 << 32;
        const ACCESS_PLATFORM = 1 << 33;
        const RING_PACKED = 1 << 34;
    }
}

const FEATURE_BUILT_IN: u64 = VirtioFeature::EVENT_IDX.bits()
    | VirtioFeature::VERSION_1.bits()
    | VirtioFeature::ACCESS_PLATFORM.bits();

#[derive(Debug, Clone, Copy)]
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

pub trait IrqSender: Send + Sync + Debug + 'static {
    fn queue_irq(&self, idx: u16);
    fn config_irq(&self);
    fn queue_irqfd(&self, idx: u16) -> Result<RawFd>;
    fn config_irqfd(&self) -> Result<RawFd>;
}
