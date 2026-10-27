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

use bitflags::bitflags;
use thiserror::Error;

#[path = "dev/dev.rs"]
pub mod dev;
#[path = "queue/queue.rs"]
pub mod queue;

#[derive(Debug, Error)]
pub enum Error {
    #[error("System IO error: {0}")]
    SystemIo(#[from] std::io::Error),

    #[error("Invalid descriptor id {0}")]
    InvalidDescriptor(u16),

    #[error("Invalid queue index {0}")]
    InvalidQueueIndex(u16),
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Clone, Copy)]
#[repr(u16)]
pub enum DeviceId {
    Net = 1,
    Block = 2,
    Entropy = 4,
    Balloon = 5,
    Socket = 19,
    Iommu = 23,
    Mem = 24,
    FileSystem = 26,
    Pmem = 27,
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VirtioFeature: u64 {
        const INDIRECT_DESC = 1 << 28;
        const EVENT_IDX = 1 << 29;
        const VERSION_1 = 1 << 32;
        const ACCESS_PLATFORM = 1 << 33;
        const RING_PACKED = 1 << 34;

        const SUPPORTED = Self::INDIRECT_DESC.bits()
            | Self::EVENT_IDX.bits()
            | Self::VERSION_1.bits();
    }
}

pub trait IrqSender: Debug + Send + Sync + 'static {
    fn queue_irq(&self, idx: u16);
    fn config_irq(&self);
}
