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

#[cfg(test)]
#[path = "virtio_test.rs"]
mod tests;

#[path = "dev/dev.rs"]
pub mod dev;
pub mod pci;
#[path = "queue/queue.rs"]
pub mod queue;
#[cfg(target_os = "linux")]
pub mod vhost;
#[cfg(target_os = "linux")]
#[path = "vu/vu.rs"]
pub mod vu;
#[path = "worker/worker.rs"]
pub mod worker;

use std::fmt::Debug;
use std::os::fd::BorrowedFd;
use std::path::PathBuf;

use bitflags::bitflags;
use snafu::Snafu;

use crate::errors::{DebugTrace, trace_error};

#[trace_error]
#[derive(Snafu, DebugTrace)]
#[snafu(module, context(suffix(false)))]
pub enum Error {
    #[snafu(display("Hypervisor internal error"), context(false))]
    HvError { source: Box<crate::hv::Error> },
    #[snafu(display("Failed to access guest memory"), context(false))]
    Memory { source: Box<crate::mem::Error> },
    #[snafu(display("PCI bus error"), context(false))]
    PciBus { source: crate::pci::Error },
    #[snafu(display("Cannot access file {path:?}"))]
    AccessFile {
        path: PathBuf,
        error: std::io::Error,
    },
    #[snafu(display("Error from OS"), context(false))]
    System { error: std::io::Error },
    #[snafu(display("Failed to create a poll"))]
    CreatePoll { error: std::io::Error },
    #[snafu(display("Failed to create a thread waker"))]
    CreateWaker { error: std::io::Error },
    #[snafu(display("Failed to register/deregister an event source"))]
    EventSource { error: std::io::Error },
    #[snafu(display("Failed to poll events"))]
    PollEvents { error: std::io::Error },
    #[snafu(display("Failed to create a worker thread"))]
    WorkerThread { error: std::io::Error },
    #[snafu(display("Invalid descriptor id {id}"))]
    InvalidDescriptor { id: u16 },
    #[snafu(display("Invalid queue index {index}"))]
    InvalidQueueIndex { index: u16 },
    #[snafu(display("Invalid msix vector {vector}"))]
    InvalidMsixVector { vector: u16 },
    #[snafu(display("Invalid virtq buffer"))]
    InvalidBuffer,
    #[cfg(target_os = "linux")]
    #[snafu(display("vhost-user error"), context(false))]
    Vu { source: Box<vu::Error> },
    #[cfg(target_os = "linux")]
    #[snafu(display("vhost error"), context(false))]
    Vhost { source: Box<vhost::Error> },
    #[snafu(display("fuse error"), context(false))]
    Fuse { source: Box<crate::fuse::Error> },
}

type Result<T, E = Error> = std::result::Result<T, E>;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VirtioFeature: u128 {
        const INDIRECT_DESC = 1 << 28;
        const EVENT_IDX = 1 << 29;
        const VHOST_PROTOCOL = 1 << 30;
        const VERSION_1 = 1 << 32;
        const ACCESS_PLATFORM = 1 << 33;
        const RING_PACKED = 1 << 34;
    }
}

const FEATURE_BUILT_IN: u128 = VirtioFeature::EVENT_IDX.bits()
    | VirtioFeature::RING_PACKED.bits()
    | VirtioFeature::VERSION_1.bits();

#[derive(Debug, Clone, Copy)]
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
    fn queue_irqfd<F, T>(&self, idx: u16, f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>;
    fn config_irqfd<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>;
}
