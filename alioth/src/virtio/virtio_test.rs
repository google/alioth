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

use std::os::fd::{AsFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
use std::sync::mpsc::Sender;

use rstest::fixture;

use crate::hv::IoeventFd;
use crate::mem::mapped::{ArcMemPages, RamBus};
use crate::virtio::queue::{QUEUE_SIZE_MAX, QueueReg};
use crate::virtio::{IrqSender, Result};

pub const MEM_SIZE: usize = 2 << 20;
pub const QUEUE_SIZE: u16 = QUEUE_SIZE_MAX;
pub const DESC_ADDR: u64 = 0x1000;
pub const AVAIL_ADDR: u64 = 0x2000;
pub const USED_ADDR: u64 = 0x3000;
pub const DATA_ADDR: u64 = 0x4000;

#[fixture]
pub fn fixture_ram_bus() -> RamBus {
    let host_pages = ArcMemPages::from_anonymous(MEM_SIZE, None, None).unwrap();
    let ram_bus = RamBus::new();
    ram_bus.add(0, host_pages).unwrap();
    ram_bus
}

#[fixture]
pub fn fixture_queue() -> QueueReg {
    QueueReg {
        size: AtomicU16::new(QUEUE_SIZE),
        desc: AtomicU64::new(DESC_ADDR),
        driver: AtomicU64::new(AVAIL_ADDR),
        device: AtomicU64::new(USED_ADDR),
        enabled: AtomicBool::new(true),
    }
}

#[derive(Debug)]
pub struct FakeIrqSender {
    pub q_tx: Sender<u16>,
}

impl IrqSender for FakeIrqSender {
    fn queue_irq(&self, idx: u16) {
        self.q_tx.send(idx).unwrap();
    }

    fn config_irq(&self) {
        unimplemented!()
    }

    fn queue_irqfd<F, T>(&self, _idx: u16, _f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        unimplemented!()
    }

    fn config_irqfd<F, T>(&self, _f: F) -> Result<T>
    where
        F: FnOnce(BorrowedFd) -> Result<T>,
    {
        unimplemented!()
    }
}

#[derive(Debug, Default)]
pub struct FakeIoeventFd;

impl AsFd for FakeIoeventFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unreachable!()
    }
}

impl IoeventFd for FakeIoeventFd {}
