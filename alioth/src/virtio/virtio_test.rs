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

use std::os::fd::BorrowedFd;
use std::sync::mpsc::Sender;

use crate::virtio::{IrqSender, Result};

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
