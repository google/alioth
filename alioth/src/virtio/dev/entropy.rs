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
use std::fs::{File, OpenOptions};
use std::os::unix::prelude::OpenOptionsExt;
use std::sync::Arc;

use bitflags::bitflags;
use libc::O_NONBLOCK;
use mio::event::Event;
use mio::Registry;
use snafu::ResultExt;

use crate::mem;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::RamBus;
use crate::virtio::dev::{DevParam, DeviceId, Virtio};
use crate::virtio::queue::handlers::reader_to_queue;
use crate::virtio::queue::{Queue, VirtQueue};
use crate::virtio::{error, IrqSender, Result, FEATURE_BUILT_IN};

#[derive(Debug, Clone)]
pub struct EntropyConfig;

impl Mmio for EntropyConfig {
    fn size(&self) -> u64 {
        0
    }

    fn read(&self, _offset: u64, _size: u8) -> mem::Result<u64> {
        Ok(0)
    }

    fn write(&self, _offset: u64, _size: u8, _val: u64) -> mem::Result<Action> {
        Ok(Action::None)
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct EntropyFeature: u64 { }
}

#[derive(Debug)]
pub struct Entropy {
    name: Arc<String>,
    source: File,
    config: Arc<EntropyConfig>,
}

impl Entropy {
    pub fn new(name: Arc<String>) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.custom_flags(O_NONBLOCK).read(true);
        let path = "/dev/urandom";
        let file = options.open(path).context(error::AccessFile { path })?;
        Ok(Entropy {
            name,
            source: file,
            config: Arc::new(EntropyConfig),
        })
    }
}

impl Virtio for Entropy {
    type Config = EntropyConfig;
    type Feature = EntropyFeature;

    fn num_queues(&self) -> u16 {
        1
    }

    fn handle_queue(
        &mut self,
        index: u16,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        let Some(queue) = queues.get(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        reader_to_queue(&self.name, &mut self.source, index, queue, irq_sender)
    }

    fn handle_event(
        &mut self,
        _event: &Event,
        _queues: &[impl VirtQueue],
        _irq_sender: &impl IrqSender,
        _registry: &Registry,
    ) -> Result<()> {
        Ok(())
    }

    fn reset(&mut self, _registry: &Registry) {}

    fn device_id() -> DeviceId {
        DeviceId::Entropy
    }

    fn config(&self) -> Arc<EntropyConfig> {
        self.config.clone()
    }

    fn feature(&self) -> u64 {
        FEATURE_BUILT_IN
    }

    fn activate(
        &mut self,
        _registry: &Registry,
        _feature: u64,
        _memory: &RamBus,
        _irq_sender: &impl IrqSender,
        _queues: &[Queue],
    ) -> Result<()> {
        Ok(())
    }
}

pub struct EntropyParam;

impl DevParam for EntropyParam {
    type Device = Entropy;
    fn build(self, name: Arc<String>) -> Result<Self::Device> {
        Entropy::new(name)
    }
}
