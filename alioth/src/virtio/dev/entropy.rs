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
use std::sync::mpsc::Receiver;
use std::thread::JoinHandle;

use bitflags::bitflags;
use libc::O_NONBLOCK;
use mio::Registry;
use mio::event::Event;
use snafu::ResultExt;

use crate::hv::IoeventFd;
use crate::mem;
use crate::mem::emulated::{Action, Mmio};
use crate::mem::mapped::RamBus;
use crate::virtio::dev::{DevParam, DeviceId, Virtio, WakeEvent};
use crate::virtio::queue::{Queue, VirtQueue};
use crate::virtio::worker::Waker;
use crate::virtio::worker::mio::{ActiveMio, Mio, VirtioMio};
use crate::virtio::{FEATURE_BUILT_IN, IrqSender, Result, error};

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
    name: Arc<str>,
    source: File,
    config: Arc<EntropyConfig>,
}

impl Entropy {
    pub fn new(name: impl Into<Arc<str>>) -> Result<Self> {
        let mut options = OpenOptions::new();
        options.custom_flags(O_NONBLOCK).read(true);
        let path = "/dev/urandom";
        let file = options.open(path).context(error::AccessFile { path })?;
        Ok(Entropy {
            name: name.into(),
            source: file,
            config: Arc::new(EntropyConfig),
        })
    }
}

impl Virtio for Entropy {
    type Config = EntropyConfig;
    type Feature = EntropyFeature;

    fn id(&self) -> DeviceId {
        DeviceId::Entropy
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn spawn_worker<S, E>(
        self,
        event_rx: Receiver<WakeEvent<S, E>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[Queue]>,
    ) -> Result<(JoinHandle<()>, Arc<Waker>)>
    where
        S: IrqSender,
        E: IoeventFd,
    {
        Mio::spawn_worker(self, event_rx, memory, queue_regs)
    }

    fn num_queues(&self) -> u16 {
        1
    }

    fn config(&self) -> Arc<EntropyConfig> {
        self.config.clone()
    }

    fn feature(&self) -> u64 {
        FEATURE_BUILT_IN
    }
}

impl VirtioMio for Entropy {
    fn activate<'a, 'm, Q, S, E>(
        &mut self,
        _feature: u64,
        _active_mio: &mut ActiveMio<'a, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        Ok(())
    }

    fn handle_queue<'a, 'm, Q, S, E>(
        &mut self,
        index: u16,
        active_mio: &mut ActiveMio<'a, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        let Some(Some(queue)) = active_mio.queues.get_mut(index as usize) else {
            log::error!("{}: invalid queue index {index}", self.name);
            return Ok(());
        };
        queue.copy_from_reader(index, &self.name, active_mio.irq_sender, &self.source)
    }

    fn handle_event<'a, 'm, Q, S, E>(
        &mut self,
        _event: &Event,
        _active_mio: &mut ActiveMio<'a, 'm, Q, S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        S: IrqSender,
        E: IoeventFd,
    {
        Ok(())
    }

    fn reset(&mut self, _registry: &Registry) {}
}

pub struct EntropyParam;

impl DevParam for EntropyParam {
    type Device = Entropy;

    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device> {
        Entropy::new(name)
    }
}
