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
use std::sync::Arc;

use crate::host::{
    GuestMemAccess, Handle, IoHost, PollEvent, Token, VirtioDeviceSpec, VirtioIrqKind,
    VirtioQueueConfig,
};
use crate::sync::Mutex;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::{DeviceId, IrqSender, Result, VirtioFeature};

pub mod blk;
pub mod net;

pub trait Virtio: Debug + Send + Sync + 'static {
    fn num_queues(&self) -> u16;
    fn reset(&mut self);
    fn device_id(&self) -> DeviceId;
    fn config_bytes(&self) -> Vec<u8>;
    fn feature(&self) -> u64;
    fn activate(&mut self, token: Token, feature: u64) -> Result<()>;
    fn handle_queue(
        &mut self,
        index: u16,
        queues: &[SplitQueue],
        irq_sender: &impl IrqSender,
    ) -> Result<()>;
    fn handle_event(
        &mut self,
        event: &PollEvent,
        queues: &[SplitQueue],
        irq_sender: &impl IrqSender,
    ) -> Result<()>;
}

#[derive(Debug)]
pub struct BridgeIrqSender {
    pub dev: Handle,
    pub host: Arc<dyn IoHost>,
}

impl IrqSender for BridgeIrqSender {
    fn queue_irq(&self, idx: u16) {
        if let Err(e) = self.host.io_virtio_irq(self.dev, VirtioIrqKind::Queue(idx)) {
            log::error!("virtio dev {}: queue_irq({idx}) failed: {e}", self.dev);
        }
    }

    fn config_irq(&self) {
        if let Err(e) = self.host.io_virtio_irq(self.dev, VirtioIrqKind::Config) {
            log::error!("virtio dev {}: config_irq failed: {e}", self.dev);
        }
    }
}

pub trait RuntimeVirtioDevice: Debug + Send + Sync + 'static {
    fn dev_handle(&self) -> Handle;
    fn token(&self) -> Token;
    fn spec(&self) -> VirtioDeviceSpec;
    fn start(&self, driver_features: u64, queues: &[VirtioQueueConfig]) -> Result<()>;
    fn notify_queue(&self, queue_index: u16) -> Result<()>;
    fn reset(&self) -> Result<()>;
    fn handle_poll_event(&self, event: &PollEvent) -> Result<()>;
}

#[derive(Debug)]
struct DeviceState<D> {
    dev: D,
    memory: Arc<dyn GuestMemAccess>,
    queues: Option<Vec<SplitQueue>>,
    irq_sender: Arc<BridgeIrqSender>,
}

#[derive(Debug)]
pub struct VirtioDevice<D>
where
    D: Virtio,
{
    pub dev_handle: Handle,
    pub name: Arc<String>,
    pub token: Token,
    pub spec: VirtioDeviceSpec,
    state: Mutex<DeviceState<D>>,
}

impl<D> VirtioDevice<D>
where
    D: Virtio,
{
    pub fn new(
        dev_handle: Handle,
        name: Arc<String>,
        token: Token,
        dev: D,
        host: Arc<dyn IoHost>,
    ) -> Self {
        let spec = VirtioDeviceSpec {
            dev: dev_handle,
            name: (*name).clone(),
            device_id: dev.device_id() as u16,
            device_features: dev.feature() | VirtioFeature::SUPPORTED.bits(),
            num_queues: dev.num_queues(),
            config_bytes: dev.config_bytes(),
        };
        let memory: Arc<dyn GuestMemAccess> = host.clone();
        let irq_sender = Arc::new(BridgeIrqSender {
            dev: dev_handle,
            host,
        });
        let state = Mutex::new(DeviceState {
            dev,
            memory,
            queues: None,
            irq_sender,
        });
        Self {
            dev_handle,
            name,
            token,
            spec,
            state,
        }
    }
}

impl<D> RuntimeVirtioDevice for VirtioDevice<D>
where
    D: Virtio,
{
    fn dev_handle(&self) -> Handle {
        self.dev_handle
    }

    fn token(&self) -> Token {
        self.token
    }

    fn spec(&self) -> VirtioDeviceSpec {
        self.spec.clone()
    }

    fn start(&self, driver_features: u64, queue_cfgs: &[VirtioQueueConfig]) -> Result<()> {
        let mut state = self.state.lock();
        let memory = state.memory.clone();
        state.dev.activate(self.token, driver_features)?;
        if VirtioFeature::from_bits_retain(driver_features).contains(VirtioFeature::RING_PACKED) {
            todo!()
        }
        let split_queues = queue_cfgs
            .iter()
            .map(|cfg| SplitQueue::new(cfg, memory.clone(), driver_features))
            .collect();
        state.queues = Some(split_queues);
        log::debug!(
            "{}: started with feature bit {driver_features:#b}",
            self.name
        );
        Ok(())
    }

    fn notify_queue(&self, q_index: u16) -> Result<()> {
        let mut state = self.state.lock();
        let DeviceState {
            dev,
            queues: Some(qs),
            irq_sender,
            ..
        } = &mut *state
        else {
            log::error!(
                "{}: driver notified queue {q_index} before device is ready",
                self.name
            );
            return Ok(());
        };
        dev.handle_queue(q_index, qs, irq_sender.as_ref())
    }

    fn reset(&self) -> Result<()> {
        let mut state = self.state.lock();
        log::info!("{}: device requested reset", self.name);
        state.dev.reset();
        state.queues = None;
        log::info!("{}: reset done", self.name);
        Ok(())
    }

    fn handle_poll_event(&self, event: &PollEvent) -> Result<()> {
        let mut state = self.state.lock();
        let DeviceState {
            dev,
            queues: Some(qs),
            irq_sender,
            ..
        } = &mut *state
        else {
            return Ok(());
        };
        dev.handle_event(event, qs, irq_sender.as_ref())
    }
}

impl<D> Drop for VirtioDevice<D>
where
    D: Virtio,
{
    fn drop(&mut self) {
        self.state.lock().dev.reset();
    }
}
