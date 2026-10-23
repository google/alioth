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
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU64};

use crate::sync::Mutex;

use crate::host::{PollEvent, Token, Vm};
use crate::mem::MemRegion;
use crate::mem::mapped::RamBus;
use crate::mem::mmio::Mmio;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::{QUEUE_SIZE_MAX, Queue, VirtQueue};
use crate::virtio::{DeviceId, IrqSender, Result, VirtioFeature};

pub mod blk;
pub mod net;

pub trait Virtio: Debug + Send + Sync + 'static {
    type Config: Mmio;

    fn num_queues(&self) -> u16;
    fn reset(&mut self);
    fn device_id() -> DeviceId;
    fn config(&self) -> Arc<Self::Config>;
    fn feature(&self) -> u64;
    fn activate(&mut self, token: Token, feature: u64, memory: &RamBus) -> Result<()>;
    fn handle_queue(
        &mut self,
        index: u16,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
    ) -> Result<()>;
    fn handle_event(
        &mut self,
        event: &PollEvent,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
    ) -> Result<()>;
    fn shared_mem_regions(&self) -> Option<Arc<MemRegion>> {
        None
    }
}

pub trait VirtioEventHandler: Debug + Send + Sync + 'static {
    fn token(&self) -> Token;
    fn handle_poll_event(&self, event: &PollEvent) -> Result<()>;
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

#[derive(Debug, Clone)]
pub enum WakeEvent<S>
where
    S: IrqSender,
{
    Notify { q_index: u16 },
    Start { feature: u64, irq_sender: Arc<S> },
    Reset,
}

#[derive(Debug)]
enum Queues {
    Split(Vec<SplitQueue>),
}

#[derive(Debug)]
struct DeviceState<D, S>
where
    S: IrqSender,
{
    dev: D,
    memory: Arc<RamBus>,
    queue_regs: Arc<Vec<Queue>>,
    queues: Option<Queues>,
    irq_sender: Option<Arc<S>>,
}

#[derive(Debug)]
pub struct VirtioDevice<D, S>
where
    D: Virtio,
    S: IrqSender,
{
    pub name: Arc<String>,
    pub token: Token,
    pub device_config: Arc<D::Config>,
    pub reg: Arc<Register>,
    pub queue_regs: Arc<Vec<Queue>>,
    pub shared_mem_regions: Option<Arc<MemRegion>>,
    state: Mutex<DeviceState<D, S>>,
}

impl<D, S> VirtioDevice<D, S>
where
    D: Virtio,
    S: IrqSender,
{
    pub fn new(
        name: Arc<String>,
        token: Token,
        dev: D,
        memory: Arc<RamBus>,
    ) -> Result<Self> {
        let device_config = dev.config();
        let reg = Arc::new(Register {
            device_feature: dev.feature() | VirtioFeature::SUPPORTED.bits(),
            ..Default::default()
        });
        let num_queues = dev.num_queues();
        let queue_regs = (0..num_queues).map(|_| Queue {
            size: AtomicU16::new(QUEUE_SIZE_MAX),
            ..Default::default()
        });
        let queue_regs = Arc::new(queue_regs.collect::<Vec<_>>());
        let shared_mem_regions = dev.shared_mem_regions();
        let state = Mutex::new(DeviceState {
            dev,
            memory,
            queue_regs: queue_regs.clone(),
            queues: None,
            irq_sender: None,
        });
        Ok(VirtioDevice {
            name,
            token,
            reg,
            queue_regs,
            device_config,
            shared_mem_regions,
            state,
        })
    }

    pub fn handle_wake_event(&self, event: WakeEvent<S>) -> Result<()> {
        let mut state = self.state.lock();
        match event {
            WakeEvent::Start {
                feature,
                irq_sender,
            } => {
                let memory = state.memory.clone();
                state.dev.activate(self.token, feature, &memory)?;
                let queues = if VirtioFeature::from_bits_retain(feature)
                    .contains(VirtioFeature::RING_PACKED)
                {
                    todo!()
                } else {
                    let new_queue = |reg| SplitQueue::new(reg, memory.clone(), feature);
                    let split_queues = state.queue_regs.iter().map(new_queue).collect();
                    Queues::Split(split_queues)
                };
                state.queues = Some(queues);
                state.irq_sender = Some(irq_sender);
                log::debug!("{}: started with feature bit {feature:#b}", self.name);
            }
            WakeEvent::Notify { q_index } => {
                let DeviceState {
                    dev,
                    queues: Some(Queues::Split(qs)),
                    irq_sender: Some(irq_sender),
                    ..
                } = &mut *state
                else {
                    log::error!(
                        "{}: driver notified queue {q_index} before device is ready",
                        self.name
                    );
                    return Ok(());
                };
                dev.handle_queue(q_index, qs, irq_sender.as_ref())?;
            }
            WakeEvent::Reset => {
                log::info!("{}: device requested reset", self.name);
                state.dev.reset();
                state.queues = None;
                state.irq_sender = None;
                log::info!("{}: reset done", self.name);
            }
        }
        Ok(())
    }
}

impl<D, S> VirtioEventHandler for VirtioDevice<D, S>
where
    D: Virtio,
    S: IrqSender,
{
    fn token(&self) -> Token {
        self.token
    }

    fn handle_poll_event(&self, event: &PollEvent) -> Result<()> {
        let mut state = self.state.lock();
        let DeviceState {
            dev,
            queues: Some(Queues::Split(qs)),
            irq_sender: Some(irq_sender),
            ..
        } = &mut *state
        else {
            return Ok(());
        };
        dev.handle_event(event, qs, irq_sender.as_ref())
    }
}

impl<D, S> Drop for VirtioDevice<D, S>
where
    D: Virtio,
    S: IrqSender,
{
    fn drop(&mut self) {
        self.state.lock().dev.reset();
    }
}

pub trait DevParam {
    type Device;
    fn build(self, name: Arc<String>, vm: &dyn Vm) -> Result<Self::Device>;
}
