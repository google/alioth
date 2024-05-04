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
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicU8};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;

use bitfield::bitfield;
use mio::event::Event;
use mio::{Events, Poll, Registry, Token, Waker};

use crate::mem::emulated::Mmio;
use crate::mem::mapped::RamBus;
use crate::mem::MemRegion;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::{Queue, VirtQueue, QUEUE_SIZE_MAX};
use crate::virtio::{DeviceId, IrqSender, Result, VirtioFeature};

pub trait Virtio: Debug + Send + Sync + 'static {
    type Config: Mmio;

    fn num_queues(&self) -> u16;
    fn reset(&mut self, registry: &Registry);
    fn device_id() -> DeviceId;
    fn config(&self) -> Arc<Self::Config>;
    fn feature(&self) -> u64;
    fn activate(&mut self, registry: &Registry, feature: u64, memory: &RamBus) -> Result<()>;
    fn handle_queue(
        &mut self,
        index: u16,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
        registry: &Registry,
    ) -> Result<()>;
    fn handle_event(
        &mut self,
        event: &Event,
        queues: &[impl VirtQueue],
        irq_sender: &impl IrqSender,
        registry: &Registry,
    ) -> Result<()>;
    fn shared_mem_regions(&self) -> Option<Arc<MemRegion>> {
        None
    }
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

const TOKEN_IS_QUEUE: u64 = 1 << 63;
const TOKEN_WORKER_EVENT: u64 = 1 << 62;

bitfield! {
    #[derive(Copy, Clone, Default)]
    struct VirtioToken(u64);
    impl Debug;
    is_queue, _: 63;
    data, _: 62, 0;
}

#[derive(Debug, Clone)]
pub enum WakeEvent<S>
where
    S: IrqSender,
{
    Notify { q_index: u16 },
    Shutdown,
    Start { feature: u64, irq_sender: Arc<S> },
    Reset,
}

#[derive(Debug)]
enum Queues {
    Split(Vec<SplitQueue>),
}

#[derive(Debug)]
struct DeviceWorker<D, S>
where
    S: IrqSender,
{
    name: Arc<String>,
    dev: D,
    poll: Poll,
    memory: Arc<RamBus>,
    event_rx: Receiver<WakeEvent<S>>,
    queue_regs: Arc<Vec<Queue>>,
    queues: Queues,
}

#[derive(Debug)]
pub struct VirtioDevice<D, S>
where
    D: Virtio,
    S: IrqSender,
{
    pub name: Arc<String>,
    pub device_config: Arc<D::Config>,
    pub reg: Arc<Register>,
    pub queue_regs: Arc<Vec<Queue>>,
    pub shared_mem_regions: Option<Arc<MemRegion>>,
    pub waker: Arc<Waker>,
    pub event_tx: Sender<WakeEvent<S>>,
    worker_handle: Option<JoinHandle<()>>,
}

impl<D, S> VirtioDevice<D, S>
where
    D: Virtio,
    S: IrqSender,
{
    fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(handle) = self.worker_handle.take() else {
            return Ok(());
        };
        self.event_tx.send(WakeEvent::Shutdown)?;
        self.waker.wake()?;
        if let Err(e) = handle.join() {
            log::error!("{}: failed to join worker thread: {e:?}", self.name)
        }
        Ok(())
    }

    pub fn new(name: Arc<String>, dev: D, memory: Arc<RamBus>) -> Result<Self> {
        let poll = Poll::new()?;
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
        let token = TOKEN_IS_QUEUE | TOKEN_WORKER_EVENT;
        let waker = Waker::new(poll.registry(), Token(token as usize))?;
        let shared_mem_regions = dev.shared_mem_regions();
        let (event_tx, event_rx) = mpsc::channel();
        let mut device_worker = DeviceWorker {
            name: name.clone(),
            dev,
            poll,
            event_rx,
            memory,
            queue_regs: queue_regs.clone(),
            queues: Queues::Split(Vec::new()),
        };
        let handle = std::thread::Builder::new()
            .name(name.as_ref().to_owned())
            .spawn(move || {
                let r = device_worker.do_work();
                if let Err(e) = r {
                    log::error!("worker {}: {e}", device_worker.name)
                } else {
                    log::debug!("worker {}: done", device_worker.name)
                }
            })?;
        let virtio_dev = VirtioDevice {
            name,
            reg,
            queue_regs,
            worker_handle: Some(handle),
            event_tx,
            waker: Arc::new(waker),
            device_config,
            shared_mem_regions,
        };
        Ok(virtio_dev)
    }
}

impl<D, S> Drop for VirtioDevice<D, S>
where
    D: Virtio,
    S: IrqSender,
{
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            log::error!("{}: failed to shutdown: {e}", self.name);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DevAction {
    Shutdown,
    Reset,
    Continue,
}

impl<D, S> DeviceWorker<D, S>
where
    D: Virtio,
    S: IrqSender,
{
    fn notify_queue(&mut self, q_index: u16, irq_sender: &S) -> Result<()> {
        let registry = self.poll.registry();
        match &self.queues {
            Queues::Split(qs) => self.dev.handle_queue(q_index, qs, irq_sender, registry),
        }
    }

    fn handle_wake_events(&mut self, irq_sender: &S) -> Result<DevAction> {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                WakeEvent::Notify { q_index } => self.notify_queue(q_index, irq_sender)?,
                WakeEvent::Shutdown => return Ok(DevAction::Shutdown),
                WakeEvent::Start { .. } => {
                    log::error!("{}: device has already started", self.name)
                }
                WakeEvent::Reset => {
                    log::info!("{}: device requested reset", self.name);
                    return Ok(DevAction::Reset);
                }
            }
        }
        Ok(DevAction::Continue)
    }

    fn wait_start(&mut self) -> Result<WakeEvent<S>> {
        let mut events = Events::with_capacity(1);
        loop {
            self.poll.poll(&mut events, None)?;
            while let Ok(wake_event) = self.event_rx.try_recv() {
                match &wake_event {
                    WakeEvent::Start { .. } | WakeEvent::Shutdown | WakeEvent::Reset => {
                        return Ok(wake_event)
                    }
                    WakeEvent::Notify { q_index } => {
                        log::error!(
                            "{}: driver notified queue {q_index} before device is ready",
                            self.name
                        )
                    }
                }
            }
        }
    }

    fn handle_event(&mut self, event: &Event, irq_sender: &S) -> Result<DevAction> {
        let token = VirtioToken(event.token().0 as u64);
        if token.is_queue() {
            if token.data() == TOKEN_WORKER_EVENT {
                self.handle_wake_events(irq_sender)
            } else {
                self.notify_queue(token.data() as u16, irq_sender)?;
                Ok(DevAction::Continue)
            }
        } else {
            let registry = self.poll.registry();
            match &self.queues {
                Queues::Split(qs) => self.dev.handle_event(event, qs, irq_sender, registry)?,
            };
            Ok(DevAction::Continue)
        }
    }

    fn loop_until_reset(&mut self) -> Result<DevAction> {
        let WakeEvent::Start {
            feature,
            irq_sender,
        } = self.wait_start()?
        else {
            return Ok(DevAction::Shutdown);
        };
        let memory = &self.memory;
        self.dev.activate(self.poll.registry(), feature, memory)?;
        self.queues =
            if VirtioFeature::from_bits_retain(feature).contains(VirtioFeature::RING_PACKED) {
                todo!()
            } else {
                let new_queue = |reg| SplitQueue::new(reg, memory.clone(), feature);
                let split_queues = self.queue_regs.iter().map(new_queue).collect();
                Queues::Split(split_queues)
            };
        log::debug!("{}: started with feature bit {feature:#b}", self.name);
        self.handle_wake_events(&irq_sender)?;
        let mut events = Events::with_capacity(128);
        loop {
            self.poll.poll(&mut events, None)?;
            for event in events.iter() {
                let ret = self.handle_event(event, &irq_sender)?;
                if ret != DevAction::Continue {
                    return Ok(ret);
                }
            }
        }
    }

    fn do_work(&mut self) -> Result<()> {
        loop {
            if self.loop_until_reset()? == DevAction::Shutdown {
                break;
            }
            self.dev.reset(self.poll.registry());
            log::info!("{}: reset done", self.name)
        }
        Ok(())
    }
}
