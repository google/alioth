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

pub mod balloon;
pub mod blk;
pub mod entropy;
#[path = "fs/fs.rs"]
pub mod fs;
#[path = "net/net.rs"]
pub mod net;
#[path = "vsock/vsock.rs"]
pub mod vsock;

use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;

use bitflags::Flags;
use snafu::ResultExt;

use crate::hv::IoeventFd;
use crate::mem::emulated::Mmio;
use crate::mem::mapped::{Ram, RamBus};
use crate::mem::{LayoutChanged, LayoutUpdated, MemRegion};
use crate::sync::notifier::Notifier;
use crate::virtio::queue::packed::PackedQueue;
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::{QUEUE_SIZE_MAX, Queue, QueueReg, VirtQueue};
#[cfg(target_os = "linux")]
use crate::virtio::vu::conn::VuChannel;
use crate::virtio::{DeviceId, IrqSender, Result, VirtioFeature, error};

pub trait Virtio: Debug + Send + Sync + 'static {
    type Config: Mmio;
    type Feature: Flags<Bits = u128> + Debug;

    fn name(&self) -> &str;
    fn id(&self) -> DeviceId;
    fn num_queues(&self) -> u16;
    fn config(&self) -> Arc<Self::Config>;
    fn feature(&self) -> u128;
    fn spawn_worker<S: IrqSender, E: IoeventFd>(
        self,
        event_rx: Receiver<WakeEvent<S, E>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[QueueReg]>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>;
    fn shared_mem_regions(&self) -> Option<Arc<MemRegion>> {
        None
    }
    fn ioeventfd_offloaded(&self, _q_index: u16) -> Result<bool> {
        Ok(false)
    }
    fn mem_update_callback(&self) -> Option<Box<dyn LayoutUpdated>> {
        None
    }
    fn mem_change_callback(&self) -> Option<Box<dyn LayoutChanged>> {
        None
    }
    #[cfg(target_os = "linux")]
    fn set_vu_channel(&mut self, _channel: Arc<VuChannel>) {}
}

#[derive(Debug, Default)]
pub struct Register {
    pub device_feature: [u32; 4],
    pub driver_feature: [AtomicU32; 4],
    pub device_feature_sel: AtomicU8,
    pub driver_feature_sel: AtomicU8,
    pub queue_sel: AtomicU16,
    pub status: AtomicU8,
}

const TOKEN_WARKER: u64 = 1 << 63;

#[derive(Debug, Clone)]
pub struct StartParam<S, E>
where
    S: IrqSender,
    E: IoeventFd,
{
    pub(crate) feature: u128,
    pub(crate) irq_sender: Arc<S>,
    pub(crate) ioeventfds: Option<Arc<[E]>>,
}

#[derive(Debug, Clone)]
pub enum WakeEvent<S, E>
where
    S: IrqSender,
    E: IoeventFd,
{
    Notify {
        q_index: u16,
    },
    Shutdown,
    #[cfg(target_os = "linux")]
    VuChannel {
        channel: Arc<VuChannel>,
    },
    Start {
        param: StartParam<S, E>,
    },
    Reset,
}

#[derive(Debug, PartialEq, Eq)]
pub enum WorkerState {
    Pending,
    Running,
    Shutdown,
}

#[derive(Debug)]
pub struct Worker<D, S, E, B>
where
    S: IrqSender,
    E: IoeventFd,
{
    context: Context<D, S, E>,
    backend: B,
}

#[derive(Debug)]
pub struct VirtioDevice<S, E>
where
    S: IrqSender,
    E: IoeventFd,
{
    pub name: Arc<str>,
    pub id: DeviceId,
    pub device_config: Arc<dyn Mmio>,
    pub device_feature: u128,
    pub queue_regs: Arc<[QueueReg]>,
    pub shared_mem_regions: Option<Arc<MemRegion>>,
    pub notifier: Arc<Notifier>,
    pub event_tx: Sender<WakeEvent<S, E>>,
    worker_handle: Option<JoinHandle<()>>,
}

impl<S, E> VirtioDevice<S, E>
where
    S: IrqSender,
    E: IoeventFd,
{
    fn shutdown(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let Some(handle) = self.worker_handle.take() else {
            return Ok(());
        };
        self.event_tx.send(WakeEvent::Shutdown)?;
        self.notifier.notify()?;
        if let Err(e) = handle.join() {
            log::error!("{}: failed to join worker thread: {e:?}", self.name)
        }
        Ok(())
    }

    pub fn new<D>(
        name: impl Into<Arc<str>>,
        dev: D,
        memory: Arc<RamBus>,
        restricted_memory: bool,
    ) -> Result<Self>
    where
        D: Virtio,
    {
        let name = name.into();
        let id = dev.id();
        let device_config = dev.config();
        let mut device_feature = dev.feature();
        if restricted_memory {
            device_feature |= VirtioFeature::ACCESS_PLATFORM.bits()
        } else {
            device_feature &= !VirtioFeature::ACCESS_PLATFORM.bits()
        }
        let num_queues = dev.num_queues();
        let queue_regs = (0..num_queues).map(|_| QueueReg {
            size: AtomicU16::new(QUEUE_SIZE_MAX),
            ..Default::default()
        });
        let queue_regs = queue_regs.collect::<Arc<_>>();

        let shared_mem_regions = dev.shared_mem_regions();
        let (event_tx, event_rx) = mpsc::channel();
        let (handle, notifier) = dev.spawn_worker(event_rx, memory, queue_regs.clone())?;
        log::debug!(
            "{name}: created with {:x?} {:x?}",
            VirtioFeature::from_bits_retain(device_feature & !D::Feature::all().bits()),
            D::Feature::from_bits_truncate(device_feature)
        );
        let virtio_dev = VirtioDevice {
            name,
            id,
            device_feature,
            queue_regs,
            worker_handle: Some(handle),
            event_tx,
            notifier,
            device_config,
            shared_mem_regions,
        };
        Ok(virtio_dev)
    }
}

impl<S, E> Drop for VirtioDevice<S, E>
where
    S: IrqSender,
    E: IoeventFd,
{
    fn drop(&mut self) {
        if let Err(e) = self.shutdown() {
            log::error!("{}: failed to shutdown: {e}", self.name);
        }
    }
}

pub trait Backend<D: Virtio>: Send + 'static {
    fn register_notifier(&mut self, token: u64) -> Result<Arc<Notifier>>;
    fn reset(&self, dev: &mut D) -> Result<()>;
    fn event_loop<'m, S, Q, E>(
        &mut self,
        memory: &'m Ram,
        context: &mut Context<D, S, E>,
        queues: &mut [Option<Queue<'_, 'm, Q>>],
        param: &StartParam<S, E>,
    ) -> Result<()>
    where
        S: IrqSender,
        Q: VirtQueue<'m>,
        E: IoeventFd;
}

pub trait BackendEvent {
    fn token(&self) -> u64;
}

pub trait ActiveBackend<D: Virtio> {
    type Event: BackendEvent;
    fn handle_event(&mut self, dev: &mut D, event: &Self::Event) -> Result<()>;
    fn handle_queue(&mut self, dev: &mut D, index: u16) -> Result<()>;
}

#[derive(Debug)]
pub struct Context<D, S, E>
where
    S: IrqSender,
    E: IoeventFd,
{
    pub dev: D,
    memory: Arc<RamBus>,
    event_rx: Receiver<WakeEvent<S, E>>,
    queue_regs: Arc<[QueueReg]>,
    pub state: WorkerState,
}

impl<D, S, E> Context<D, S, E>
where
    D: Virtio,
    S: IrqSender,
    E: IoeventFd,
{
    fn handle_wake_events<B>(&mut self, backend: &mut B) -> Result<()>
    where
        B: ActiveBackend<D>,
    {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                WakeEvent::Notify { q_index } => backend.handle_queue(&mut self.dev, q_index)?,
                WakeEvent::Shutdown => {
                    self.state = WorkerState::Shutdown;
                    break;
                }
                WakeEvent::Start { .. } => {
                    log::error!("{}: device has already started", self.dev.name())
                }
                #[cfg(target_os = "linux")]
                WakeEvent::VuChannel { channel } => self.dev.set_vu_channel(channel),
                WakeEvent::Reset => {
                    log::info!("{}: guest requested reset", self.dev.name());
                    self.state = WorkerState::Pending;
                    break;
                }
            }
        }
        Ok(())
    }

    fn wait_start(&mut self) -> Option<StartParam<S, E>> {
        for wake_event in self.event_rx.iter() {
            match wake_event {
                WakeEvent::Reset => {}
                WakeEvent::Start { param } => {
                    self.state = WorkerState::Running;
                    return Some(param);
                }
                #[cfg(target_os = "linux")]
                WakeEvent::VuChannel { channel } => self.dev.set_vu_channel(channel),
                WakeEvent::Shutdown => break,
                WakeEvent::Notify { q_index } => {
                    log::error!(
                        "{}: driver notified queue {q_index} before device is ready",
                        self.dev.name()
                    )
                }
            }
        }
        self.state = WorkerState::Shutdown;
        None
    }

    pub fn handle_event<B>(&mut self, event: &B::Event, backend: &mut B) -> Result<()>
    where
        B: ActiveBackend<D>,
    {
        if event.token() == TOKEN_WARKER {
            self.handle_wake_events(backend)
        } else {
            backend.handle_event(&mut self.dev, event)
        }
    }
}

impl<D, S, E, B> Worker<D, S, E, B>
where
    D: Virtio,
    S: IrqSender,
    B: Backend<D>,
    E: IoeventFd,
{
    pub fn spawn(
        dev: D,
        mut backend: B,
        event_rx: Receiver<WakeEvent<S, E>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[QueueReg]>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)> {
        let notifier = backend.register_notifier(TOKEN_WARKER)?;
        let worker = Worker {
            context: Context {
                dev,
                event_rx,
                memory,
                queue_regs,
                state: WorkerState::Pending,
            },
            backend,
        };
        let name = worker.context.dev.name();
        let handle = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || worker.do_work())
            .context(error::WorkerThread)?;
        Ok((handle, notifier))
    }

    fn event_loop<'m, Q>(
        &mut self,
        queues: &mut [Option<Queue<'_, 'm, Q>>],
        ram: &'m Ram,
        param: &StartParam<S, E>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
        E: IoeventFd,
    {
        log::debug!(
            "{}: activated with {:x?} {:x?}",
            self.context.dev.name(),
            VirtioFeature::from_bits_retain(param.feature & !D::Feature::all().bits()),
            D::Feature::from_bits_truncate(param.feature)
        );
        self.backend
            .event_loop(ram, &mut self.context, queues, param)
    }

    fn loop_until_reset(&mut self) -> Result<()> {
        let Some(param) = self.context.wait_start() else {
            return Ok(());
        };
        let memory = self.context.memory.clone();
        let ram = memory.lock_layout();
        let feature = param.feature & !VirtioFeature::ACCESS_PLATFORM.bits();
        let queue_regs = self.context.queue_regs.clone();
        let feature = VirtioFeature::from_bits_retain(feature);
        let event_idx = feature.contains(VirtioFeature::EVENT_IDX);
        if feature.contains(VirtioFeature::RING_PACKED) {
            let new_queue = |reg| {
                let Some(split_queue) = PackedQueue::new(reg, &ram, event_idx)? else {
                    return Ok(None);
                };
                Ok(Some(Queue::new(split_queue, reg, &ram)))
            };
            let queues: Result<Box<_>> = queue_regs.iter().map(new_queue).collect();
            self.event_loop(&mut (queues?), &ram, &param)?;
        } else {
            let new_queue = |reg| {
                let Some(split_queue) = SplitQueue::new(reg, &ram, event_idx)? else {
                    return Ok(None);
                };
                Ok(Some(Queue::new(split_queue, reg, &ram)))
            };
            let queues: Result<Box<_>> = queue_regs.iter().map(new_queue).collect();
            self.event_loop(&mut (queues?), &ram, &param)?;
        };
        self.backend.reset(&mut self.context.dev)?;
        Ok(())
    }

    fn do_work(mut self) {
        while self.context.state != WorkerState::Shutdown {
            if let Err(e) = self.loop_until_reset() {
                log::error!("worker {}: {e:?}", self.context.dev.name(),);
                return;
            }
        }
        log::debug!("worker {}: done", self.context.dev.name())
    }
}

pub trait DevParam {
    type Device;
    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device>;
    fn needs_mem_shared_fd(&self) -> bool {
        false
    }
}
