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

use bitflags::Flags;
use snafu::ResultExt;

use crate::hv::{IoeventFd, IoeventFdRegistry};
use crate::mem::emulated::Mmio;
use crate::mem::mapped::{Ram, RamBus};
use crate::mem::{LayoutChanged, LayoutUpdated, MemRegion};
use crate::virtio::queue::split::SplitQueue;
use crate::virtio::queue::{Queue, VirtQueue, QUEUE_SIZE_MAX};
use crate::virtio::worker::Waker;
use crate::virtio::{error, DeviceId, IrqSender, Result, VirtioFeature};

pub mod blk;
pub mod entropy;
#[cfg(target_os = "linux")]
pub mod fs;
#[cfg(target_os = "linux")]
#[path = "net/net.rs"]
pub mod net;
#[cfg(target_os = "linux")]
#[path = "vsock/vsock.rs"]
pub mod vsock;

pub trait Virtio: Debug + Send + Sync + 'static {
    const DEVICE_ID: DeviceId;
    type Config: Mmio;
    type Feature: Flags<Bits = u64> + Debug;

    fn name(&self) -> &str;
    fn num_queues(&self) -> u16;
    fn config(&self) -> Arc<Self::Config>;
    fn feature(&self) -> u64;
    fn spawn_worker<S: IrqSender, E: IoeventFd>(
        self,
        event_rx: Receiver<WakeEvent<S>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[Queue]>,
        fds: Arc<[(E, bool)]>,
    ) -> Result<(JoinHandle<()>, Arc<Waker>)>;
    fn shared_mem_regions(&self) -> Option<Arc<MemRegion>> {
        None
    }
    fn offload_ioeventfd<E>(&self, _qindex: u16, _fd: &E) -> Result<bool>
    where
        E: IoeventFd,
    {
        Ok(false)
    }
    fn mem_update_callback(&self) -> Option<Box<dyn LayoutUpdated>> {
        None
    }
    fn mem_change_callback(&self) -> Option<Box<dyn LayoutChanged>> {
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

const TOKEN_WARKER: u64 = 1 << 63;

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

#[derive(Debug, PartialEq, Eq)]
pub enum WorkerState {
    Pending,
    Running,
    Shutdown,
}

#[derive(Debug)]
pub struct Worker<D, S, B>
where
    S: IrqSender,
{
    context: Context<D, S>,
    backend: B,
}

#[derive(Debug)]
pub struct VirtioDevice<D, S, E>
where
    D: Virtio,
    S: IrqSender,
    E: IoeventFd,
{
    pub name: Arc<str>,
    pub device_config: Arc<D::Config>,
    pub reg: Arc<Register>,
    pub queue_regs: Arc<[Queue]>,
    pub ioeventfds: Arc<[(E, bool)]>,
    pub shared_mem_regions: Option<Arc<MemRegion>>,
    pub waker: Arc<Waker>,
    pub event_tx: Sender<WakeEvent<S>>,
    worker_handle: Option<JoinHandle<()>>,
}

impl<D, S, E> VirtioDevice<D, S, E>
where
    D: Virtio,
    S: IrqSender,
    E: IoeventFd,
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

    pub fn new<R>(
        name: impl Into<Arc<str>>,
        dev: D,
        memory: Arc<RamBus>,
        registry: &R,
        restricted_memory: bool,
    ) -> Result<Self>
    where
        R: IoeventFdRegistry<IoeventFd = E>,
    {
        let name = name.into();
        let device_config = dev.config();
        let mut dev_feat = dev.feature();
        if restricted_memory {
            dev_feat |= VirtioFeature::ACCESS_PLATFORM.bits()
        } else {
            dev_feat &= !VirtioFeature::ACCESS_PLATFORM.bits()
        }
        let reg = Arc::new(Register {
            device_feature: dev_feat,
            ..Default::default()
        });
        let num_queues = dev.num_queues();
        let queue_regs = (0..num_queues).map(|_| Queue {
            size: AtomicU16::new(QUEUE_SIZE_MAX),
            ..Default::default()
        });
        let queue_regs = queue_regs.collect::<Arc<_>>();

        let create_ioeventfd = |index: u16| -> Result<(E, bool)> {
            let fd = registry.create()?;
            let offloaded = dev.offload_ioeventfd(index, &fd)?;
            Ok((fd, offloaded))
        };
        let ioeventfds = (0..num_queues)
            .map(create_ioeventfd)
            .collect::<Result<Arc<_>, _>>()?;

        let shared_mem_regions = dev.shared_mem_regions();
        let (event_tx, event_rx) = mpsc::channel();
        let (handle, waker) =
            dev.spawn_worker(event_rx, memory, queue_regs.clone(), ioeventfds.clone())?;
        log::debug!(
            "{name}: created with {:x?} {:x?}",
            VirtioFeature::from_bits_retain(reg.device_feature & !D::Feature::all().bits()),
            D::Feature::from_bits_truncate(reg.device_feature)
        );
        let virtio_dev = VirtioDevice {
            name,
            reg,
            queue_regs,
            ioeventfds,
            worker_handle: Some(handle),
            event_tx,
            waker,
            device_config,
            shared_mem_regions,
        };
        Ok(virtio_dev)
    }
}

impl<D, S, E> Drop for VirtioDevice<D, S, E>
where
    D: Virtio,
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
    fn register_waker(&mut self, token: u64) -> Result<Arc<Waker>>;
    fn activate_dev(
        &mut self,
        dev: &mut D,
        feature: u64,
        memory: &Ram,
        irq_sender: &impl IrqSender,
        queues: &[Queue],
    ) -> Result<()>;
    fn reset(&self, dev: &mut D) -> Result<()>;
    fn event_loop<'m, S: IrqSender, Q: VirtQueue<'m>>(
        &mut self,
        context: &mut Context<D, S>,
        queues: &mut [Option<Q>],
        irq_sender: &S,
    ) -> Result<()>;
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
pub struct Context<D, S>
where
    S: IrqSender,
{
    pub dev: D,
    memory: Arc<RamBus>,
    event_rx: Receiver<WakeEvent<S>>,
    queue_regs: Arc<[Queue]>,
    pub state: WorkerState,
}

impl<D, S> Context<D, S>
where
    D: Virtio,
    S: IrqSender,
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
                WakeEvent::Reset => {
                    log::info!("{}: guest requested reset", self.dev.name());
                    self.state = WorkerState::Pending;
                    break;
                }
            }
        }
        Ok(())
    }

    fn wait_start(&mut self) -> Option<(u64, Arc<S>)> {
        for wake_event in self.event_rx.iter() {
            match wake_event {
                WakeEvent::Reset => {}
                WakeEvent::Start {
                    feature,
                    irq_sender,
                } => {
                    self.state = WorkerState::Running;
                    return Some((feature, irq_sender));
                }
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

impl<D, S, B> Worker<D, S, B>
where
    D: Virtio,
    S: IrqSender,
    B: Backend<D>,
{
    pub fn spawn(
        dev: D,
        mut backend: B,
        event_rx: Receiver<WakeEvent<S>>,
        memory: Arc<RamBus>,
        queue_regs: Arc<[Queue]>,
    ) -> Result<(JoinHandle<()>, Arc<Waker>)> {
        let waker = backend.register_waker(TOKEN_WARKER)?;
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
        Ok((handle, waker))
    }

    fn loop_until_reset(&mut self) -> Result<()> {
        let Some((feature, irq_sender)) = self.context.wait_start() else {
            return Ok(());
        };
        let memory = self.context.memory.clone();
        let ram = memory.lock_layout();
        let feature = feature & !VirtioFeature::ACCESS_PLATFORM.bits();
        self.backend.activate_dev(
            &mut self.context.dev,
            feature,
            &ram,
            irq_sender.as_ref(),
            &self.context.queue_regs,
        )?;
        log::debug!(
            "{}: activated with {:x?} {:x?}",
            self.context.dev.name(),
            VirtioFeature::from_bits_retain(feature & !D::Feature::all().bits()),
            D::Feature::from_bits_truncate(feature)
        );
        if VirtioFeature::from_bits_retain(feature).contains(VirtioFeature::RING_PACKED) {
            todo!()
        } else {
            let new_queue = |reg| SplitQueue::new(reg, &ram, feature);
            let queues: Result<Box<_>> = self.context.queue_regs.iter().map(new_queue).collect();
            let mut queues = queues?;
            self.backend
                .event_loop(&mut self.context, &mut queues, &irq_sender)?;
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
