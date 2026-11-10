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
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitflags::Flags;
use flume::{Receiver, RecvTimeoutError, Sender, TryRecvError};
use parking_lot::Mutex;
use snafu::ResultExt;

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
    fn spawn_worker<S: IrqSender>(
        self,
        param: WorkerParam<S>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)>;
    fn shared_mem_regions(&self) -> Option<Arc<MemRegion>> {
        None
    }
    fn notifier_offloaded(&self, _q_index: u16) -> Result<bool> {
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
    pub device_feature_sel: AtomicU32,
    pub driver_feature_sel: AtomicU32,
    pub queue_sel: AtomicU16,
    pub status: AtomicU8,
}

impl Register {
    pub fn get_driver_feature(&self) -> u128 {
        let mut result = 0u128;
        for (i, feature) in self.driver_feature.iter().enumerate() {
            result |= (feature.load(Ordering::Acquire) as u128) << (i << 5);
        }
        result
    }
}

const TOKEN_WARKER: u64 = 1 << 63;

/// How long a transport waits for the worker to reset a device when it
/// cannot leave the waiting to the driver.
///
/// It is longer than the time the io_uring worker waits for in-flight
/// requests when it leaves its event loop.
pub(crate) const RESET_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct StartParam<S>
where
    S: IrqSender,
{
    pub(crate) feature: u128,
    pub(crate) irq_sender: Arc<S>,
    pub(crate) notifiers: Option<Arc<[Notifier]>>,
}

/// Parameters a transport hands to the worker thread of a virtio device.
///
/// A transport builds one in [`VirtioDevice::new`] and passes it to
/// [`Virtio::spawn_worker`], which forwards it to the backend and finally
/// to [`Worker::spawn`]. Device implementations never look inside, so new
/// fields can be added without touching them.
#[derive(Debug)]
pub struct WorkerParam<S>
where
    S: IrqSender,
{
    /// Receiving end of the wake event channel. The sending end is in
    /// [`WorkerCtl`].
    pub(crate) event_rx: Receiver<WakeEvent<S>>,
    /// Sending end of the report channel. The receiving end is in
    /// [`WorkerCtl`].
    ///
    /// Only the worker holds it, so the channel disconnects once the worker
    /// exits, which completes all pending resets.
    pub(crate) report_tx: Sender<WorkerReport>,
    /// Guest memory.
    pub(crate) memory: Arc<RamBus>,
    /// Queue registers, shared with the transport.
    pub(crate) queue_regs: Arc<[QueueReg]>,
}

#[derive(Debug, Clone)]
pub enum WakeEvent<S>
where
    S: IrqSender,
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
        param: StartParam<S>,
    },
    /// Resets the device. Once the worker no longer uses the queues, it
    /// reports [`WorkerReport::ResetDone`] with `seq`.
    Reset {
        seq: u64,
    },
}

/// What a worker reports to the transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerReport {
    /// The worker has completed reset `seq`.
    ResetDone { seq: u64 },
    /// The worker has failed, and does not serve the queues until the
    /// device is reset.
    Failed,
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

/// The handle a transport uses to drive the worker thread of a virtio
/// device.
#[derive(Debug)]
pub struct WorkerCtl<S>
where
    S: IrqSender,
{
    name: Arc<str>,
    event_tx: Sender<WakeEvent<S>>,
    notifier: Arc<Notifier>,
    /// Sequence number of the last requested reset.
    ///
    /// The lock is held while sending the reset event, so that the worker
    /// sees resets in the order of their sequence numbers.
    reset_seq: Mutex<u64>,
    reports: Mutex<Reports>,
}

/// Returns `true` if reset `seq` is not later than reset `done`.
///
/// Sequence numbers are compared in serial number arithmetic, which stays
/// correct after the counter wraps around, as long as the two are less than
/// 2^63 resets apart.
fn reset_completed(done: u64, seq: u64) -> bool {
    (done.wrapping_sub(seq) as i64) >= 0
}

/// What the worker has reported so far.
#[derive(Debug)]
struct Reports {
    rx: Receiver<WorkerReport>,
    /// Sequence number of the last completed reset.
    reset_done: u64,
    /// Whether the worker has failed since the last completed reset.
    failed: bool,
}

impl Reports {
    fn handle(&mut self, report: WorkerReport) {
        match report {
            WorkerReport::ResetDone { seq } => {
                if !reset_completed(self.reset_done, seq) {
                    self.reset_done = seq;
                }
                // A reset brings the device back into service.
                self.failed = false;
            }
            WorkerReport::Failed => self.failed = true,
        }
    }

    /// Handles all pending reports.
    ///
    /// Returns `false` if the worker has exited.
    fn drain(&mut self) -> bool {
        loop {
            match self.rx.try_recv() {
                Ok(report) => self.handle(report),
                Err(TryRecvError::Empty) => break true,
                Err(TryRecvError::Disconnected) => break false,
            }
        }
    }
}

impl<S> WorkerCtl<S>
where
    S: IrqSender,
{
    pub(crate) fn new(
        name: Arc<str>,
        event_tx: Sender<WakeEvent<S>>,
        notifier: Arc<Notifier>,
        report_rx: Receiver<WorkerReport>,
    ) -> Self {
        WorkerCtl {
            name,
            event_tx,
            notifier,
            reset_seq: Mutex::new(0),
            reports: Mutex::new(Reports {
                rx: report_rx,
                reset_done: 0,
                failed: false,
            }),
        }
    }

    /// Sends `event` to the worker and wakes it up.
    ///
    /// Returns `false` if the worker has exited.
    pub fn wake(&self, event: WakeEvent<S>) -> bool {
        // A worker accepts `Start` only while it is pending, during which
        // it waits on the channel instead of the notifier.
        let is_start = matches!(event, WakeEvent::Start { .. });
        if let Err(e) = self.event_tx.send(event) {
            log::error!("{}: failed to send event: {e}", self.name);
            return false;
        }
        if !is_start && let Err(e) = self.notifier.notify() {
            log::error!("{}: failed to wake up device: {e}", self.name);
        }
        true
    }

    /// Asks the worker to reset the device.
    ///
    /// Returns the sequence number of this reset, which
    /// [`poll_reset`](Self::poll_reset) and [`wait_reset`](Self::wait_reset)
    /// take.
    pub fn request_reset(&self) -> u64 {
        let mut reset_seq = self.reset_seq.lock();
        let seq = reset_seq.wrapping_add(1);
        *reset_seq = seq;
        self.wake(WakeEvent::Reset { seq });
        seq
    }

    /// Returns `true` if the worker has completed reset `seq`.
    ///
    /// The worker handles resets in order, so this also means that all
    /// earlier resets have completed.
    pub fn poll_reset(&self, seq: u64) -> bool {
        let mut reports = self.reports.lock();
        let alive = reports.drain();
        // An exited worker no longer uses the queues.
        !alive || reset_completed(reports.reset_done, seq)
    }

    /// Waits until the worker has completed reset `seq`.
    pub fn wait_reset(&self, seq: u64, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let mut reports = self.reports.lock();
        while !reset_completed(reports.reset_done, seq) {
            match reports.rx.recv_deadline(deadline) {
                Ok(report) => reports.handle(report),
                Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => {
                    let name = self.name.clone();
                    return error::ResetTimeout { name, timeout }.fail();
                }
            }
        }
        Ok(())
    }

    /// Returns `true` if the worker has failed, so that the device needs a
    /// reset.
    pub fn failed(&self) -> bool {
        let mut reports = self.reports.lock();
        reports.drain();
        reports.failed
    }
}

#[derive(Debug)]
pub struct VirtioDevice<S>
where
    S: IrqSender,
{
    pub name: Arc<str>,
    pub id: DeviceId,
    pub device_config: Arc<dyn Mmio>,
    pub device_feature: u128,
    pub queue_regs: Arc<[QueueReg]>,
    pub shared_mem_regions: Option<Arc<MemRegion>>,
    pub ctl: Arc<WorkerCtl<S>>,
    pub(crate) worker_handle: Option<JoinHandle<()>>,
}

impl<S> VirtioDevice<S>
where
    S: IrqSender,
{
    fn shutdown(&mut self) {
        let Some(handle) = self.worker_handle.take() else {
            return;
        };
        self.ctl.wake(WakeEvent::Shutdown);
        if let Err(e) = handle.join() {
            log::error!("{}: failed to join worker thread: {e:?}", self.name)
        }
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
        let (event_tx, event_rx) = flume::unbounded();
        let (report_tx, report_rx) = flume::unbounded();
        let param = WorkerParam {
            event_rx,
            report_tx,
            memory,
            queue_regs: queue_regs.clone(),
        };
        let (handle, notifier) = dev.spawn_worker(param)?;
        log::debug!(
            "{name}: created with {:x?}, {:x?}",
            VirtioFeature::from_bits_retain(device_feature & !D::Feature::all().bits()),
            D::Feature::from_bits_truncate(device_feature)
        );
        let ctl = WorkerCtl::new(name.clone(), event_tx, notifier, report_rx);
        let virtio_dev = VirtioDevice {
            name,
            id,
            device_feature,
            queue_regs,
            worker_handle: Some(handle),
            ctl: Arc::new(ctl),
            device_config,
            shared_mem_regions,
        };
        Ok(virtio_dev)
    }
}

impl<S> Drop for VirtioDevice<S>
where
    S: IrqSender,
{
    fn drop(&mut self) {
        self.shutdown()
    }
}

pub trait Backend<D: Virtio>: Send + 'static {
    fn register_notifier(&mut self, token: u64) -> Result<Arc<Notifier>>;
    fn reset(&self, dev: &mut D) -> Result<()>;
    fn event_loop<'m, S, Q>(
        &mut self,
        memory: &'m Ram,
        context: &mut Context<D, S>,
        queues: &mut [Option<Queue<'_, 'm, Q>>],
        param: &StartParam<S>,
    ) -> Result<()>
    where
        S: IrqSender,
        Q: VirtQueue<'m>;
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
    param: WorkerParam<S>,
    pub state: WorkerState,
    /// The reset being handled, acknowledged once the worker no longer uses
    /// the queues.
    reset_seq: Option<u64>,
}

impl<D, S> Context<D, S>
where
    D: Virtio,
    S: IrqSender,
{
    fn report(&self, report: WorkerReport) {
        // The transport might be gone, e.g. at VMM shutdown.
        let _ = self.param.report_tx.send(report);
    }

    fn ack_reset(&self, seq: u64) {
        log::debug!("{}: reset {seq} completed", self.dev.name());
        self.report(WorkerReport::ResetDone { seq });
    }

    fn handle_wake_events<B>(&mut self, backend: &mut B) -> Result<()>
    where
        B: ActiveBackend<D>,
    {
        while let Ok(event) = self.param.event_rx.try_recv() {
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
                WakeEvent::Reset { seq } => {
                    log::info!("{}: reset requested", self.dev.name());
                    self.state = WorkerState::Pending;
                    self.reset_seq = Some(seq);
                    break;
                }
            }
        }
        Ok(())
    }

    fn wait_start(&mut self) -> Option<StartParam<S>> {
        for wake_event in self.param.event_rx.iter() {
            match wake_event {
                // The device has not started, so there is nothing to reset.
                WakeEvent::Reset { seq } => self.ack_reset(seq),
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

impl<D, S, B> Worker<D, S, B>
where
    D: Virtio,
    S: IrqSender,
    B: Backend<D>,
{
    pub fn spawn(
        dev: D,
        mut backend: B,
        param: WorkerParam<S>,
    ) -> Result<(JoinHandle<()>, Arc<Notifier>)> {
        let notifier = backend.register_notifier(TOKEN_WARKER)?;
        let worker = Worker {
            context: Context {
                dev,
                param,
                state: WorkerState::Pending,
                reset_seq: None,
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
        param: &StartParam<S>,
    ) -> Result<()>
    where
        Q: VirtQueue<'m>,
    {
        log::debug!(
            "{}: activated with {:x?}, {:x?}",
            self.context.dev.name(),
            VirtioFeature::from_bits_retain(param.feature & !D::Feature::all().bits()),
            D::Feature::from_bits_truncate(param.feature)
        );
        let ret = self
            .backend
            .event_loop(ram, &mut self.context, queues, param);
        // Clean up even if the event loop failed, since the device might
        // have been partially activated.
        let reset = self.backend.reset(&mut self.context.dev);
        ret.and(reset)
    }

    fn run(&mut self, param: &StartParam<S>) -> Result<()> {
        let memory = self.context.param.memory.clone();
        let ram = memory.load();
        let feature = param.feature & !VirtioFeature::ACCESS_PLATFORM.bits();
        let queue_regs = self.context.param.queue_regs.clone();
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
            self.event_loop(&mut (queues?), &ram, param)
        } else {
            let new_queue = |reg| {
                let Some(split_queue) = SplitQueue::new(reg, &ram, event_idx)? else {
                    return Ok(None);
                };
                Ok(Some(Queue::new(split_queue, reg, &ram)))
            };
            let queues: Result<Box<_>> = queue_regs.iter().map(new_queue).collect();
            self.event_loop(&mut (queues?), &ram, param)
        }
    }

    fn loop_until_reset(&mut self) -> Result<()> {
        let Some(param) = self.context.wait_start() else {
            return Ok(());
        };
        let ret = self.run(&param);
        // Unless the worker failed in handling a reset or a shutdown, the
        // device is out of service until the driver resets it. The worker
        // stays alive for that reset.
        if ret.is_err() && self.context.state == WorkerState::Running {
            self.context.state = WorkerState::Pending;
            self.context.report(WorkerReport::Failed);
            // The transport sets DEVICE_NEEDS_RESET, after which a running
            // device must notify the driver of a configuration change
            // (VirtIO spec 1.4, Sec 2.1.2).
            param.irq_sender.config_irq();
        }
        ret
    }

    fn do_work(mut self) {
        while self.context.state != WorkerState::Shutdown {
            if let Err(e) = self.loop_until_reset() {
                log::error!("worker {}: {e:?}", self.context.dev.name());
            }
            // The worker has dropped the queues and its guest memory
            // snapshot by now.
            if let Some(seq) = self.context.reset_seq.take() {
                self.context.ack_reset(seq);
            }
        }
        log::debug!("worker {}: done", self.context.dev.name())
    }
}

pub trait DevSpec {
    type Device;
    fn build(self, name: impl Into<Arc<str>>) -> Result<Self::Device>;
    fn needs_mem_shared_fd(&self) -> bool {
        false
    }
}

#[cfg(test)]
#[path = "dev_test.rs"]
mod tests;
